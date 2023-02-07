use crate::{
    execution_state::{ExecEnv, FileType::{self, STDOUT, STDERR, INVALID}},
    configurables::FUZZ_INPUT,
    dbg_print,
};

use unicorn_engine::{
    Unicorn,
    unicorn_const::{uc_error, Permission},
};

use std::cell::{RefMut, Ref};

// Helper Strunicornts for syscalls {{{

#[repr(C)]
#[derive(Debug)]
struct Stat {
    st_dev:     u64,
    st_ino:     u64,
    st_mode:    u32,
    st_nlink:   u32,
    st_uid:     u32,
    st_gid:     u32,
    st_rdev:    u64,
    __pad1:     u64,

    st_size:    i64,
    st_blksize: i32,
    __pad2:     i32,

    st_blocks: i64,

    st_atime:     u64,
    st_atimensec: u64,
    st_mtime:     u64,
    st_mtimensec: u64,
    st_ctime:     u64,
    st_ctimensec: u64,

    __glibc_reserved: [i32; 2],
}

// }}}

/// Read filename until nullbyte from the unicorn address space at a specified `addr`
fn read_null_terminated_str_at_addr(unicorn: &mut Unicorn<'_, ()>, addr: u64) 
        -> Result<String, uc_error> {
    let mut buf: Vec<u8> = Vec::new();
    let mut cur = 0;

    loop {
        let c: u8 = unicorn.mem_read_as_vec(addr + cur, 1)?[0];
        buf.push(c);
        if c == 0 {
            break;
        }
        cur += 1;
    }

    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub fn exit(mut exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL exit");
    exec_env.error_flag = uc_error::OK;
    unicorn.emu_stop()?;
    Ok(())
}

pub fn exit_group(exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    exit(exec_env, unicorn)
}

pub fn fstat(exec_env: Ref<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL fstat");
    let fd      = unicorn.reg_read(unicorn.syscall_arg0_reg()?)? as usize;
    let statbuf = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;

    // Check if the FD is valid
    let file = exec_env.fd_list.get(fd);
    if file.is_none() {
        // FD was not valid, return out with an error
        unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
        return Ok(());
    }

    // qemu output for the syscall + correct input lengths
    if file.unwrap().ftype == FileType::FUZZINPUT {
        let stat: Stat = Stat {
            st_dev:           0x803,
            st_ino:           0x81889,
            st_mode:          0x81a4,
            st_nlink:         0x1,
            st_uid:           0x3e8,
            st_gid:           0x3e8,
            st_rdev:          0x0,
            __pad1:           0,
            st_size:          exec_env.fuzz_input.len() as i64,
            st_blksize:       0x1000,
            __pad2:           0,
            st_blocks:        (exec_env.fuzz_input.len() as i64 + 511) / 512,
            st_atime:         0x5f0fe246,
            st_atimensec:     0,
            st_mtime:         0x5f0fe244,
            st_mtimensec:     0,
            st_ctime:         0x5f0fe244,
            st_ctimensec:     0,
            __glibc_reserved: [0, 0],
        };

        // Cast the stat strunicornture to raw bytes
        let stat = unsafe {
            core::slice::from_raw_parts(
                &stat as *const Stat as *const u8,
                core::mem::size_of_val(&stat))
        };

        // Write in the stat data
        unicorn.mem_write(statbuf, stat)?;
        unicorn.reg_write(unicorn.syscall_return_reg()?, 0)?;
    } else if file.unwrap().ftype != FileType::OTHER {
        unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
    } else {
        unreachable!();
    }

    Ok(())
}

pub fn open(mut exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL open");

    let filename  = unicorn.reg_read(unicorn.syscall_arg0_reg()?)?;
    let _flags    = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;
    let _mode     = unicorn.reg_read(unicorn.syscall_arg2_reg()?)?;

    // Read filename until nullbyte
    let filename_str = read_null_terminated_str_at_addr(unicorn, filename)?;

    let fd = if filename_str.contains(FUZZ_INPUT) {
        exec_env.alloc_file(FileType::FUZZINPUT)
    } else {
        exec_env.alloc_file(FileType::OTHER)
    } as u64;

    unicorn.reg_write(unicorn.syscall_return_reg()?, fd)?;
    Ok(())
}

pub fn openat(mut exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL open");

    let _dirfd    = unicorn.reg_read(unicorn.syscall_arg0_reg()?)?;
    let pathname  = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;
    let _flags    = unicorn.reg_read(unicorn.syscall_arg2_reg()?)?;
    let _mode     = unicorn.reg_read(unicorn.syscall_arg3_reg()?)?;

    let pathname_str = read_null_terminated_str_at_addr(unicorn, pathname)?;
    let filename = pathname_str.split('/').last().unwrap();

    let fd = if filename.contains(FUZZ_INPUT) {
        exec_env.alloc_file(FileType::FUZZINPUT)
    } else {
        exec_env.alloc_file(FileType::OTHER)
    } as u64;

    unicorn.reg_write(unicorn.syscall_return_reg()?, fd)?;
    Ok(())
}

pub fn read(mut exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL read");

    let fd    = unicorn.reg_read(unicorn.syscall_arg0_reg()?)? as usize;
    let buf   = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;
    let count = unicorn.reg_read(unicorn.syscall_arg2_reg()?)? as usize;

    // If the file does not exist or has already been closed, return an error
    let file = exec_env.fd_list.get(fd);
    if file.is_none() || file.unwrap().ftype == FileType::INVALID {
        unicorn.reg_write(unicorn.syscall_return_reg()?, 0)?;
        return Ok(());
    }

    // Special case, reading in the fuzzinput
    if exec_env.fd_list[fd].ftype == FileType::FUZZINPUT {
        let offset = exec_env.fd_list[fd].cursor.unwrap();
        let len = core::cmp::min(count, exec_env.fuzz_input.len()-offset);

        unicorn.mem_write(buf, &exec_env.fuzz_input[offset..offset+len])
            .expect("Error occured while trying to read in fuzz-input");

        unicorn.reg_write(unicorn.syscall_return_reg()?, len as u64)?;
        exec_env.fd_list[fd].cursor = Some(offset + len);
    } else {
        // Read in a different file
        unicorn.reg_write(unicorn.syscall_return_reg()?, count as u64)?;
    }

    Ok(())
}

pub fn write(exec_env: Ref<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL write");

    let fd    = unicorn.reg_read(unicorn.syscall_arg0_reg()?)? as usize;
    let buf   = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;
    let count = unicorn.reg_read(unicorn.syscall_arg2_reg()?)? as usize;

    // If the file does not exist or has already been closed, return an error
    let file = exec_env.fd_list.get(fd);
    if file.is_none() || file.as_ref().unwrap().ftype == FileType::INVALID {
        unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
        return Ok(());
    }

    // Set to true if you wish to see the actual stdout output of this syscall
    if false {
        let file = file.unwrap();
        if file.ftype == STDOUT || file.ftype == STDERR {
            let mut read_data = vec![0u8; count];
            unicorn.mem_read(buf, &mut read_data).unwrap();

            match std::str::from_utf8(&read_data) {
                Ok(v) => print!("{v}"),
                Err(_) => print!("{read_data:?}"),
            }
        } else {
            panic!("Write to unsupported file occured");
        }
    }

    unicorn.reg_write(unicorn.syscall_return_reg()?, count as u64)?;
    Ok(())
}

pub fn brk(unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL brk");

    let base = unicorn.reg_read(unicorn.syscall_arg0_reg()?)? as usize;
    if base == 0 {
        unicorn.reg_write(unicorn.syscall_return_reg()?, 0)?;
        return Ok(());
    }
    panic!("Not supporting brk, consider inserting a hook to a custom malloc implementation");
}

pub fn close(mut exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL close");

    let fd = unicorn.reg_read(unicorn.syscall_arg0_reg()?)? as usize;
    let file = exec_env.fd_list.get_mut(fd);

    if file.is_none() {
        unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
        return Ok(());
    }

    let file = file.unwrap();
    file.ftype = INVALID;

    unicorn.reg_write(unicorn.syscall_return_reg()?, 0)?;
    Ok(())
}

pub fn geteuid(unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL geteuid");
    unicorn.reg_write(unicorn.syscall_return_reg()?, 905)?;
    Ok(())
}

pub fn getuid(unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL getuid");
    unicorn.reg_write(unicorn.syscall_return_reg()?, 905)?;
    Ok(())
}

pub fn arch_prctl(unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL arch_prctl");
    unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
    Ok(())
}

pub fn access(unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL access");
    let pathname = unicorn.reg_read(unicorn.syscall_arg0_reg()?)?;
    let _mode    = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;

    // This syscall is probably not relevant to our fuzz-case so we will just fast-path it and 
    // return `-1` instead of actually reading from disk to check if we can access the requested 
    // file. This syscall is usually used by allocators to read `/etc/suid-debug` to indicate if
    // we have suid privs on the executable
    if false {
        let path = read_null_terminated_str_at_addr(unicorn, pathname)?;
        println!("called access on: {path}");
    }

    unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
    Ok(())
}

pub fn fstatat(exec_env: Ref<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL fstatat");
    let _dirfd   = unicorn.reg_read(unicorn.syscall_arg0_reg()?)?;
    let pathname = unicorn.reg_read(unicorn.syscall_arg1_reg()?)?;
    let statbuf  = unicorn.reg_read(unicorn.syscall_arg2_reg()?)?;
    let flags    = unicorn.reg_read(unicorn.syscall_arg3_reg()?)?;

    assert_eq!(flags, 0, "No support for non-0 flag arg in newfstatat syscall");

    let pathname_str = read_null_terminated_str_at_addr(unicorn, pathname)?;
    let filename = pathname_str.split('/').last().unwrap();

    // qemu output for the syscall + correct input lengths
    // Only handle this syscall properly if this is our fuzz-input
    if filename.contains(FUZZ_INPUT) {
        let stat: Stat = Stat {
            st_dev:           0x803,
            st_ino:           0x81889,
            st_mode:          0x81a4,
            st_nlink:         0x1,
            st_uid:           0x3e8,
            st_gid:           0x3e8,
            st_rdev:          0x0,
            __pad1:           0,
            st_size:          exec_env.fuzz_input.len() as i64,
            st_blksize:       0x1000,
            __pad2:           0,
            st_blocks:        (exec_env.fuzz_input.len() as i64 + 511) / 512,
            st_atime:         0x5f0fe246,
            st_atimensec:     0,
            st_mtime:         0x5f0fe244,
            st_mtimensec:     0,
            st_ctime:         0x5f0fe244,
            st_ctimensec:     0,
            __glibc_reserved: [0, 0],
        };

        // Cast the stat strunicornture to raw bytes
        let stat = unsafe {
            core::slice::from_raw_parts(
                &stat as *const Stat as *const u8,
                core::mem::size_of_val(&stat))
        };

        // Write in the stat data
        unicorn.mem_write(statbuf, stat)?;
        unicorn.reg_write(unicorn.syscall_return_reg()?, 0)?;
    } else {
        // Not our fuzz-input, we don't care, return -1
        unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
    }

    Ok(())
}

pub fn mmap(mut exec_env: RefMut<ExecEnv>, unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL mmap");
    let addr   = unicorn.reg_read(unicorn.syscall_arg0_reg()?)?;
    let length = unicorn.reg_read(unicorn.syscall_arg1_reg()?)? as usize;
    let prot   = unicorn.reg_read(unicorn.syscall_arg2_reg()?)?;
    let _flags = unicorn.reg_read(unicorn.syscall_arg3_reg()?)?;
    let fd     = unicorn.reg_read(unicorn.syscall_arg4_reg()?)? as usize;
    let offset = unicorn.reg_read(unicorn.syscall_arg5_reg()?)? as usize;

    // Convert mmap permission flags to format Unicorn expects
    let perms: Permission = {
        let mut init_perms: Permission = Permission::NONE;
        if prot & 1 != 0 { init_perms |= Permission::READ;  }
        if prot & 2 != 0 { init_perms |= Permission::WRITE; }
        if prot & 4 != 0 { init_perms |= Permission::EXEC;  }
        init_perms
    };

    // Unicorn requires page-aligned allocations
    let aligned_length: usize = ((0x1000 - 1 + length) & !(0x1000- 1)) as usize;
    let aligned_addr  : u64   = addr & !(0x1000- 1);

    // If no address was provided we can just tread this like a standard allocation
    let alloc_addr: u64 = if addr == 0 {
        exec_env.allocate(unicorn, aligned_length, perms)?
    } else {
        unicorn.mem_map(aligned_addr, aligned_length, perms)?;
        exec_env.mmap_allocations.insert(aligned_addr, aligned_length);
        aligned_addr
    };

    // fd is set so user intends to map a file into memory here
    if fd != 0 && fd != 0xffffffff && fd != 0xffffffffffffffff {
        if let Some(file) = exec_env.fd_list.get(fd) {
            assert!((offset % 0x1000) == 0, 
                    "According to man-pages, `offset` needs to be a page-size multiple");

            // Get data that this file stores
            let file_data: &Vec<u8> = match file.ftype {
                FileType::FUZZINPUT => &exec_env.fuzz_input,
                FileType::OTHER     => &file.backing.as_ref().unwrap(),
                _ => unreachable!(),
            };

            // Get the data that we intend to write (based on file-offset and length to read in), 
            // and write it to the unicorn address space
            let data      = &file_data[offset..];
            let truncated = &data[0..length];
            unicorn.mem_write(alloc_addr, &truncated)?;
        } else {
            // FD was not valid, return out with an error
            unicorn.reg_write(unicorn.syscall_return_reg()?, !0)?;
            return Ok(());
        }
    }

    unicorn.reg_write(unicorn.syscall_return_reg()?, alloc_addr)?;
    Ok(())
}

pub fn getrandom(unicorn: &mut Unicorn<'_, ()>) -> Result<(), uc_error> {
    dbg_print("SYSCALL getrandom");
    let buf     = unicorn.reg_read(unicorn.syscall_arg0_reg()?)?;
    let buflen  = unicorn.reg_read(unicorn.syscall_arg1_reg()?)? as usize;
    let _flags   = unicorn.reg_read(unicorn.syscall_arg2_reg()?)?;

    let random_bytes: Vec<u8> = (0..buflen).map(|_| { rand::random::<u8>() }).collect();
    unicorn.mem_write(buf, &random_bytes)?;

    unicorn.reg_write(unicorn.syscall_return_reg()?, random_bytes.len() as u64)?;
    Ok(())
}
