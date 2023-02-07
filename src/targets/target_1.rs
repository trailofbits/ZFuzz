//! This loads the first target. In this case it is a static linux elf binary, so the default
//! elf-parser can be used to load it into memory. Afterwards we just setup a stack and insert
//! some hooks.
//! In this case the target takes its input via a filename passed through argv, so we just
//! append the filename to argv during the stack setup. If you want to pass input to the 
//! target in a different way, the best way would be to setup a hook at a specific address/syscall
//! that is in charge of inserting `emulator.fuzz_input` into the targets memory space.

use crate::{
    execution_state::ExecEnv,
    hooks::{
        insert_linux_syscall_hook, 
        insert_malloc_hook,
        insert_free_hook,
    },
    configurables::{VMMAP_ALLOCATION_SIZE, FIRSTALLOCATION},
    error_exit, load_elf_segments, 
};
use byteorder::{LittleEndian, WriteBytesExt};
use unicorn_engine::{
    Unicorn, RegisterRISCV,
    unicorn_const::{Permission, uc_error, Arch, Mode},
};
use std::rc::Rc;
use std::cell::RefCell;

const TARGET_1_PATH: &str = "./test_cases/simple_test_riscv64";

/// Initialize and harness a target
pub fn initialize_target() 
        -> Result<(Rc<RefCell<ExecEnv>>, Unicorn<'static, ()>), uc_error> {
    // Create emulator that will hold system context such as open files, dirty pages, etc
    let exec_env: Rc<RefCell<ExecEnv>> = 
        Rc::new(RefCell::new(ExecEnv::new(64 * 1024 * 1024)));

    // Create unicorn cpu emulator
    let mut unicorn = unicorn_engine::Unicorn::new(Arch::RISCV, Mode::RISCV64)?;

    // Load a static elf file into memory
    load_elf_segments(&mut unicorn, TARGET_1_PATH).unwrap_or_else(|err| {
        let error_string = format!("{err:#?}");
        error_exit(&format!("Unrecoverable error while loading elf segments: {error_string}"));
    });

    // Allocate memory map for emulator. This backing will be used to allocate the initial stack 
    // and handle later heap allocations during program execution
    unicorn.mem_map(FIRSTALLOCATION, VMMAP_ALLOCATION_SIZE, Permission::NONE).unwrap();

    // Allocate stack and populate argc, argv & envp
    {
        let stack = exec_env.borrow_mut()
            .allocate(&mut unicorn, 1024 * 1024, Permission::READ | Permission::WRITE)
            .expect("Error allocating stack");
        unicorn.reg_write(RegisterRISCV::SP, stack + (1024 * 1024) - 8)?;

        // Setup arguments to pass in argv
        let mut argv: Vec<u64> = Vec::new();

        // Macro to push 64-bit integers onto the stack
        macro_rules! push {
            ($expr:expr) => {
                let sp = unicorn.reg_read(RegisterRISCV::SP)? - 8;
                let mut wtr = vec![];
                wtr.write_u64::<LittleEndian>($expr as u64).unwrap();
                assert_eq!(wtr.len(), 8);
                unicorn.mem_write(sp, &wtr)?;
                unicorn.reg_write(RegisterRISCV::SP, sp)?;
            }
        }

        // Macro to push some array of bytes onto argv
        macro_rules! push_argv {
            ($expr:expr) => {
                let addr = exec_env.borrow_mut().allocate(&mut unicorn, 4096, 
                                                     Permission::READ | Permission::WRITE)
                    .expect("Allocating an argument failed");
                unicorn.mem_write(addr as u64, $expr.as_bytes()).unwrap();
                argv.push(addr);
            }
        }

        // This target takes its argument via its filename through argv. The fuzzer recognizes files
        // with the name `fuzz_input` as an input to the fuzzer, so we make the target open this as
        // its input file
        push_argv!("simple_test\0");
        push_argv!("fuzz_input\0");

        // Setup argc, argv & envp
        push!(0u64);            // Auxp
        push!(0u64);            // Envp
        push!(0u64);            // Null-terminate Argv
        for arg in argv.iter().rev() {
            push!(*arg);
        }
        push!(argv.len());      // Argc
    }

    // Insert optional target-specific hooks
    {
        // This hook catches interrupts to hook syscalls. For eg. Windows or embedded targets, you 
        // will want to define a different interrupt hook to hook their respective context-switch 
        // operations
        insert_linux_syscall_hook(&exec_env, &mut unicorn)?;

        // Insert memory allocator hooks (On linux, addresses of `_malloc_r` & `_free_r`)
        // This is optional, but highly recommended to use an allocator that can find potentially
        // non-crashing bugs such as double-free's or uaf's
        insert_malloc_hook(&exec_env, &mut unicorn, 0x103a4)?;
        insert_free_hook(&exec_env, &mut unicorn, 0x10fe4)?;
    }

    // Return initialized execution-environment/emulator to caller
    Ok((exec_env, unicorn))
}
