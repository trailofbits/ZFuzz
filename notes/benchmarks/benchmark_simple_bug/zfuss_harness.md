```rust
use crate::{
    execution_state::ExecEnv,
    configurables::{VMMAP_ALLOCATION_SIZE, FIRSTALLOCATION},
    error_exit, load_dump, 
};
use unicorn_engine::{
    Unicorn, RegisterX86,
    unicorn_const::{Permission, uc_error, Arch, Mode},
};
use std::rc::Rc;
use std::cell::RefCell;

const DUMP_PATH: &str = "./dump";

/// Initialize and harness a target
pub fn initialize_target() 
        -> Result<(Rc<RefCell<ExecEnv>>, Unicorn<'static, ()>), uc_error> {
    // Create emulator that will hold system context such as open files, dirty pages, etc
    let exec_env: Rc<RefCell<ExecEnv>> = 
        Rc::new(RefCell::new(ExecEnv::new(64 * 1024 * 1024)));

    // Create unicorn cpu emulator
    let mut unicorn = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64)?;

    // Load memory dump of target
    load_dump(&exec_env, &mut unicorn, DUMP_PATH).unwrap_or_else(|err| {
        let error_string = format!("{err:#?}");
        error_exit(&format!("Unrecoverable error while loading memory dump: {error_string}"));
    });

    // Allocate memory map for emulator. This backing will be used to allocate the initial stack 
    // and handle later heap allocations during program execution
    unicorn.mem_map(FIRSTALLOCATION, VMMAP_ALLOCATION_SIZE, Permission::NONE).unwrap();

    // Insert optional target-specific hooks
    {
        //insert_exit_hook(&exec_env, &mut unicorn, 0x0000000000401626)?;
        insert_exit_hook(&mut unicorn, 0x00005555555550f0)?;
        insert_exit_hook(&mut unicorn, 0x0000555555555127)?;

        // Hook to insert input into the target
        let hook_location = unicorn.get_pc().unwrap();
        insert_input_hook(&exec_env, &mut unicorn, hook_location)?;
    }

    // Return initialized execution-environment/emulator to caller
    Ok((exec_env, unicorn))
}

/// Places a hook at `addr` that loads the `exec_env.fuzz_input` into the targets address space
pub fn insert_exit_hook(unicorn: &mut Unicorn<'_, ()>, addr: u64) -> Result<(), uc_error> {
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        uc.emu_stop().unwrap();
    };

    unicorn.add_code_hook(addr, addr, callback)?;
    Ok(())
}

/// Places a hook at `addr` that loads the `exec_env.fuzz_input` into the targets address space
/// In this case fuzz-cases start right after a `read` syscall, so we write the input to `rsi`
/// and the number of bytes written to `rax`
pub fn insert_input_hook(exec_env: &Rc<RefCell<ExecEnv>>, unicorn: &mut Unicorn<'_, ()>, addr: u64) 
        -> Result<(), uc_error> {
    let exec_env_clone = Rc::clone(exec_env);
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
        let input_buffer_addr: u64 = uc.reg_read(RegisterX86::RSI).unwrap();
        let mut mutated_data = exec_env_clone.borrow().fuzz_input.clone();

        // From looking at the targets source, we know it reads in at most 100 bytes
        mutated_data.truncate(100);
        
        uc.reg_write(RegisterX86::RAX, mutated_data.len() as u64).unwrap();
        uc.mem_write(input_buffer_addr, &mutated_data)
            .expect("Failed to write mutated data into target");
    };

    unicorn.add_code_hook(addr, addr, callback)?;
    Ok(())
}
```