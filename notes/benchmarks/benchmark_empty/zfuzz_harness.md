```rust
use crate::{
    execution_state::ExecEnv,
    configurables::{VMMAP_ALLOCATION_SIZE, FIRSTALLOCATION},
    error_exit, load_dump, 
};
use unicorn_engine::{
    Unicorn,
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
        insert_exit_hook(&mut unicorn, 0x0000555555555046)?;
    }

    // Return initialized execution-environment/emulator to caller
    Ok((exec_env, unicorn))
}

/// Places a hook at `addr` that exits fuzz-case
pub fn insert_exit_hook(unicorn: &mut Unicorn<'_, ()>, addr: u64) -> Result<(), uc_error> {
    let callback = move |uc: &mut Unicorn<'_, ()>, _address: u64, _size: u32| {
	    // Exit hook hit, just stop the emulator to start next fuzz-case
        uc.emu_stop().unwrap();
    };

    unicorn.add_code_hook(addr, addr, callback)?;
    Ok(())
}
```