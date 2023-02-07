- `/include/`
	- `unicorn/`
		- `<target>.h` - Lists target specific registers/cpu-models/etc
		- `platform.h` - Header files that amy be required for msvc compatibility
		- `unicorn.h` - Exports public api of the unicorn engine
			- Lists important unicorn enums/types such as `uc_err`, `uc_mode`, `uc_arch`, `uc_mem_type`, `uc_hook_type`, and various callbacks to hook specific actions (eg. all mem_reads)
	- `uc_priv.h` - Contains various relevant unicorn types/structs and some api's
		- `uc_struct{}`
		- `hook{}`
		- `uc_hook_idx{}` - Different types of hooks, enum values used to navigate hook-list
- `/qemu/`
	- `unicorn_common.h` - Defines functions that are referenced in all arch-spercific code such as `vm_start()` or `uc_common_init()`
		- This sets `uc_write/read_mem`, `memory_map`, and others
	- `target/`
		- `<target/>`
			- `unicorn.c` - Contains target specific api's (eg. register read/writing and target-specific unicorn initialization routine)
```c
void riscv64_uc_init(struct uc_struct *uc) {
    uc->reg_read = riscv_reg_read;
    uc->reg_write = riscv_reg_write;
    uc->reg_reset = riscv_reg_reset;
    uc->release = riscv_release;
    uc->set_pc = riscv_set_pc;
    uc->get_pc = riscv_get_pc;
    uc->stop_interrupt = riscv_stop_interrupt;
    uc->insn_hook_validate = riscv_insn_hook_validate;
    uc->cpus_init = riscv_cpus_init;
    uc->cpu_context_size = offsetof(CPURISCVState, rdtime_fn);
    uc_common_init(uc);
}
```

	- `include/`
		- `qemu-common.h` - Externally exposes some qemu api's such as `qemu_min()`, `page_size_init()` & `qemu_get_cpu()`
- `/uc.c`
	- `hook_insert()` & `hook_append()` & `hook_invalidate_region()` & `hook_delete` - hooks maintained in a linked list
	- `uc_init()` - Does some basic initialization, including register resets & setting the hook-delete functions
	- `uc_open()` - Creates new unicorn engine, sets memory spaces
	- `uc_close()` - Free's unicorn engine fields
	- `uc_read_read/write()` - Read/write registers (potentially in batches)
	- `check_mem_area()` - 
	- `uc_mem_read/write()` - Read/write high level api's. Tcg generated code uses different api's.
		- For mips & ppc,  `mem_redirect()` is called to convert address to proper form
		- Gets `MemoryRegion` for given address and uses `uc->read/write_mem() to access memory`
	- `enable_emu_timer()` & `_timeout_fn()` - Spawns thread that sleeps for a timer
	- `uc_emu_start()` - Does a good bit of initialization and then calls `uc->vm_start()`
		- If timeout is set, this will not terminate the vm until timer is reached
	- `uc_emu_stop()` - Just sets some field to indicate that emulation is finished
	- `memory_overlap()` - Check if memory regions overlap
	- `uc_mem_map()` - Uses `mem_map_check()` & `mem_map()` to create a new memory mapping
		- Internally calls `realloc()` to add an additional memory-region to `uc->mapped_blocks`
	- `uc_mem_protect()` - Change permissions of a `MemoryRegion` by splitting up the overarching `MemRegion()` and setting `mr->perms`
	- `uc_hook_add()`
		- Calls `uc-><type>_hook_validate()` & inserts hook into `uc->hook[]` if validation is successful
```c
// `/include/uc_priv.h:149`
struct hook {
    int type;       // UC_HOOK_*
    int insn;       // instruction for HOOK_INSN
    int refs;       // reference count to free hook stored in multiple lists
    int op;         // opcode for HOOK_TCG_OPCODE
    int op_flags;   // opcode flags for HOOK_TCG_OPCODE
    bool to_delete; // set to true when the hook is deleted by the user. The destruction of the hook is delayed.
    uint64_t begin, end; // only trigger if PC or memory access is in this address (depends on hook type)
    void *callback;      // a uc_cb_* type
    void *user_data;
    GHashTable *hooked_regions; // The regions this hook instrumented on
};
```

	- `uc_hook_del()` - Sets a flag that the hook should eventually be deleted, appends it to `uc->hooks_to_del` linked list, and removes it from relevant `MemoryRegion`'s'
	- `helper_uc_traceopcode()` & `helper_uc_tracecode()`
		- These are called from the tcg code
		- `helper_uc_tracecode` - This is called for codehooks