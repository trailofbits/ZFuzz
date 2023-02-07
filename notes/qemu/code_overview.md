- `/target/` - Architecture-specific files to support multiple architectures
	- `<target>`/
		- `translate.c`
			- `void gen_intermediate_code()` - Creates a target-specific `DisasContext` struct and calls generic `translator_loop`
			- `void <target>_tr_translate_insn()` - This is in charge of decoding instructions and translating them to IR
			```c
			opc_handler_t **table, *handler;
			table = cpu->opcodes;
			handler = table[opc1(ctx->opcode)];
			(*(handler->handler))(ctx);
			```
- `/hw/`
	- `<target>/` - Can be used to access different hardware machine configurations for various `target` architectures
	- `char/` - Char devices
	- `pci-host/` - PCI host controllers
	- `net/` - Network controllers
	- `mem/pc-dimm.c` - Hotswappable memory
- `/include/`
	- `exec/`
		- `memory.h` - This contains various structs/api's related to memory operations
			- `address_space_rw()` - Read and Write to/from ana ddress space
			- `MemoryRegion{}` - Struct representing a memory region
		- `AddressSpace{}` - Describes mapping of addresses to `MemoryRegion{}` objects
			- `RAMBlock{}` - Points to actual memory backing
		- `gen-icount.h`
			- `void gen_tb_start()` - Generates generic `TranslationBlock` prologues. This seems to mostly be related to instruction counting.
			```c
			// Allocate space to track instr-count
			%count = alloc: i32
			load i32 %count, i32 instr_count
			
			// Emit branch to exit if count has reached 0
			beq _exit, count, 0 

			// Store updated instruction count
			store i32 %count, i32 instr_count
			```
			- `void gen_tb_end()` - Generates generic `TranslationBlock` epilogue. Used to exit from TB. Blocks end with `exit_tb`, which is used to indicate if execution should go back to qemu (Host address of QEMU translator), or to another `TranslationBlock` (address of other tb as return valuie).
- `/backends/`
	- `hostmem.c` - Provides api's to act on memory-backend objects
- `/linux-user/`
	- `<target>/`
		- `cpu_loop.c`
			- `void cpu_loop()` Implements architecture-specific cpu-loop
	- `syscall.c` - Handles syscalls
- `/accel`
	- `tcg`
		- `cpu-exec.c`
			- `int cpu_exec()` - Non architecture dependent main cpu-loop
			- `TranslationBlock *tb_lookup()` - Check if some `pc` has already been JIT-compiled, if so return the `TranslationBlock`
			- `void cpu_loop_exec_tb()` 
				- This executes a translated `TranslationBlock`
				- `cpu_loop_exec_tb() -> tcg_qemu_tb_exec()`
			- `bool cpu_handle_exception` - Highest level of handling exceptions. Actual exception is delegated to arch-specific code
		- `translate-all.c`
			- `TranslationBlock tb_gen_code()` - Handles code compilation at some pc and returns the `TranslationBlock`
		- `translater.c`
			- `void translator_loop()` - 
		- `tci.c`
			- `QEMU_DISABLE_CFI tcg_qemu_tb_exec` - This function seems to emulate TCG IR when it is not JIT compiled to host isa
		- `cputlb.c`
			- load_helper
- `/tcg/`
	- `tcg.c`
		- `int tcg_gen_code()` - Takes `TranslationBlock` and produces machine code for host isa
		- `void tcg_dump_ops()` - Print out a tcg-IR-block
		- `void tcg_dump_op()` - Print out a tcg-IR-op
	- `<target>/`
		- `tcg-target.c.inc`
			- `void tcg_out_op()` - Host-isa specific switch statement to generate opcodes from IR
			- `bool tcg_out_qemu_st()` - Handles store instructions for tcg code
			- `bool tcg_out_qemu_ld()` - Handles load instructions for tcg code
	- `tcg-op.c`
		- `gen_ldst_i32()` - Might handle all IR-gen for 32-bit load/stores
		- `gen_ldst_i32()` - Might handle all IR-gen for 64-bit load/stores
- `/cpus-common.c`
	- `void cpu_exec_start()` - Take control of exclusive locks for some cpu and mark it as running
	- `void cpu_exec_end()` - Release locks and mark the cpu as not-running
- `/softmmu/`
	- `cpus.c`
		`int do_vm_stop()` - Changes run-state of the VM to `stopped` (State changes can be hooked, this is how gdb-server stub is implemented)
- `/migration/`
	- `savevm.c` - Can be used to save/reload snapshots of running vm