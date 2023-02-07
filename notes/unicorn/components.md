
It looks like the `uc_struct` is a member of the `AddressSpace` struct defined in `/qemu/include/exec/memory.h:422`

- Hook execution (more in codegen notes)
	- Hooks are maintained as a linked list of hook-arrays
	- Memory read/write hooks
		- Look at `qemu/accel/tcg/cputlb.c` for `uc_cb_hookmem_t()` (Memory read/write hook)
		- All memory operations cause a vmexit to access the tlb & memory. This is where hooks are checked and executed
	- Code Hooks
		 - `qemu/tcg/tcg.c` using `uc_cb_hookcode_t()`
		- `uc_add_inline_hook` uses `tcg_gen_callN()` to insert a `call` instruction to the callback 
	- Interrupt Hooks
		- `qemu/accel/tcg/cpu-exec.c` using `uc_cb_hookintr_t()`
		- `cpu_handle_exception()` is in charge of executing hook-callbacks on interrupts
