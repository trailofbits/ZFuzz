### General
- Qemu-User
	- Emulates userland binaries allowing linux binaries to be run on a linux host
- Qemu-System
	- Emulates full system (cpu, devices, kernel & apps)
- Hypervisors Basics
	- Type-1 (Hyper-V, Xen)  : Hypervisor runs on hardware, all OS's are guests
	- Type-2 (VMware, KVM): General purpose OS runs as host in VMX root operation mode
	- Before virtualization hardware support virtualization was generally accomplished through binary translation (eg. vmware) or cpu paravirtualization (eg. Xen)
	- Hypervisors can either be Full-fledged (Emulating CPUs, MMU, Devices & Firmware), or Pass-through (Emulating CPUs & MMU)
		- With pass-through hypervisors, the guest can make full use of system resources so the hypervisor only intercepts operations it is interested in, thus making it much simpler. This form of paravirtualization lets the host machine handle many operations, only emulating desired features, the raised abstraction layer allows for better performance.
- If host & guest arch is the same, qemu offers virtualization accelerators directly executing the code without having to emulate the instructions (ring0 instructions may still be emulated). This requires vmx/svm extensions respectively for intel/amd.
	- These accelerators can be find in `qemu_init_vcpu()` with a usage priority of kvm > hax > hvf > tcg > whpx
	- KVM is the linux kernel based virtual machinea ccelerator
	- HVF is the macos hypervisor framework accelerator
	- HAX is the cross-platform INTEL HAXM accelarator
	- WHP is the windows hypervisor platform accelerator
	- TCG is qemu's internal JIT
```sh
	$ qemu-system-x86_64 -accel ?
	Possible accelerators: kvm, xen, hax, tcg
```
- Internal API-Sets
	- QemuOpts (2009) - Simple API used to store device parameters in a better way than strings. Used by configuration and cli-parsing code
	- qdev (2009) - Manages the qemu device tree based on buses & devices. The device tree can be seen using the `info qtree` monitor command in qemu. It provides an API for device configuration/initialization without requiring knowledge of specific devices. Mostly replaced by QOM.
	- QOM: Qemu Object Model (2011) - Provides property system for object/device configuration introspection. 
	- VMState (2009) - Used to manage device state saving/loading in a central/safer manner
	- QMP: Qemu Monitor Protocol (2009) - Protocol for applications to talk to qemu over json so qemu can be controlled over cli
	- QObject (2009) - Provides various basic types such as integers, strings, etc. Includes reference counting, and supports all data types defined in the QAPI schema
	- QAPI (2011) - Provides an internal API for external applications to communicate with qemu (QMP is based on this). This API is also used by different qemu components to communicate with one another
	- Visitor API (2011) - Used to serialize QAPI data to/from the external world

### KVM
- Part of the linux kernel as a kernel module giving it access to a lot of kernel code such as the schedulers or even the linux userland (eg. for networking)
- Virtualization feature that allows guest programs execute directly on cpu assuming arch matches (supported on x86, armv8, ppc, s390 & Mips)
- Once the guest performs an impure operation such as accessing hardware registers or an interrupt, KVM exits to qemu and lets it handle it. 
- Guests have a dedicated iothread running a `select(2)` event loop to process I/O such as disk/network operations.
- Slot-based guest memory mapping guest physical to host virtual memory (supports dirty tracking)
	- Guest accesses directed to virtual MMIO regions
- According to docs, guest perf is almost native, with the main overhead coming in with vmexits

```sh
+----------------------------+----------------------------+---------------------+---+
|                                      LINUX HOST                                   |
+----------------------------+----------------------------+---------------------+---+
|       Qemu-Process-1       |       Qemu-Process-2       |       Firefox       |...|
+----------------------------+----------------------------+---------------------+---+
|  vcpu0 | vcpu1 | iothread  |  vcpu0 | vcpu1 | iothread  |           -         | - |
+----------------------------+----------------------------+---------------------+---+
|        Guest Memory        |        Guest Memory        |           -         | - |
+----------------------------+----------------------------+---------------------+---+
```

##### KVM IOCTL's
- https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt
- These allow qemu to communicate with the KVM kernel component using the `/dev/kvm` device interface
```sh
# Check kernel for available features/KVM version
KVM_GET_API_VERSION
KVM_CHECK_EXTENSION

# Create VM
KVM_CREATE_VM

# Setup memory region, interrupt controllers and vcpu
KVM_SET_USER_MEMORY_REGION  
KVM_CREATE_IRQCHIP
KVM_CREATE_VCPU

# Setup cpu state and register responses 
KVM_SET_REGS / ...SREGS / ...FPU / ...  
KVM_SET_CPUID / ...MSRS / ...VCPU_EVENTS / ... (x86)  
KVM_SET_LAPIC

# Run VM
KVM_RUN
```

### IOThread
- This runs in a separate thread next to the vcpu's and is in charge of handling io, timers, etc in an async manner

### Libvirt
- Management api that interacts with qemu
- Guest config stored in XML file

### Memory
- https://github.com/qemu/qemu/blob/v4.2.0/docs/devel/memory.rst
- https://github.com/qemu/qemu/blob/v4.2.0/include/exec/memory.h
- http://blog.vmsplice.net/2016/01/qemu-internals-how-guest-physical-ram.html
```sh
+--------------+     +----------------+
|   pc-dimm    |  -  | memory-backend |       User-visible objects
+--------------+     +----------------+
                             |
+--------------+     +----------------+
| AddressSpace |  -  |  MemoryRegion  |       Guest physical RAM layout
+--------------+     +----------------+
                             |
+--------------+     +----------------+
|   RAMList    |  -  |    RAMBlock    |       Host mmap memory chunks
+--------------+     | uint8_t *host  |
                     +----------------+
```

- User-Visible Memory
	- Both DIMMs and Memory backends can be managed using QEMU cmd options and the QMP monitor interface
	- Physical memory implemented through memory chipps (DIMMs)
		- Adding more memory to a guest is then done through DIMM hotplugging so a guest OS can detect new memory being added
		- `/hw/mem/pc-dimm.c` models a DIMM. Memory is hotplugged by creating a new dimm device
		- This dimm is associated with a `memory-backend` object which stores the actual memory
	- Memory backends `/backends/hostmem.c`
		- This contains the actual guest-ram data, either anonymous mmapped or file-backed mmapped memory
		- Allows for shared memory with host
- Memory backend-structures
	- MemoryRegion
		- Created by one of the `memory_region_init` functions
		- Can contain other memory regions (subregions), has its own properties and is attached so an address-space view
		- After creation `MemoryRegion`'s can be added to an `AddressSpace` using `memory_region_add_subregion()`
		- The addresses of `MemoryRegion`'s can overlap, in which case the Region with the higher priority has precedence. The other region can handle operations that fall into this region that the higher priority region does not wish to handle
	- Memory inside of the user-visible `memory-backend` is mmapped by RAMBlock through `qemu_ram_alloc()` in `/include/exec/memory.h`
	- Among other information, each RAMBlock has a pointer to the mmap memory and a ram_addr_t offset
		- The ram_addr_t namespace is different from the guest physical memory space. It is a tightly packed address space of all RAMBlocks. This does not include reserved memory regions such as memory-mapped I/O.
	- All RAMBlocks are in a global RAMList object called `ram_list`. This RAMList object holds the RAMBlocks and dirty memory bitmaps.
		```c
		 struct RAMBlock {
			/// I believe this field points to the actual memory backing
			uint8_t *host;

			/// Global namespace offset by which this RAMBlock can be looked up externally
			ram_addr_t offset;
			
			...
		 }
		```
- Dirty Memory Tracking
	- Different features need this information (All of these require separate bitmaps in `ram_list` since dirty memory tracking can be enabled/disabled indepdently)
	- Live migration feature relies on tracking dirty memory pages so they know if they change during live migration
	- TCG relies on tracking self-modifying code so ti can recompile changed instrs
	- Graphics card emulation needs to track dirty video memory to only redraw changed lines
- AddressSpace (`/include/exec/memory.h`)
	- Describes mappings from addreses to `MemoryRegion` objects in a tree datastructure

- General Memory API's
	- `memory_map_init()` (called in `cpu_exec_init_all()`)
		- This function creates the `system` memory region. It is one of the default memory regions and is the top level-one memory region. Subregions are usually added to this `system` memory region to create the memory map
	- `memory_region_allocate_system_memory()`
		- Creates a new memory region for the RAM and added as a subregion of the `system` memory region allowing physical addresses to be accessed
	- `memory_region_add_subregion()`
		- Add subregion to some MemoryRegion
	- `MemoryRegionOps{}`
		- Functions can be added to this structure to register callbacks for operations in some MemoryRegion
- Memory load/store API's
	- https://github.com/qemu/qemu/blob/v4.2.0/docs/devel/loads-stores.rst
	- `ld*_p & st*_p`
		- These operate on host pointers and should only be used when a pointer into host memory is available
		- `ld{type}{sign}{size}_endian_p(ptr)`
		- `st{type}{sign}_endian_p(ptr, val)`
	- `cpu_{ld,st}_*``
		- These operate on guest virtual addresses. 
		- Various faults causing CPU exceptions can result in the host taking control and updating state. Shoudl therefore only be used while implementing emulation of a target CPU
		- Possibility to throw an exception to the top level of TCG loop
		- `cpu_ld{sign}{size}_{mmusuffix}(env, ptr)`
		- `cpu_st{size}_{mmusuffix}(env, ptr, val)` (mmusufux is either `data` or `code`)
	- `cpu_{ld,st}_*_ra`
		- These functions work similar to the previous cpu_ld/st instructions but take a retaddr allowing correct unwinding of exceptions
	- `helper_*_{ld,st}*mmu`
		- Meant to be called by the code generated by TCG
	- `address_space_*`
		- Primary API's that should be used when emulating CPU or device memory accesses
	- `address_space_write_rom`
		- Same as above, but if the write is to a ROM then the contents are modified even if a guest-write would usually be ignored
	- `{ld,st}*_phys`
		- Identical to `address_space_*` but ignore wheter the transaction succeeds or fails
	- `cpu_physical_memory_*`
		- Convenience functions identical to `address_space_*` but operate directly on system address space

### TCG (Tiny Code Generator)
https://github.com/qemu/qemu/blob/master/tcg/README
https://wiki.qemu.org/Documentation/TCG
- Just in time compiler to translate target isa into host isa
- Frontend
	- Generate IR from guest isa
	- `/target/<target>/translate.c` & `/accel/tcg/translator.c` handles the main IR generation loop
	- While the translator loop is the same, the passed in `TranslatorOps` differ between archs and provides eg. instruction decoding features

```c
// Target specific struct that provides functions to translate a specific arch
// `/target/<target>/translate.c`
static const TranslatorOps riscv_tr_ops = {                                                         
	.init_disas_context = riscv_tr_init_disas_context,                                              
    .tb_start           = riscv_tr_tb_start,                                                        
    .insn_start         = riscv_tr_insn_start,                                                      
    .translate_insn     = riscv_tr_translate_insn,                                                  
    .tb_stop            = riscv_tr_tb_stop,                                                         
    .disas_log          = riscv_tr_disas_log,                                                       
};
```

```c
	/// `accel/tcg/translator.c`
	
	// Initialize context
	ps->init_disas_context(db, cpu);

	// Prologue, indicates translating start
	gen_tb_start(db->tb);
	ops->tb_start(db, cpu);

	// Main loop
	while (true) {
		ops->translate_insn(db, cpu);
		
		// Stop translation if `db->is_jmp` is set to indicate end of block
		if (db->is_jmp != DISAS_NEXT) {
			break;
		}
	}
	
	// Epilogue, indicates translation end
	// This epilogue is usually used as a placeholder for block chaining optimizations
	ops->tb_stop(db, cpu);
	gen_tb_end(db->tb, db->num_insns);
```

- Backend
	- Generate host isa from IR
	- Most instructions can be generically translated directly froms some guest isa to some host isa, some instructions however are isa-specific and thus require calls to external qemu-functions used to emulate the behavior
		- These are implemented using the `guest helper concept`, and are also widely used for guest memory accesses
	- Memory accesses by tcg instrs are generally handled by qemu's softmmu which transforms guest virtual addresses into physical addresses
	- A tlb is maintained to translate addresses. If the address is contained in the tlb it can be resolved cheaply, otherwise it gets more expensive

(https://airbus-seclab.github.io/qemu_blog/tcg_p2.html) (more examples in unicorn/codegen)
```c
0xfff00100:  movi_i32    r1,$0x10000
             movi_i32    tmp0,$0x409c
             or_i32      r1,r1,tmp0

0xfff00108:  movi_i32    r0,$0x0

0xfff0010c:  movi_i32    tmp1,$0x4
             add_i32     tmp0,r1,tmp1
             qemu_st_i32 r0,tmp0,beul,3

0xfff00110:  movi_i32    nip,$0xfff00114
             mov_i32     tmp0,r0
             call        store_msr,$0,tmp0

             movi_i32    nip,$0xfff00114
             exit_tb     $0x0
             set_label   $L0
             exit_tb     $0x7f5a0caf8043
```

Is translated into the following x86 assembly code:

```c
0x7f5a0caf810b:  movl     $0x1409c, 4(%rbp)

0x7f5a0caf8112:  xorl     %ebx, %ebx

0x7f5a0caf8114:  movl     %ebx, (%rbp)
0x7f5a0caf8117:  movl     $0x140a0, %r12d
0x7f5a0caf811d:  movl     %r12d, %edi
0x7f5a0caf8129:  addq     0x398(%rbp), %rdi
...
0x7f5a0caf8159:  movq     %rbp, %rdi
0x7f5a0caf815c:  movl     %ebx, %esi
0x7f5a0caf815e:  callq    *0x34(%rip)

0x7f5a0caf8164:  movl     $0xfff00114, 0x16c(%rbp)
0x7f5a0caf8182:  movl     %ebx, %edx
0x7f5a0caf8184:  movl     $0xa3, %ecx
0x7f5a0caf8189:  leaq     -0x41(%rip), %r8
0x7f5a0caf8190:  pushq    %r8
0x7f5a0caf8192:  jmpq     *8(%rip)
0x7f5a0caf8198:  .quad  0x000055d62e46eba0
0x7f5a0caf81a0:  .quad  0x000055d62e3895a0
```