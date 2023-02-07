#### TranslationBlock Prologue (This is generated at the start of every TranslationBlock)
- Generated @ `gen_tb_start()`
```c
 // tmp0 = instruction_count
 0:  ld_i32 tmp0,env,$0xfffffffffffffff0

 // tmp1 = 0x0
 1:  movi_i32 tmp1,$0x0

 // if (tmp0 == tmp1) { j. $L0 }
 2:  brcond_i32 tmp0,tmp1,lt, $L0
```

#### TranslationBlock Epilogue (This is generated at the end of every TranslationBlock)
- Generated @ `gen_tb_end()` 
```c
 // This is appended right at the end of a `TranslationBlock`, so `0` denotes the code generated for the blog including the prologue
 0:  block_code

 // This can be one of 2 instructions, either a vmexit to return to unicorn (a) or through block-chaining 
 // optimizations a direct call to the next block
 1a: goto_ptr tmp
 1b: exit_tb $0x0

 // Sets a label for $L0. This can be used by any other instructions in this block to perform an early exit
 // to the qemu emulator. This is used by eg. the Epilogue
 2:  set_label $L0

 // vmexit
 3:  exit_tb $0x7f6b2760a883
```

#### Memory Store
```c
 // TODO: Figure out how exactly `mem_base` works
 1:  mov_i64 tmp2,x14/a4 mem_base=0x562da0d14278                                                     
 2:  mov_i64 tmp3,x11/a1 mem_base=0x562da0d14278

 // Memory store instruction. Machine code for this is generated using `tcg_out_qemu_st()`
 // This ends up creating multiple machinecode instructions in the tcg-backend
 3:  qemu_st_i64 tmp3,tmp2,leq,3

 // New TB Prologue since we had to do a vmexit
 4:  ld_i32 tmp0,env,$0xfffffffffffffff0                                                             
 5:  movi_i32 tmp1,$0x0                                                                              
 6:  brcond_i32 tmp0,tmp1,lt,$L0
```

#### Memory Load
```c
 // TODO: Figure out how exactly `mem_base` works
 1:  mov_i64 tmp2,x2/sp mem_base=0x562da0d14278

 // Memory load instruction. Machine code for this is generated using `tcg_out_qemu_ld()`
 // This ends up creating multiple machinecode instructions in the tcg-backend
 2:  qemu_ld_i64 tmp3,tmp2,leq,3

 // New TB Prologue since we had to do a vmexit
 3:  ld_i32 tmp0,env,$0xfffffffffffffff0
 4:  movi_i32 tmp1,$0x0
 5:  brcond_i32 tmp0,tmp1,lt,$L0

 // Mov the value loaded from memory into appropriate register
 6:  mov_i64 x8/s0,tmp3
```

#### Code Hooks
- (Syscall hooks are handled through vmexits so they aren't generated during codegen)
- (Memory hooks are handled in the tlb using load/store_helper @ `qemu/accel/tcg/cputlb.c`)
```c
0: TB Prologue

// Save pc
1:  movi_i64 pc,$0x12ab0

// Instr-size (in the case of riscv 4)
2:  movi_i32 tmp0,$0x4

// Type of hook based on `enum uc_hook_idx{}` (0x2 is `UC_HOOK_CODE_IDX`)
3:  movi_i32 tmp1,$0x2

// Address of main unicorn struct: `uc_struct`
4:  movi_i64 tmp2,$0x562da0cfc9d0

// Address at which hook was inserted
5:  movi_i64 tmp3,$0x12ab0                                                                          

// helper_uc_tracecode(int32_t size, uc_hook_idx index, void *handle, int64_t address)''
6:  call uc_tracecode,$0x0,$0,tmp0,tmp1,tmp2,tmp3

// TB Prologue is repeated
7:  ld_i32 tmp0,env,$0xfffffffffffffff0                                                             
8:  movi_i32 tmp1,$0x0                                                                              
9:  brcond_i32 tmp0,tmp1,lt,$L0  

// Instructions are still generated even if the TB is hooked
10: TB IR Instrs
11: TB Epilogue
```