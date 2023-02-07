- rbp points to array of 8-byte values representing registers

### Memory Store
- `/qemu/tcg/i386/tcg-target.inc.c` - `tcg_out_qemu_st()`
```c
   // Load IR(riscv) regs x11 and x14 into x86 registers 
   // x11 = 0x58 (0x58 / 8bits = 11th register)
   // x14 = 0x70 (0x70 / 8bits = 14th register)
   0x7fffb7bec755:	mov    rbx,QWORD PTR [rbp+0x58]
   0x7fffb7bec759:	mov    r12,QWORD PTR [rbp+0x70]
   0x7fffb7bec75d:	mov    rdi,r12

   // qemu_st_i64 x11, x14
   0x7fffb7bec760:	shr    rdi,0x7
   0x7fffb7bec764:	and    rdi,QWORD PTR [rbp-0x20]
   0x7fffb7bec768:	add    rdi,QWORD PTR [rbp-0x18]
   0x7fffb7bec76c:	lea    rsi,[r12+0x7]
   0x7fffb7bec771:	and    rsi,0xfffffffffffff000
   0x7fffb7bec778:	cmp    rsi,QWORD PTR [rdi+0x8]
   0x7fffb7bec77c:	mov    rsi,r12
   0x7fffb7bec77f:	jmp    0x7fffb7bec857
   0x7fffb7bec784:	add    rsi,QWORD PTR [rdi+0x18]
   0x7fffb7bec788:	mov    QWORD PTR [rsi],rbx
   
   // Memory-load Epilogue
	   // ld_i32 tmp0,env,$0xfffffffffffffff0
	   // movi_i32 tmp1,$0x0
	   // brcond_i32 tmp0,tmp1,lt,$L0  dead: 0 1
   0x7fffb7bec78b:	mov    ebx,DWORD PTR [rbp-0x10]
   0x7fffb7bec78e:	test   ebx,ebx
   0x7fffb7bec790:	jl     0x7fffb7bec84b
   0x7fffb7bec796:	mov    rdi,rbp
```











insn_idx=4 ---- 00000000000102dc
 3:  add_i64 tmp2, x14, tmp4
 4:  qemu_st_i64 x11, tmp2
 5:  ld_i32 tmp0,env,$0xfffffffffffffff0
 6:  movi_i32 tmp1,$0x0
 7:  brcond_i32 tmp0,tmp1,lt,$L0  dead: 0 1
```c
   0x7fffb7bec7a7:	mov    r12,QWORD PTR [rbp+0x58]
   0x7fffb7bec7ab:	mov    rdi,rbx
   0x7fffb7bec7ae:	shr    rdi,0x7
   0x7fffb7bec7b2:	and    rdi,QWORD PTR [rbp-0x20]
   0x7fffb7bec7b6:	add    rdi,QWORD PTR [rbp-0x18]
   0x7fffb7bec7ba:	lea    rsi,[rbx+0x7]
   0x7fffb7bec7be:	and    rsi,0xfffffffffffff000
   0x7fffb7bec7c5:	cmp    rsi,QWORD PTR [rdi+0x8]
   0x7fffb7bec7c9:	mov    rsi,rbx
   0x7fffb7bec7cc:	jmp    0x7fffb7bec871
   0x7fffb7bec7d1:	add    rsi,QWORD PTR [rdi+0x18]
   0x7fffb7bec7d5:	mov    QWORD PTR [rsi],r12
   0x7fffb7bec7d8:	mov    ebx,DWORD PTR [rbp-0x10]
   0x7fffb7bec7db:	test   ebx,ebx
   0x7fffb7bec7dd:	jl     0x7fffb7bec84b
   0x7fffb7bec7e3:	mov    rdi,rbp

```

```
=> 0x7fffb7bec994:	mov    rbx,QWORD PTR [rbp+0x58]
   0x7fffb7bec998:	mov    r12,QWORD PTR [rbp+0x70]
   0x7fffb7bec99c:	mov    rdi,r12
   0x7fffb7bec99f:	shr    rdi,0x7
   0x7fffb7bec9a3:	and    rdi,QWORD PTR [rbp-0x20]
   0x7fffb7bec9a7:	add    rdi,QWORD PTR [rbp-0x18]
   0x7fffb7bec9ab:	lea    rsi,[r12+0x7]
   0x7fffb7bec9b0:	and    rsi,0xfffffffffffff000
   0x7fffb7bec9b7:	cmp    rsi,QWORD PTR [rdi+0x8]
   0x7fffb7bec9bb:	mov    rsi,r12
   0x7fffb7bec9be:	jmp    0x7fffb7beca97
   0x7fffb7bec9c3:	add    rsi,QWORD PTR [rdi+0x18]
   0x7fffb7bec9c7:	mov    QWORD PTR [rsi],rbx
   0x7fffb7bec9ca:	mov    ebx,DWORD PTR [rbp-0x10]
   0x7fffb7bec9cd:	test   ebx,ebx
   0x7fffb7bec9cf:	jl     0x7fffb7beca8b
   0x7fffb7bec9d5:	mov    rdi,rbp

```