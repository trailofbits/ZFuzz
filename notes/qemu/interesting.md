#### Snapshots
- Qemu provides commands to create/restore snapshots. At a quick glance, Unicorn does not seem to support this. Might be worth exploring and figuring out how fast this is, and why Unicorn does not support this (if it actually does not, only grepped a little so far). 

- It looks like qemu's snapshotting is based on dirty pages

### Performance
- Qemu uses a global lock for a lot of its features preventing it from scaling well in many cases (`include/qemu/main-loop.h`)
- Can patch `tcg_target_reg_alloc_order` to remove registers from the register scheduler, thus giving us registers to use exclusively for coverage collection/dirty bit tracking (Need to be callee saved, and will need to modify `tcg_target_qemu_prologue` to properly set them on entry to the jit

### Possible Hook locations
- Can hook `tcg_out_qemu_str()` to track dirty maps for the purposes of snapshotting
- Can hook `tcg_gen_code()` to track coverage