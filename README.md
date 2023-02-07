This project was built by Gilbert Hoermann during the Trail of Bits 2022 Winter Internship. The project is provided as is. Contact opensource@trailofbits.com if you'd like to use this project.

# zfuzz
Emulation based snapshot fuzzer. Can load arbitrary memory dumps and start fuzzing. Provides a
mutational and a generationl grammar based mutator.

#### Build
```sh
# This will take a while the first time. Afterwards you can set the `QUICK_REBUILD` flag which
# should speed up build considerably
# (code should work on all OS's, makefile is currently laid out specifically for linux though)
make
```

#### Testing against provided test\_cases
The repo currently contains 2 test-cases that the fuzzer is harnessed for. `simple_test` &
`simple_test_x86`. Both are based on the source code `/test_cases/simple_test.c`. 

- `simple_test_riscv64` is a riscv64 statically linked binary. The harness for it is located at
`src/target_1.rs`. This binary is loaded from disk using a simple static elf-loader. Allocators are
hooked, and the fuzzer starts running it.

- `simple_test_x86` is a 64-bit statically compiled binary (Although in this case it could also be
dynamic. I just chose to compile it static cause it seems to run faster in my fuzzer). The harness
for this test-case is located at `src/target_2.rs`. In this case a memory-dump is loaded from disk
and then executed. To test this case you will need to generate this dump using the following
commands. They will run the target in the debugger until right after the `read` syscall and then
use the snapshot.py gdb-script I wrote to dump the entire memory/register/file-state.
```sh
gdb ./test_cases/simple_test_x86
b *main+52      
run ./in/input.txt (Just some sample file from disk used to get the target to the `read` syscall)
source ./tools/snapshot.py 
fulldump
```

To run either of the targets, follow the steps outlined above, and then go to 
`src/targets/target.rs`. Here you can add targets to the `TARGETS` array using their TargetId 
number. Every target registered this way will be run by the fuzzer. Technically both targets can be
run at the same time by registering multiple harnesses, but this is not yet tested. In the future 
this will enable differential fuzzing between multiple targets running at the same time on this
fuzzer.

#### Run
```sh
mkdir in out && head -c 100 /dev/urandom > in/input.txt
./target/release/zfuzz -i in -o out
```

