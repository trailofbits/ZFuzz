```c
#include <stdint.h>
#include <stddef.h>

// clang-14 -O2 -fsanitize=fuzzer ./targets/fuzz_me.c -o fuzz_me
// clang-14 ./in/ -max_len=100 

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  return 0;
}
```