```c
#include <stdint.h>
#include <stddef.h>

// clang-14 -O2 -fsanitize=fuzzer ./targets/fuzz_me.c -o fuzz_me
// clang-14 ./in/ -max_len=100 

#include <stdint.h>
#include <stddef.h>

// This call was added instead of the deref/crash because there isn't a good way to keep libfuzzer
// fuzzing after it runs into its first crash
int do_something() {
    return 3;
}

int fuzz(const uint8_t *data, size_t DataSize) {
    int res;
    if (data[0] == 0x41) {
      if (data[1] == 0x42) {
        if (data[2] == 0x43) {
          if (data[3] == 0x44) {
            if (data[4] == 0x45) {
              if (data[5] == 0x46) {
                  res += do_something();
              }
            }
          }
        }
      }
    }
    return res;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    fuzz(Data, Size);
    return 0;
}
}
```