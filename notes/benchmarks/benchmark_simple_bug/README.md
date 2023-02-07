This benchmark is only slightly more complex than the previous one. Unicorn does not provide syscall support, and as far as I'm aware, afl-unicorn never implemented that feature on top of unicorn, so the fuzz-cases for both fuzzers will be done on a memory dump starting after the `read()` call. Additionally, fuzz-cases are early-terminated at the end of `main()`.

```c
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    char buf[100];
    int fd = open(argv[1], O_RDONLY);

    read(fd, buf, 100);

    if (buf[0] == 0x41) {
      if (buf[1] == 0x42) {
        if (buf[2] == 0x43) {
          if (buf[3] == 0x44) {
            if (buf[4] == 0x45) {
              if (buf[5] == 0x46) {
                *(unsigned long*)0x4141414141414141 = 0;
              }
            }
          }
        }
      }
    }
    return 0;
}
```

## Single-threaded:
zfuzz: 550,000 fcps
afl-unicorn:  -
libfuzzer: 340,000 fcps

## 8-threads:
zfuzz: 4 million fcps
afl-unicorn: -
libfuzzer: 2.4 million

## 16-threads:
zfuzz: 5 million fcps
afl-unicorn: -
libfuzzer: 2.4 million

## Conclusion
Libfuzzer performed pretty much exactly the same here as with the completely empty set. This suggests that at this point libfuzzer's entire bottleneck lies on its own overhead.

Zfuzz slowed down quite significantly from the previous completely empty case. This is because the fuzzer's actual overhead is tiny, so the bottleneck is occuring on the fuzzed-code & especially the hooks we are adding with unicorn.

Unicorn-AFL does not support syscalls and I was unable to get any of the debugger-snapshot scripts to run, so I was not able to easily generate benchmarks for afl-unicorn here.