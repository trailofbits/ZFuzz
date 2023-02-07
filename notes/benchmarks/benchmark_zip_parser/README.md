This is the first real target I attempted to use the fuzzer on. "Real" as in I didn't specifically write the target for the fuzzer. I pulled a random [zip parser](https://github.com/chshxi1989/zipparser) from github for this. This zip-parser is terrible (probably someone's school project), but I wanted something that could guarantee some bugs. The fuzzer found 3 quick segfaults, but apart from that, I was not able to get very far with the target. The compression libs embedded with the binary used avx instructions that unicorn does not have support for, so 99% of cases were just terminating because they hit one of these instructions. This made it very hard to actually measure the performance of the fuzzer on this target so I quickly moved on. This is not a target very well suited for zfuzz. I included the results anyways, but I don't think they really demonstrate much in this case.

After this I attempted to fuzz 2 more x86 userspace targets [cJSON](https://github.com/DaveGamble/cJSON) & [ffmpeg](https://github.com/FFmpeg/FFmpeg). WIth both of these I ran into the same issue with avx instructions being generated that unicorn can't handle. If I really wanted to fuzz x86 userspace targets anyways, I would need to either compile my own std-lib without avx instructions or manually hook all offending functions and handle them myself. The first approach seems sensible and like something that shouldn't be too hard to do, but I did not have enough time to properly give that a go.

![[Pasted image 20230202202905.png]]

## Single-threaded:
zfuzz: 3,200 fcps
afl-unicorn: 

## 8-threads:
zfuzz: 25,000
afl-unicorn:

## 16-threads:
zfuzz: 30,000
afl-unicorn: -

## Conclusion
Unicorn-AFL does not support syscalls and I was unable to get any of the debugger-snapshot scripts to run, so I was not able to easily generate benchmarks for afl-unicorn here.

Zfuzz still performs extremely well and is behaving as expected