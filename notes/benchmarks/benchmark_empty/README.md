Simplest possible benchmark, measured against empty case, snapshot taken at start of main, executes a couple of non-memory hitting instructions and exits. (The ret was hooked and used for early exits on both fuzzers tested). The harnesses I used for afl-unicorn & sfuzz are provided. The afl-unicorn harness is based on https://github.com/AFLplusplus/AFLplusplus/blob/stable/unicorn_mode/samples/c/harness.c. Fork-server and in-memory input insertion were both enabled. 

![[Pasted image 20230202152804.png]]

## Single-threaded:
zfuzz: 3.2 million fcps
afl-unicorn: 2,400 fcps
libfuzzer: 350,000 fcps

## 8-threads:
zfuzz: 19 million fcps
afl-unicorn: 7,600 fcps
libfuzzer: 2.4 million fcps

## 16-threads:
zfuzz: 22million fcps
afl-unicorn: -
libfuzzer: 2.4 million fcps

## Conclusion
Since this setup had the target executing basically no code, so pretty much the entire bottleneck existed in mutations for zfuzz. Disabling these and the resets brought the single-threaded performance up to 15 million fcps. Until threads started going onto hardware-threads rather than cores, zfuzz was scaling pretty much linearly. Afl-unicorn's performance in comparison dropped down immensely. The below screenshot showcases cpu usage for 8 fuzz-threads. With this, almost the entire cpu time was spent in the kernel at that point instead of fuzzing. Libfuzzer actually scaled surprisingly well. 90% of fuzz-time was still spent in the kernel, but this lined up about equally with its single threaded performance.

This benchmark isn't terribly useful when thinking about real fuzzing, but it puts the overhead of the actual fuzzer into perspective when it comes to just resetting/running targets and makes it a little easier to reason about expected performance numbers for real benchmarks later.

#### Libfuzzer-8jobs:
![[Pasted image 20230203080309.png]]

#### AFL-unicorn-8jobs
![[Pasted image 20230202160034.png]]