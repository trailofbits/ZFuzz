## Test-system
```
AMD Ryzen 7 4800H @2.9GHz
8 cores - 16 hw threads
```

1. benchmark_empty - This benchmark focuses on testing pure fuzzer-overhead by running a super-small target
2. benchmark_simple - This benchmark still has a simple target, but one that touches memory a little, performs operations requiring coverage tracking, and has a potential crash
3. benchmark_zip_parser - This benchmark runs against a very simple & buggy target I found on github