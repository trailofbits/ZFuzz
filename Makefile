.ONESHELL:

# Compile both Unicorn and Zfuzz with debug flags. Do not use for actual fuzzing as this is much
# slower
DEBUG=false

# Skip cmake command, use when config has already been done
QUICK_REBUILD=false

# Build fzero-based grammar mutator with grammar defined by `GRAMMAR_FILE`
GRAMMAR=false
GRAMMAR_FILE='./grammars/json.json'

# Set the maximum depth for the input generation.
# Higher depth = more complex inputs but also increased time required to generate input
# For the json.json grammar, exceeding a depth of ~200 started bottlenecking the fuzzzer
MAX_DEPTH=64

# Number of processors to parallelize build
NPROCS:=$(shell grep -c ^processor /proc/cpuinfo)

build:
	-@ echo "[+] Starting build with DEBUG=$(DEBUG) for Unicorn and Zfuzz"

	-@ if [ ! -d "./include/unicorn" ]; then echo "[+] Cloning unicorn repo"; git clone \
		https://github.com/seal9055/unicorn ./include/unicorn; fi
	
	-@ echo "[+] Building Unicorn"
	-@ if [ ! -d "./include/unicorn/build" ]; then mkdir ./include/unicorn/build; fi
	-@ cd ./include/unicorn/build
ifeq ($(QUICK_REBUILD), false)
ifeq ($(DEBUG), true)
	-@ CFLAGS="-fno-omit-frame-pointer -fno-optimize-sibling-calls -g3 -O0" \
			cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
			-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
else
	-@ CFLAGS="-O3" cmake .. -DCMAKE_BUILD_TYPE=Release
endif
endif

	-@ echo "[+] Compiling Unicorn with $(NPROCS) jobs"
	-@ make -j $(NPROCS)
	-@ cd ../../..
	
ifeq ($(GRAMMAR), true)
	-@ echo "[+] Building Grammar Mutator"
	-@ cd ./include/fzero_fuzzer
	-@ cargo run --release ../../$(GRAMMAR_FILE) grammar_mut.rs $(MAX_DEPTH)
	-@ mv grammar_mut.rs ../../src/grammar_mut.rs
	-@ cd ../..
else
	-@ cp ./src/default_grammar.rs ./src/grammar_mut.rs
endif

	-@ echo "[+] Building Zfuzz"
ifeq ($(DEBUG), true)
	-@ mv ./include/unicorn/build/compile_commands.json ./include/unicorn/
	-@ cargo build
else
	-@ cargo build --release
endif
	-@ echo "[+] Done"

clean:
	-@ echo "[+] Cleaning up build files"
	-@ cargo clean
	-@ if [ -d "./include/unicorn/build" ]; then rm -r ./include/unicorn/build; fi
	-@ if [ -f "./include/unicorn/compile_commands.json" ]; then \
		rm ./include/unicorn/compile_commands.json; fi
	-@ if [ -f "./src/grammar_mut.rs" ]; then rm ./src/grammar_mut.rs; fi
	-@ if [ -d "./include/fzero_fuzzer/target" ]; then cd ./include/fzero_fuzzer && cargo clean && \
		cd ../../; fi
	-@ if [ -d "./dump" ]; then rm -r ./dump; fi
	-@ echo "[+] Done"

run:
ifeq ($(DEBUG), true)
	-@ ./target/debug/zfuzz -i in -o out
else
	-@ ./target/release/zfuzz -i in -o out
endif
