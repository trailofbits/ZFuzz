```c
/*
   Run under AFL as follows:

   $ cd <afl_path>/unicorn_mode/samples/c
   $ make
   $ ../../../afl-fuzz -m none -i sample_inputs -o out -- ./harness @@

	- Adopted from:
	https://github.com/AFLplusplus/AFLplusplus/blob/stable/unicorn_mode/samples/c/harness.c
*/

// This is not your everyday Unicorn.
#define UNICORN_AFL

#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <unicorn/unicorn.h>
#include <unicornafl/unicornafl.h>

#define BINARY_FILE ("test_case")
static const int64_t BASE_ADDRESS = 0x100000;
static const int64_t CODE_ADDRESS = 0x101129;
static const int64_t END_ADDRESS  = 0x101137;

static const int64_t STACK_ADDRESS = (((int64_t) 0x01) << 58);
static const int64_t STACK_SIZE = 0x10000;
static const int64_t INPUT_LOCATION = 0x10000;

// Maximum allowable size of mutated data from AFL
static const int64_t INPUT_SIZE_MAX = 0x10000;

// Alignment for unicorn mappings (seems to be needed)
static const int64_t ALIGNMENT = 0x1000;

/* Unicorn page needs to be 0x1000 aligned, apparently */
static uint64_t pad(uint64_t size) {
    if (size % ALIGNMENT == 0) return size;
    return ((size / ALIGNMENT) + 1) * ALIGNMENT;
} 

/* returns the filesize in bytes, -1 or error. */
static off_t afl_mmap_file(char *filename, char **buf_ptr) {

    off_t ret = -1;

    int fd = open(filename, O_RDONLY);

    struct stat st = {0};
    if (fstat(fd, &st)) goto exit;

    off_t in_len = st.st_size;
    if (in_len == -1) {
	/* This can only ever happen on 32 bit if the file is exactly 4gb. */
	fprintf(stderr, "Filesize of %s too large", filename);
	goto exit;
    }

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;
}

/* Place the input at the right spot inside unicorn */
static bool place_input_callback(
    uc_engine *uc, 
    char *input, 
    size_t input_len, 
    uint32_t persistent_round, 
    void *data
){
    // printf("Placing input with len %ld to %x\n", input_len, DATA_ADDRESS);
    if (input_len < 1 || input_len >= INPUT_SIZE_MAX) {
        // Test input too short or too long, ignore this testcase
        return false;
    }
;
    // Write the testcase to unicorn.
    uc_mem_write(uc, INPUT_LOCATION input, input_len);
    return true;
}

static void mem_map_checked(uc_engine *uc, uint64_t addr, size_t size, uint32_t mode) {
    size = pad(size);
    //printf("SIZE %llx, align: %llx\n", size, ALIGNMENT);
    uc_err err = uc_mem_map(uc, addr, size, mode);
    if (err != UC_ERR_OK) {
        printf("Error mapping %ld bytes at 0x%llx: %s (mode: %d)\n", size, (unsigned long long) addr, uc_strerror(err), (int) mode);
        exit(1);
    }
}

int main(int argc, char **argv, char **envp) {
    if (argc == 1) return -1;

    uc_engine *uc;
    uc_err err;
    char *file_contents;
    char *filename = argv[1];

	// Map target into memory on first load
	{
	    // Initialize emulator in X86_64 mode
	    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	    if (err) return -2;

		// Map memory.
	    off_t len = afl_mmap_file(BINARY_FILE, &file_contents);
	    mem_map_checked(uc, BASE_ADDRESS, len, UC_PROT_ALL);
	
	    // write machine code to be emulated to memory
	    if (uc_mem_write(uc, BASE_ADDRESS, file_contents, len) != UC_ERR_OK) {
	        printf("Error writing to CODE");
	    }
	    
	    // Release copied contents
	    munmap(file_contents, len);
    }

    // Set the program counter to the start of the code
    uint64_t start_address = CODE_ADDRESS;            // address of entry point of main()
    uint64_t end_address   = END_ADDRESS;             // Address of last instruction in main()
    uc_reg_write(uc, UC_X86_REG_RIP, &start_address); // address of entry point of main()
    
    // Setup the Stack
    mem_map_checked(uc, STACK_ADDRESS - STACK_SIZE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    uint64_t stack_val = STACK_ADDRESS;
    //printf("Stack at %lu\n", stack_val);
    uc_reg_write(uc, UC_X86_REG_RSP, &stack_val);

    // reserve some space for our input data
    mem_map_checked(uc, INPUT_LOCATION, INPUT_SIZE_MAX, UC_PROT_READ);

    // For persistent-iters=1, we don't need to reset this as it's restarted/reforked for each run.
    uc_reg_write(uc, UC_X86_REG_RIP, &CODE_ADDRESS); // Set the instruction pointer back
    // Set up the function parameters accordingly RSI, RDI (see calling convention/disassembly)
    uc_reg_write(uc, UC_X86_REG_RSI, &INPUT_LOCATION); // argv
    uc_reg_write(uc, UC_X86_REG_RDI, &2);  // argc == 2
   
    // let's gooo
    uc_afl_ret afl_ret = uc_afl_fuzz(
        uc, // The unicorn instance we prepared
        filename, // Filename of the input to process. In AFL this is usually the '@@' placeholder, outside it's any input file.
        place_input_callback, // Callback that places the input (automatically loaded from the file at filename) in the unicorninstance
        &end_address, // Where to exit (this is an array)
        1,  // Count of end addresses
        NULL, // Optional calback to run after each exec
        false, // true, if the optional callback should be run also for non-crashes
        1, // For persistent mode: How many rounds to run
        NULL // additional data pointer
    );

    switch(afl_ret) {
        case UC_AFL_RET_ERROR:
            printf("Error starting to fuzz");
            return -3;
            break;
        case UC_AFL_RET_NO_AFL:
            printf("No AFL attached - We are done with a single run.");
            break;
        default:
            break;
    } 
    return 0;
}
```
