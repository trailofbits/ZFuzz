use crate::{
    execution_state::FileType::{STDIN, STDOUT, STDERR},
    configurables::{MAX_ALLOCATION_ADDR, FIRSTALLOCATION},
};

use rustc_hash::FxHashMap;
use unicorn_engine::{
    Unicorn, Context,
    unicorn_const::{Permission, uc_error},
};

use std::rc::Rc;
use std::cell::RefCell;

/// Different types of files that the fuzzer supports
#[derive(Copy, Debug, Clone, Eq, PartialEq)]
pub enum FileType {
    /// STDIN (0)
    STDIN,

    /// STDOUT (1), basically ignored apart from debug-prints to console
    STDOUT,

    /// STDERR (2), basically ignored apart from debug-prints to console
    STDERR,

    /// The input we are fuzzing. It keeps its byte-backing in emulator.fuzz_input
    FUZZINPUT,

    /// A standard file that is not 0/1/2 or the input we are fuzzing
    OTHER,

    /// Invalid file
    INVALID,
}

/// Memoery mapped file implementation
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct File {
    /// Filetype of this file
    pub ftype:   FileType,

    /// The byte-backing used by this file. Not required by 0/1/2, or the fuzzinput
    pub backing: Option<Vec<u8>>,

    /// Cursor is used by the fuzz-input and potential other files that aren't 0/1/2
    pub cursor:  Option<usize>,
}

impl File {
    /// Create a new file
    fn new(ftype: FileType) -> Self {
        let (backing, cursor) = match ftype {
            FileType::OTHER => (Some(Vec::new()), Some(0)),
            FileType::FUZZINPUT => (None, Some(0)),
            _ => (None, None),
        };
        File {
            ftype,
            backing,
            cursor,
        }
    }
}

/// State of initial snapshot is saved in this struct and used for future snapshot restores
pub struct SnapshotContext {
    /// Used to maintain memory mapping. When the memory of the guest is reset for the next 
    /// fuzz-case, these mappings are used to restore the initial context.
    pub page_map: FxHashMap<usize, Vec<u8>>,

    /// CPU-Context structure used by unicorn engine
    pub cpu_context: Context,

    /// List of originally active file descriptors 
    pub fd_list: Vec<File>,

    /// Address of last block hit before snapshot was taken
    pub prev_block: u64,

    /// Address of the next free region of memory that the allocator will use for allocations
    pub alloc_addr: u64,
}

/// Execution environment. Keeps track of files, allocator variables, dirty-list, etc
pub struct ExecEnv {
    /// List of file descriptors that the process can use for syscalls
    pub fd_list: Vec<File>,

    /// The fuzz input that is in use by the current case
    pub fuzz_input: Vec<u8>,

    /// Holds the current program break at which new memory is allocated whenever needed
    alloc_addr: u64,

    /// Allocations made during process run, used to find heap bugs
    /// (address, size)
    pub heap_allocations: FxHashMap<u64, usize>,

    /// Allocations made during process run using mmap, require different allocation routine
    /// since the default allocator does not take an address while mmap does
    pub mmap_allocations: FxHashMap<u64, usize>,

    /// Vector that holds addresses that have been dirtied, only one address per page recorded
    /// This enables us to keep track of all dirtied pages in a simple array that we can traverse 
    /// once while resetting to find all dirtied pages. Without this list we would have to iterate 
    /// through the entire bitmap to find dirtied pages.
    pub dirty: Vec<usize>,

    /// This indicates that a `uc_error` occured. This is mainly used by syscalls since 
    /// they can't directly return a result to the worker function
    pub error_flag: uc_error,

    /// This tracks the address of the last block used for edge-coverage tracking
    pub prev_block: u64,

    /// This tracks the new coverage that a fuzz-case finds. Reset after each case
    pub cov_count: usize,
}

impl ExecEnv {
    /// Create a new execution environment that is used to track state during fuzz-cases 
    pub fn new(size: usize) -> Self {
        ExecEnv {
            fd_list:           vec![File::new(STDIN), File::new(STDOUT), File::new(STDERR)],
            fuzz_input:        Vec::new(),
            alloc_addr:        FIRSTALLOCATION,
            heap_allocations:  FxHashMap::default(),
            mmap_allocations:  FxHashMap::default(),
            dirty:             Vec::with_capacity(size / 4096 + 1),
            error_flag:        uc_error::OK,
            prev_block:        0x8392674281237520, // (arbitrary high-entropy number)
            cov_count:         0x0,
        }
    }

    /// Allocate a new new memory region, memory is never repeated, each allocation returns fresh 
    /// memory, even if a prior allocation was free'd
    pub fn allocate(&mut self, uc: &mut Unicorn<'_, ()>, size: usize, perms: Permission) 
            -> Result<u64, uc_error> {
        // Need to align all allocations to page size due to unicorn restrictions
        let aligned_size = (0xfff + size) & !0xfff;
        let base = self.alloc_addr;

        // Cannot allocate without running out of memory
        if base >= MAX_ALLOCATION_ADDR || 
                base.checked_add(aligned_size as u64).unwrap() >= MAX_ALLOCATION_ADDR {
            return Err(uc_error::NOMEM);
        }

        // Register this allocation so it can later be free'd
        self.heap_allocations.insert(base, aligned_size);

        // Set permissions on allocated memory region and increase the next allocation addr
        uc.mem_protect(base, aligned_size, perms)?;
        self.alloc_addr = self.alloc_addr.checked_add(aligned_size as u64).unwrap();

        Ok(base)
    }

    /// Free a region of previously allocated memory
    pub fn free(&mut self, uc: &mut Unicorn<'_, ()>, addr: u64) 
            -> Result<(), uc_error> {

        if addr > MAX_ALLOCATION_ADDR {
            return Err(uc_error::InvalidFree);
        }

        // Get the allocation size and perform the free
        if let Some(allocation_size) = self.heap_allocations.get(&addr) {
            let aligned_size = (0xfff + allocation_size) & !0xfff;

            // Free memory by resetting permissions to `NONE`. 
            // We dont actually free the memory since that would be much more expensive
            uc.mem_protect(addr, aligned_size, Permission::NONE)?;
            Ok(())
        } else {
            panic!("Attempting to free memory that hasn't been allocted @ 0x{addr:X}");
        }
    }

    /// Allocate a new file in the emulator
    pub fn alloc_file(&mut self, ftype: FileType) -> usize {
        let file = File::new(ftype);
        self.fd_list.push(file);
        self.fd_list.len() - 1
    }

    /// Take a snapshot of the current emulator state and return it
    pub fn save_reset_state(&mut self, unicorn: &Unicorn<'_, ()>, page_list: Vec<usize>) 
            -> Result<SnapshotContext, uc_error> {

        // Initialize page-map that keeps track of initial memory mappings
        let mut page_map = FxHashMap::default();
        for addr in page_list {
            let data = unicorn.mem_read_as_vec(addr as u64, 0x1000)?;

            assert_eq!(page_map.insert(addr, data.to_owned()),
                    None, "Attempted to insert duplicate pages into page-map");
        }

        // Initialize cpu-context (keeps track of registers, eflags, etc
        let cpu_context = unicorn.context_init()?;

        // Initialize file-mappings
        let fd_list = self.fd_list.clone();

        Ok(SnapshotContext {
            page_map,
            cpu_context,
            fd_list,
            prev_block: self.prev_block,
            alloc_addr: self.alloc_addr,
        })
    }

    /// Reset the emulator state based on the previously stored snapshot_context
    pub fn reset_snapshot(&mut self, unicorn: &mut Unicorn<'_, ()>, 
                          snapshot_context: &SnapshotContext) -> Result<(), uc_error> {
        // Restore unicorn cpu-state context
        unicorn.context_restore(&snapshot_context.cpu_context)?;

        // Restore unicorn memory-state context and dirty lists
        for &addr in &self.dirty {
            let page_start = (addr & !(0x1000-1)) as u64;

            // Reset bitmap-entry for this page
            unicorn.reset_dirty(addr as u64);

            // Reset all dirtied memory pages by restoring from an original copy
            if let Some(original_memory) = snapshot_context.page_map.get(&(page_start as usize)) {
                unicorn.mem_write(page_start, original_memory)?;
            } else {
                // This case is triggered with pages that were not yet initialized during our 
                // initial snapshot. This means they were allocated during runtime and can thus just 
                // be zeroed out.
                let original_memory = vec![0x0u8; 0x1000];
                unicorn.mem_write(page_start, &original_memory)?;
            }
        }
        self.dirty.clear();

        // Free all Heap allocations made in the fuzz-case by resetting permissions of memory
        // regions to `NONE`. We dont actually free the memory since that would be much more 
        // expensive
        for (alloc_addr, size) in &self.heap_allocations {
            unicorn.mem_protect(*alloc_addr, *size, Permission::NONE)?;
        }
        self.heap_allocations.clear();

        // For mmap'd regions, actually remove them cause they pollute the address space
        for (alloc_addr, size) in &self.mmap_allocations {
            unicorn.mem_unmap(*alloc_addr, *size)?;
        }
        self.mmap_allocations.clear();

        // Reset files to initial state
        self.fd_list = snapshot_context.fd_list.clone();

        // Reset current base address of allocator
        self.alloc_addr = snapshot_context.alloc_addr;

        // Reset error flag to `Ok`in case it was used to set an error in the previous case
        self.error_flag = uc_error::OK;

        // Reset previous block to snapshot state
        self.prev_block = snapshot_context.prev_block;

        // Reset coverage-counter after every fuzz-case
        self.cov_count = 0;

        Ok(())
    }
}

/// Save initial state that fuzz-cases will be based on. All future snapshot resets will go back 
/// to this initial state
pub fn take_snapshot(exec_env: &Rc<RefCell<ExecEnv>>, uc: &Unicorn<'_, ()>) 
        -> Result<SnapshotContext, uc_error> {
    let mut page_list: Vec<usize> = Vec::new();
    for mem_region in uc.mem_regions()? {
        if mem_region.perms != Permission::NONE {
            let num_pages = ((mem_region.end + 1) - mem_region.begin) / 4096;
            for i in 0..num_pages {
                let addr = mem_region.begin + (4096 * i);
                page_list.push(addr as usize);
            }
        }
    }
    exec_env.borrow_mut().save_reset_state(uc, page_list)
}
