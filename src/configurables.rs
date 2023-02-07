//! This file contains some configurables that you may want to edit depending on the target you are
//! fuzzing

/// Specify a file-name that if operated on is caught by the fuzzer. This can be used to specify
/// a filename that represents the fuzz-case inputs. Whenever the target tries using this file
/// (eg. with a `read` syscall to read in input), `ExecState::fuzz_input` is used as the backing
pub const FUZZ_INPUT: &str = "fuzz_input";

/// Once an input is chosen for mutations, it is mutated/ran in the fuzzer `SEED_ENERGY` times
/// before moving on to the next input. Statistic updates are also only done every `SEED_ENERGY`
/// cases. The slower the target is executing, the lower `SEED_ENERGY` should be to consistently get
/// stats updates. Lowering it too much will hurt performance though, especially for faster targets
pub const SEED_ENERGY: usize = 1000;

/// Size of the coverage-map. Larger map is less cache-friendly but will result in less
/// hash-collisions while collection coverage
pub const COVMAP_SIZE: u64 = 1024 * 1024 * 1024;

/// Enables some debug prints
pub const DEBUG: bool = false;

/// The starting address for our memory allocator (Change if this overlaps with an address the 
/// target uses
pub const FIRSTALLOCATION: u64 = 0x900000;

/// Amount of memory allocated for each emulator to handle stack & heap allocations
pub const VMMAP_ALLOCATION_SIZE: usize = 16 * 1024 * 1024;

/// Maximum address that can be used by the emulator for allocations before going OOM
pub const MAX_ALLOCATION_ADDR: u64 = FIRSTALLOCATION + VMMAP_ALLOCATION_SIZE as u64;

/// Set the mutator type, either based on mutations or grammar-based generation
pub const MUTATOR: MutType = MutType::Mut;

#[derive(Eq, PartialEq)]
pub enum MutType {
    Mut,
    Gen,
}
