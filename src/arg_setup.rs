use crate::{
    error_exit,
    targets::targets::TARGETS,
};
use clap::Parser;
use std::sync::OnceLock;

/// Address at which the fuzzer attempts to create a snapshot once reached
pub static SNAPSHOT_ADDR: OnceLock<Option<usize>> = OnceLock::new();

/// Number of cores to run the fuzzer with
pub static NUM_THREADS: OnceLock<usize> = OnceLock::new();

/// File that contains the user-supplied dictionary
pub static DICT_FILE: OnceLock<Option<String>> = OnceLock::new();

/// Path to directory to which fuzzer-outputs are saved
pub static OUTPUT_DIR: OnceLock<String> = OnceLock::new();

/// Additional information is printed out, alongside rolling statistics. Some parts of this only
/// work while running single-threaded
pub static DEBUG_PRINT: OnceLock<bool> = OnceLock::new();

/// Used by clap to parse command-line arguments
#[derive(Debug, Parser)]
#[clap(author = "seal9055", version, about = "tmp")]
#[clap(override_usage = "zfuzz [OPTION] -- /path/to/fuzzed_app [ ... ] (use `@@` to specify \
    position of fuzz-input in target-argv)\n\n    ex: zfuzz -- ./test_cases/test @@")]
pub struct Cli {
    #[clap(short, value_name = "DIR", forbid_empty_values = true, display_order = 1)]
    /// - Input directory that should contain the initial seed files
    pub input_dir: String,

    #[clap(short, value_name = "DIR", forbid_empty_values = true, display_order = 2)]
    /// - Output directory that will be used to eg. save crashes
    pub output_dir: String,

    #[clap(short = 'd', value_name = "DICT", help_heading = "CONFIG", forbid_empty_values = true)]
    /// - Optionally supply a new-line separated list of inputs that will be mutated into the 
    /// fuzz-inputs
    pub dictionary: Option<String>,

    #[clap(short = 'V', takes_value = false)]
    /// - Print version information
    pub version: bool,

    #[clap(short = 'h', takes_value = false)]
    /// - Print help information
    pub help: bool,

    #[clap(short = 'D', help_heading = "CONFIG", takes_value = false)]
    /// - Enable a rolling debug-print and information on which functions are lifted instead of the
    /// default print-window
    pub debug_print: bool,
}

/// Initialize configuration variables based on passed in commandline arguments, and verify that
/// the user properly setup their fuzz-case
pub fn handle_cli(args: &mut Cli) {
    DEBUG_PRINT.set(!args.debug_print).unwrap();
    // Verify that the input and output directories are valid
    if !std::path::Path::new(&args.input_dir).is_dir() {
        error_exit("You need to specify a valid input directory");
    }

    if !std::path::Path::new(&args.output_dir).is_dir() {
        error_exit("You need to specify a valid output directory");
    }
    OUTPUT_DIR.set(args.output_dir.clone()).unwrap();

    if let Some(dict) = &args.dictionary {
        if !std::path::Path::new(&dict).is_file() {
            error_exit("You need to specify a valid dictionary file");
        }
        DICT_FILE.set(Some(dict.to_string())).unwrap();
    } else {
        DICT_FILE.set(None).unwrap();
    }

    // Create the directory to save output too
    for target in TARGETS {
        let mut crash_dir = args.output_dir.clone();
        crash_dir.push_str(&format!("/{}/crashes/", target.target_id));

        let mut inv_insns_dir = args.output_dir.clone();
        inv_insns_dir.push_str(&format!("/{}/inv_insns/", target.target_id));

        std::fs::create_dir_all(crash_dir).unwrap();
        std::fs::create_dir_all(inv_insns_dir).unwrap();
    }
}
