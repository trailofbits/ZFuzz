use zfuzz::{
    Statistics, AllShared, Input, worker, TargetShared,
    arg_setup::{handle_cli, Cli},
    targets::targets::{HarnessInit, TARGET_INIT_FUNCTIONS, TARGETS},
    execution_state::take_snapshot,
    pretty_printing::print_stats,
};

use unicorn_engine::unicorn_const::uc_error;
use rustc_hash::FxHashMap;
use console::Term;
use clap::Parser;

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Setup and spawn fuzzer-threads for target with given `target_id`
fn start_target(tx: &Sender<Statistics>, all_shared: Arc<AllShared>, harness_init: HarnessInit) {

    // Set up a temporary exec_env/unicorn engine to create the initial memory/file/context snapshot
    let snapshot = {
        let (exec_env, unicorn) = TARGET_INIT_FUNCTIONS[harness_init.target_id]()
                                        .expect("Failed to initialize one of the fuzz-targets");
        take_snapshot(&exec_env, &unicorn)
            .expect(&format!("Failed to snapshot target: {}", harness_init.target_id))
    };
    
    let target_shared: Arc<TargetShared> = Arc::new(TargetShared::default());

    // Wrap thread-shared objects for this target in `Arc` so they can be safely shared
    let snapshot = Arc::new(snapshot);

    // Spawn worker threads to do the actual fuzzing for the `target_id` target 
    for _ in 0..harness_init.num_threads {
        let all_shared    = all_shared.clone();
        let target_shared = target_shared.clone();
        let snapshot      = snapshot.clone();
        let tx            = tx.clone();

        thread::spawn(move || worker(&harness_init, snapshot, all_shared, target_shared, tx));
    }
}

fn main() -> Result<(), uc_error> {
    // Parse commandline-args and set config variables based on them
    let mut args: Cli = Cli::parse();
    handle_cli(&mut args);

    // Statistics structure. This is kept local to the main thread and updated via message passing 
    // from the worker threads to reduce shared state
    let mut stats: FxHashMap<usize, Statistics> = FxHashMap::default();
    TARGETS.iter().for_each(|t| { stats.insert(t.target_id, Statistics::new(t.target_id)); });

    // Messaging objects used to transfer statistics between worker threads and main thread
    let (tx, rx): (Sender<Statistics>, Receiver<Statistics>) = mpsc::channel();

    // This structure is shared between all threads and targets. It is initialized with the initial 
    // input files and then keeps track of new inputs and some input-related statistics
    let all_shared: AllShared = AllShared::new();
    {
        let mut corpus_tmp = all_shared.inputs.write();
        for filename in std::fs::read_dir(args.input_dir).unwrap() {
            let filename = filename.unwrap().path();
            let data = std::fs::read(filename).expect("Failed to read input file");

            // Add the input to the corpus
            corpus_tmp.push(Input::new(data));
        }
        if corpus_tmp.is_empty() { panic!("Please supply at least 1 initial seed"); }
    }

    // Wrap data in an `Arc` to make it thread-safe
    let all_shared = Arc::new(all_shared);

    // Starts up all registered targets
    {
        TARGETS.iter().for_each(|t| start_target(&tx, all_shared.clone(), *t));
    }

    // Continuous statistic tracking via message passing in main thread
    let start = Instant::now();
    let mut last_time = Instant::now();
    let mut last_cov_event: f64 = 0.0;
    let term = Term::buffered_stdout();
    term.clear_screen().unwrap();

    // Sleep for short duration on startup before printing statistics, otherwise elapsed time might
    // be 0, leading to a div-by-0 crash while printing statistics
    thread::sleep(Duration::from_millis(1000));

    for received in rx {
        let elapsed_time = start.elapsed().as_secs_f64();

        // Check if we got new coverage
        if received.coverage != 0 {
            last_cov_event = elapsed_time;
        }

        let id = received.target_id;

        stats.get_mut(&id).unwrap().total_cases   += received.total_cases;
        stats.get_mut(&id).unwrap().crashes       += received.crashes;
        stats.get_mut(&id).unwrap().ucrashes      += received.ucrashes;
        stats.get_mut(&id).unwrap().coverage      += received.coverage;
        stats.get_mut(&id).unwrap().invalid_insns += received.invalid_insns;
        stats.get_mut(&id).unwrap().num_inputs     = received.num_inputs;

        // Print out updated statistics every second
        if last_time.elapsed() >= Duration::from_millis(500) {
            print_stats(&term, &stats, elapsed_time, last_cov_event);
            last_time = Instant::now();
        }
    }
    Ok(())
}
