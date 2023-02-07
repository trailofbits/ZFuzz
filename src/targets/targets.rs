//! Use this file to register harness functions/initialization-data for your targets

use crate::{
    execution_state::ExecEnv, targets,
};

use unicorn_engine::{
    Unicorn,
    unicorn_const::uc_error,
};

use std::cell::RefCell;
use std::rc::Rc;

const NUM_TARGETS: usize = 1;

/// Setup basic configuration for your targets
/// Register one or more harnesses that are used to initialize the fuzzer(s)
pub const TARGETS: [HarnessInit; NUM_TARGETS] = [
    HarnessInit {
        target_id: TargetId::TargetOne as usize,
        num_threads: 1,
        instr_timeout: 0,
        time_timeout: 0,
    },
];

/// Registered targets
/// Give your target a `TargetId` that lines up with its index in `TARGET_INIT_FUNCTIONS`
pub enum TargetId {
    TargetOne = 0,
    TargetTwo = 1,
}

/// List of functions used to initialize targets
/// Use this to register your harness initialization function
pub const TARGET_INIT_FUNCTIONS:
    [fn() -> 
        Result<(Rc<RefCell<ExecEnv>>, Unicorn<'static, ()>), 
        uc_error>; std::mem::variant_count::<TargetId>()] = 
        [
            targets::target_1::initialize_target,
            targets::target_2::initialize_target,
        ];

/// Data passed to worker function/harness that describes some run-options
#[derive(Clone, Copy)]
pub struct HarnessInit {
    /// Target-id used to determine which harness to run
    pub target_id: usize,

    /// Number of threads to run this target with
    pub num_threads: usize,

    /// Maximum amount of instructions to execute before terminating fuzz-case
    /// 0 to never timeout
    /// Note: Unicorn does not produce an error-condition for timeouts
    pub instr_timeout: usize,

    /// Maximum time in microseconds terminating fuzz-case
    /// 0 to never timeout
    /// Note: Unicorn does not produce an error-condition for timeouts
    pub time_timeout: u64,
}

