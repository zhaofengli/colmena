//! Parallelism limits.

use tokio::sync::Semaphore;

/// Amount of RAM reserved for the system, in MB.
const EVAL_RESERVE_MB: u64 = 1024;

/// Estimated amount of RAM needed to evaluate one host, in MB.
const EVAL_PER_HOST_MB: u64 = 512;

/// The parallelism limit for a deployment.
#[derive(Debug)]
pub struct ParallelismLimit {
    /// Limit of concurrent evaluation processes.
    pub evaluation: Semaphore,

    /// Limit of concurrent apply processes.
    pub apply: Semaphore,
}

impl Default for ParallelismLimit {
    fn default() -> Self {
        Self {
            evaluation: Semaphore::new(1),
            apply: Semaphore::new(10),
        }
    }
}

impl ParallelismLimit {
    /// Sets the concurrent apply limit.
    pub fn set_apply_limit(&mut self, limit: usize) {
        self.apply = Semaphore::new(limit);
    }
}

/// Limit of the number of nodes in each evaluation process.
///
/// The evaluation process is very RAM-intensive, with memory
/// consumption scaling linearly with the number of nodes
/// evaluated at the same time. This can be a problem if you
/// are deploying to a large number of nodes at the same time,
/// where `nix-instantiate` may consume too much RAM and get
/// killed by the OS (`ChildKilled` error).
///
/// Evaluating each node on its own is not an efficient solution,
/// with total CPU time and memory consumption vastly exceeding the
/// case where we evaluate the same set of nodes at the same time
/// (TODO: Provide statistics).
///
/// To overcome this problem, we split the evaluation process into
/// chunks when necessary, with the maximum number of nodes in
/// each `nix-instantiate` invocation determined with:
///
/// - A simple heuristic based on remaining memory in the system
/// - A supplied number
/// - No limit at all
#[derive(Copy, Clone, Debug)]
pub enum EvaluationNodeLimit {
    /// Use a naive heuristic based on available memory.
    Heuristic,

    /// Supply the maximum number of nodes.
    Manual(usize),

    /// Do not limit the number of nodes in each evaluation process
    None,
}

impl Default for EvaluationNodeLimit {
    fn default() -> Self {
        Self::Heuristic
    }
}

impl EvaluationNodeLimit {
    /// Returns the maximum number of hosts in each evaluation.
    ///
    /// The result should be cached.
    pub fn get_limit(&self) -> Option<usize> {
        match self {
            EvaluationNodeLimit::Heuristic => {
                if let Ok(mem_info) = sys_info::mem_info() {
                    let mut mb = mem_info.avail / 1024;

                    if mb >= EVAL_RESERVE_MB {
                        mb -= EVAL_RESERVE_MB;
                    }

                    let nodes = mb / EVAL_PER_HOST_MB;

                    if nodes == 0 {
                        Some(1)
                    } else {
                        Some(nodes as usize)
                    }
                } else {
                    Some(10)
                }
            }
            EvaluationNodeLimit::Manual(limit) => Some(*limit),
            EvaluationNodeLimit::None => None,
        }
    }
}
