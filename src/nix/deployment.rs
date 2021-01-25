use std::cmp::max;
use std::sync::Arc;
use std::collections::HashMap;

use futures::future::join_all;
use futures::join;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};
use tokio::sync::{Mutex, Semaphore};

use super::{Hive, Host, CopyOptions, host};
use crate::progress::get_spinner_styles;

/// Amount of RAM reserved for the system, in MB. 
const EVAL_RESERVE_MB: u64 = 1024;

/// Estimated amount of RAM needed to evaluate one host, in MB. 
const EVAL_PER_HOST_MB: u64 = 512;

const BATCH_OPERATION_LABEL: &'static str = "(...)";

macro_rules! set_up_batch_progress_bar {
    ($multi:ident, $style:ident, $chunk:ident, $single_text:expr, $batch_text:expr) => {{
        let bar = $multi.add(ProgressBar::new(100));
        bar.set_style($style.clone());
        bar.enable_steady_tick(100);

        if $chunk.len() == 1 {
            bar.set_prefix(&$chunk[0]);
            bar.set_message($single_text);
        } else {
            bar.set_prefix(BATCH_OPERATION_LABEL);
            bar.set_message(&format!($batch_text, $chunk.len()));
        }
        bar.inc(0);

        bar
    }};
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DeploymentGoal {
    /// Build the configurations only.
    Build,

    /// Push the closures only.
    Push,

    /// Make the configuration the boot default and activate now.
    Switch,

    /// Make the configuration the boot default.
    Boot,

    /// Activate the configuration, but don't make it the boot default.
    Test,

    /// Show what would be done if this configuration were activated.
    DryActivate,
}

impl DeploymentGoal {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "build" => Some(Self::Build),
            "push" => Some(Self::Push),
            "switch" => Some(Self::Switch),
            "boot" => Some(Self::Boot),
            "test" => Some(Self::Test),
            "dry-activate" => Some(Self::DryActivate),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'static str> {
        use DeploymentGoal::*;
        match self {
            Build => None,
            Push => None,
            Switch => Some("switch"),
            Boot => Some("boot"),
            Test => Some("test"),
            DryActivate => Some("dry-activate"),
        }
    }

    pub fn success_str(&self) -> Option<&'static str> {
        use DeploymentGoal::*;
        match self {
            Build => Some("Configuration built"),
            Push => Some("Pushed"),
            Switch => Some("Activation successful"),
            Boot => Some("Will be activated next boot"),
            Test => Some("Activation successful (test)"),
            DryActivate => Some("Dry activation successful"),
        }
    }

    pub fn should_switch_profile(&self) -> bool {
        use DeploymentGoal::*;
        match self {
            Boot | Switch => true,
            _ => false,
        }
    }

    pub fn requires_activation(&self) -> bool {
        use DeploymentGoal::*;
        match self {
            Build | Push => false,
            _ => true,
        }
    }
}

/// Internal deployment stages
#[derive(Debug)]
enum DeploymentStage {
    Evaluate(Vec<String>),
    Build(Vec<String>),
    Apply(String),
}

/// Results of a deployment to a node
#[derive(Debug)]
struct DeploymentResult {
    /// Stage in which the deployment ended.
    stage: DeploymentStage,

    /// Whether the deployment succeeded or not.
    success: bool,

    /// Unstructured logs of the deployment.
    logs: Option<String>,
}

impl DeploymentResult {
    fn success(stage: DeploymentStage, logs: Option<String>) -> Self {
        Self {
            stage,
            success: true,
            logs,
        }
    }

    fn failure(stage: DeploymentStage, logs: Option<String>) -> Self {
        Self {
            stage,
            success: true,
            logs,
        }
    }

    fn is_successful(&self) -> bool {
        self.success
    }

    fn print(&self) {
        use DeploymentStage::*;

        if self.is_successful() {
            unimplemented!();
        }

        match &self.stage {
            Evaluate(nodes) => {
                self.print_failed_nodes("Evaluation of", &nodes);
            }
            Build(nodes) => {
                self.print_failed_nodes("Build of", &nodes);
            }
            Apply(node) => {
                self.print_failed_nodes("Deployment to", &vec![node.clone()]);
            }
        }
    }

    fn print_failed_nodes(&self, prefix: &'static str, nodes: &Vec<String>) {
        let last_lines: Option<Vec<String>> = self.logs.as_ref().map(|logs| {
            logs.split("\n").collect::<Vec<&str>>().iter().rev().take(10).rev()
                .map(|line| line.to_string()).collect()
        });

        let msg = if nodes.len() == 1 {
            format!("{} {} failed.", prefix, nodes[0])
        } else {
            format!("{} {} nodes failed.", prefix, nodes.len())
        };

        if let Some(lines) = last_lines {
            log::error!("{} Last {} lines of logs:", msg, lines.len());
            for line in lines {
                log::error!("{}", line);
            }
        }
    }
}

#[derive(Debug)]
pub struct Deployment {
    hive: Hive,
    goal: DeploymentGoal,
    nodes: Vec<String>,
    node_hosts: Mutex<HashMap<String, Box<dyn Host>>>,
    parallelism_limit: ParallelismLimit,
    evaluation_node_limit: EvaluationNodeLimit,
    options: DeploymentOptions,
    results: Mutex<Vec<DeploymentResult>>,
}

impl Deployment {
    pub fn new(hive: Hive, targets: HashMap<String, Box<dyn Host>>, goal: DeploymentGoal) -> Self {
        let nodes: Vec<String> = targets.keys().cloned().collect();

        Self {
            hive,
            goal,
            nodes,
            node_hosts: Mutex::new(targets),
            parallelism_limit: ParallelismLimit::default(),
            evaluation_node_limit: EvaluationNodeLimit::default(),
            options: DeploymentOptions::default(),
            results: Mutex::new(Vec::new()),
        }
    }

    pub fn set_options(&mut self, options: DeploymentOptions) {
        self.options = options;
    }

    pub fn set_parallelism_limit(&mut self, limit: ParallelismLimit) {
        self.parallelism_limit = limit;
    }

    pub fn set_evaluation_node_limit(&mut self, limit: EvaluationNodeLimit) {
        self.evaluation_node_limit = limit;
    }

    /// Executes the deployment (user-facing)
    ///
    /// Self must be wrapped inside an Arc.
    pub async fn execute(self: Arc<Self>) {
        let multi = Arc::new(MultiProgress::new());
        let root_bar = Arc::new(multi.add(ProgressBar::new(100)));
        let alignment = self.node_name_alignment();
        multi.set_draw_target(ProgressDrawTarget::stderr_nohz());

        {
            let (spinner_style, _) = get_spinner_styles(alignment);
            root_bar.set_message("Running...");
            root_bar.set_style(spinner_style);
            root_bar.tick();
            root_bar.enable_steady_tick(100);
        }

        let arc_self = self.clone();
        let eval_limit = arc_self.clone().eval_limit();

        // FIXME: Saner logging
        let mut futures = Vec::new();

        for chunk in self.nodes.chunks(eval_limit) {
            let arc_self = self.clone();
            let multi = multi.clone();
            let (spinner_style, failing_spinner_style) = get_spinner_styles(alignment);

            // FIXME: Eww
            let chunk: Vec<String> = chunk.iter().map(|s| s.to_string()).collect();

            futures.push(tokio::spawn(async move {
                let drv = {
                    // Evaluation phase
                    let permit = arc_self.parallelism_limit.evaluation.acquire().await.unwrap();

                    let bar = set_up_batch_progress_bar!(multi, spinner_style, chunk,
                        "Evaluating configuration...",
                        "Evaluating configurations for {} nodes"
                    );

                    let drv = match arc_self.hive.eval_selected(&chunk, Some(bar.clone())).await {
                        Ok(drv) => {
                            bar.finish_and_clear();
                            drv
                        }
                        Err(e) => {
                            bar.set_style(failing_spinner_style.clone());
                            bar.abandon_with_message(&format!("Evalation failed: {}", e));

                            let mut results = arc_self.results.lock().await;
                            let stage = DeploymentStage::Evaluate(chunk.clone());
                            results.push(DeploymentResult::failure(stage, None));
                            return;
                        }
                    };

                    drop(permit);
                    drv
                };

                let profiles = {
                    // Build phase
                    let permit = arc_self.parallelism_limit.build.acquire().await.unwrap();

                    let bar = set_up_batch_progress_bar!(multi, spinner_style, chunk,
                        "Building configuration...",
                        "Building configurations for {} nodes"
                    );

                    // FIXME: Remote build?
                    let mut builder = host::local();

                    if arc_self.options.progress_bar {
                        builder.set_progress_bar(bar.clone());
                    }

                    let profiles = match drv.realize(&mut *builder).await {
                        Ok(profiles) => {
                            let goal = arc_self.goal;
                            if goal == DeploymentGoal::Build {
                                bar.finish_with_message(goal.success_str().unwrap());

                                let mut results = arc_self.results.lock().await;
                                let stage = DeploymentStage::Build(chunk.clone());
                                let logs = builder.dump_logs().await.map(|s| s.to_string());
                                results.push(DeploymentResult::success(stage, logs));
                                return;
                            } else {
                                bar.finish_and_clear();
                                profiles
                            }
                        }
                        Err(e) => {
                            bar.set_style(failing_spinner_style.clone());
                            bar.abandon_with_message(&format!("Build failed: {}", e));

                            let mut results = arc_self.results.lock().await;
                            let stage = DeploymentStage::Build(chunk.clone());
                            let logs = builder.dump_logs().await.map(|s| s.to_string());
                            results.push(DeploymentResult::failure(stage, logs));
                            return;
                        }
                    };

                    drop(permit);
                    profiles
                };

                // Apply phase
                let mut futures = Vec::new();
                for node in chunk {
                    let arc_self = arc_self.clone();
                    let multi = multi.clone();
                    let spinner_style = spinner_style.clone();
                    let failing_spinner_style = failing_spinner_style.clone();

                    let mut host = {
                        let mut node_hosts = arc_self.node_hosts.lock().await;
                        node_hosts.remove(&node).unwrap()
                    };
                    let profile = profiles.get(&node).cloned()
                        .expect(&format!("Somehow profile for {} was not built", node));

                    futures.push(tokio::spawn(async move {
                        let permit = arc_self.parallelism_limit.apply.acquire().await.unwrap();

                        let bar = multi.add(ProgressBar::new(100));
                        bar.set_style(spinner_style);
                        bar.set_prefix(&node);
                        bar.set_message("Starting...");
                        bar.tick();
                        bar.enable_steady_tick(100);

                        if arc_self.options.progress_bar {
                            host.set_progress_bar(bar.clone());
                        }

                        let copy_options = arc_self.options.to_copy_options()
                            .include_outputs(true);

                        let goal = arc_self.goal;
                        match host.deploy(&profile, goal, copy_options).await {
                            Ok(_) => {
                                bar.finish_with_message(goal.success_str().unwrap());

                                let mut results = arc_self.results.lock().await;
                                let stage = DeploymentStage::Apply(node.clone());
                                let logs = host.dump_logs().await.map(|s| s.to_string());
                                results.push(DeploymentResult::success(stage, logs));
                            }
                            Err(e) => {
                                bar.set_style(failing_spinner_style);
                                bar.abandon_with_message(&format!("Failed: {}", e));

                                let mut results = arc_self.results.lock().await;
                                let stage = DeploymentStage::Apply(node.clone());
                                let logs = host.dump_logs().await.map(|s| s.to_string());
                                results.push(DeploymentResult::failure(stage, logs));
                            }
                        }

                        drop(permit);
                    }));
                }

                join_all(futures).await;
            }));
        }

        let wait_for_tasks = tokio::spawn(async move {
            join_all(futures).await;
            root_bar.finish_with_message("Finished");
        });

        let tasks_result = if self.options.progress_bar {
            let wait_for_bars = tokio::task::spawn_blocking(move || {
                multi.join().unwrap();
            });

            let (tasks_result, _) = join!(wait_for_tasks, wait_for_bars);

            tasks_result
        } else {
            wait_for_tasks.await
        };

        if let Err(e) = tasks_result {
            log::error!("Deployment process failed: {}", e);
        }

        self.print_logs().await;
    }

    async fn print_logs(&self) {
        let results = self.results.lock().await;
        for result in results.iter() {
            if !result.is_successful() {
                result.print();
            }
        }
    }

    fn node_name_alignment(&self) -> usize {
        if let Some(len) = self.nodes.iter().map(|n| n.len()).max() {
            max(BATCH_OPERATION_LABEL.len(), len)
        } else {
            BATCH_OPERATION_LABEL.len()
        }
    }

    fn eval_limit(&self) -> usize {
        if let Some(limit) = self.evaluation_node_limit.get_limit() {
            limit
        } else {
            self.nodes.len()
        }
    }
}

#[derive(Debug)]
pub struct ParallelismLimit {
    /// Limit of concurrent evaluation processes.
    evaluation: Semaphore,

    /// Limit of concurrent build processes.
    build: Semaphore,

    /// Limit of concurrent apply processes.
    apply: Semaphore,
}

impl Default for ParallelismLimit {
    fn default() -> Self {
        Self {
            evaluation: Semaphore::new(1),
            build: Semaphore::new(2),
            apply: Semaphore::new(10),
        }
    }
}

impl ParallelismLimit {
    // Do we actually want this to be configurable?
    /*
    /// Sets the concurrent evaluation limit.
    ///
    /// This limits the number of evaluation processes, not
    /// the number of nodes in each evaluation process.
    /// The latter is controlled in DeploymentOptions.
    pub fn set_evaluation_limit(&mut self, limit: usize) {
        self.evaluation = Semaphore::new(limit);
    }
    */

    /// Sets the concurrent build limit.
    pub fn set_build_limit(&mut self, limit: usize) {
        self.build = Semaphore::new(limit);
    }

    /// Sets the concurrent apply limit.
    pub fn set_apply_limit(&mut self, limit: usize) {
        self.apply = Semaphore::new(limit);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DeploymentOptions {
    /// Whether to show condensed progress bars.
    ///
    /// If set to false, verbose logs will be displayed instead.
    progress_bar: bool,

    /// Whether to use binary caches when copying closures to remote hosts.
    substituters_push: bool,

    /// Whether to use gzip when copying closures to remote hosts.
    gzip: bool,
}

impl Default for DeploymentOptions {
    fn default() -> Self {
        Self {
            progress_bar: true,
            substituters_push: true,
            gzip: true,
        }
    }
}

impl DeploymentOptions {
    pub fn set_progress_bar(&mut self, value: bool) {
        self.progress_bar = value;
    }

    pub fn set_substituters_push(&mut self, value: bool) {
        self.substituters_push = value;
    }

    pub fn set_gzip(&mut self, value: bool) {
        self.gzip = value;
    }

    fn to_copy_options(&self) -> CopyOptions {
        let options = CopyOptions::default();

        options
            .use_substitutes(self.substituters_push)
            .gzip(self.gzip)
    }
}

/// Limit of the number of nodes in each evaluation process.
///
/// The evaluation process is very RAM-intensive, with memory
/// consumption scaling linearly with the number of nodes
/// evaluated at the same time. This can be a problem if you
/// are deploying to a large number of nodes at the same time,
/// where `nix-instantiate` may consume too much RAM and get
/// killed by the OS (`NixKilled` error).
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
