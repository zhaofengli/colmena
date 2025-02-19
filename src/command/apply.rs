use std::env;
use std::path::PathBuf;

use clap::{builder::ArgPredicate, Args};

use crate::error::ColmenaError;
use crate::nix::{
    deployment::{Deployment, EvaluationNodeLimit, EvaluatorType, Goal, Options, ParallelismLimit},
    node_filter::NodeFilterOpts,
    Hive,
};
use crate::progress::SimpleProgressOutput;

#[derive(Debug, Args)]
pub struct DeployOpts {
    #[arg(
        value_name = "LIMIT",
        default_value_t,
        long,
        help = "Evaluation node limit",
        long_help = r#"Limits the maximum number of hosts to be evaluated at once.

The evaluation process is RAM-intensive. The default behavior is to limit the maximum number of host evaluated at the same time based on naive heuristics.

Set to 0 to disable the limit.
"#
    )]
    eval_node_limit: EvaluationNodeLimit,
    #[arg(
        value_name = "LIMIT",
        default_value_t = 10,
        long,
        short,
        help = "Deploy parallelism limit",
        long_help = r#"Limits the maximum number of hosts to be deployed in parallel.

Set to 0 to disable parallelism limit.
"#
    )]
    parallel: usize,
    #[arg(
        long,
        help = "Create GC roots for built profiles",
        long_help = r#"Create GC roots for built profiles.

The built system profiles will be added as GC roots so that they will not be removed by the garbage collector.
The links will be created under .gcroots in the directory the Hive configuration is located.
"#
    )]
    keep_result: bool,
    #[arg(
        short,
        long,
        help = "Be verbose",
        long_help = "Deactivates the progress spinner and prints every line of output."
    )]
    verbose: bool,
    #[arg(
        long,
        help = "Do not upload keys",
        long_help = r#"Do not upload secret keys set in `deployment.keys`.

By default, Colmena will upload keys set in `deployment.keys` before deploying the new profile on a node.
To upload keys without building or deploying the rest of the configuration, use `colmena upload-keys`.
"#
    )]
    no_keys: bool,
    #[arg(
        long,
        help = "Reboot nodes after activation",
        long_help = "Reboots nodes after activation and waits for them to come back up."
    )]
    reboot: bool,
    #[arg(
        long,
        alias = "no-substitutes",
        help = "Do not use substitutes",
        long_help = "Disables the use of substituters when copying closures to the remote host.",
        overrides_with = "use_substitute"
    )]
    no_substitute: bool,
    #[arg(
        long,
        alias = "use-substitutes",
        help = "Use substitutes",
        long_help = r#"Enable the use of substituters when copying closures to the remote host.

By default, Colmena enables the use of substitutes. This can be disabled via the per-node
`deployment.noSubstitutes` option, which can be overridden with this flag."#
    )]
    use_substitute: bool,
    #[arg(
        long,
        help = "Do not use gzip",
        long_help = "Disables the use of gzip when copying closures to the remote host."
    )]
    no_gzip: bool,
    #[arg(
        long,
        help = "Build the system profiles on the target nodes",
        long_help = r#"Build the system profiles on the target nodes themselves.

If enabled, the system profiles will be built on the target nodes themselves, not on the host running Colmena itself.
This overrides per-node perferences set in `deployment.buildOnTarget`.
To temporarily disable remote build on all nodes, use `--no-build-on-target`.
"#
    )]
    build_on_target: bool,
    #[arg(long, hide = true)]
    no_build_on_target: bool,
    #[arg(
        long,
        help = "Ignore all targeted nodes deployment.replaceUnknownProfiles setting",
        long_help = r#"If `deployment.replaceUnknownProfiles` is set for a target, using this switch
will treat deployment.replaceUnknownProfiles as though it was set true and perform unknown profile replacement."#
    )]
    force_replace_unknown_profiles: bool,
    #[arg(
        long,
        default_value_t,
        help = "The evaluator to use (experimental)",
        long_help = r#"If set to `chunked` (default), evaluation of nodes will happen in batches. If set to `streaming`, the experimental streaming evaluator (nix-eval-jobs) will be used and nodes will be evaluated in parallel.

This is an experimental feature."#
    )]
    evaluator: EvaluatorType,
    #[command(flatten)]
    node_filter: NodeFilterOpts,
}

#[derive(Debug, Args)]
#[command(name = "apply", about = "Apply configurations on remote machines")]
pub struct Opts {
    #[arg(
        help = "Deployment goal",
        long_help = r#"The goal of the deployment.

Same as the targets for switch-to-configuration, with the following extra pseudo-goals:

- build: Only build the system profiles
- push: Only copy the closures to remote nodes
- keys: Only upload the keys to the remote nodes

`switch` is the default goal unless `--reboot` is passed, in which case `boot` is the default.
"#,
        default_value_t,
        default_value_if("reboot", ArgPredicate::IsPresent, Some("boot"))
    )]
    pub goal: Goal,
    #[command(flatten)]
    pub deploy: DeployOpts,
}

pub async fn run(hive: Hive, opts: Opts) -> Result<(), ColmenaError> {
    let ssh_config = env::var("SSH_CONFIG_FILE").ok().map(PathBuf::from);

    let Opts {
        goal,
        deploy:
            DeployOpts {
                eval_node_limit,
                parallel,
                keep_result,
                verbose,
                no_keys,
                reboot,
                no_substitute,
                use_substitute,
                no_gzip,
                build_on_target,
                no_build_on_target,
                force_replace_unknown_profiles,
                evaluator,
                node_filter,
            },
    } = opts;

    if node_filter.on.is_none() && goal != Goal::Build {
        // User did not specify node, we should check meta and see rules
        let meta = hive.get_meta_config().await?;
        if !meta.allow_apply_all {
            log::error!("No node filter is specified and meta.allowApplyAll is set to false.");
            log::error!("Hint: Filter the nodes with --on.");
            quit::with_code(1);
        }
    }

    let targets = hive
        .select_nodes(
            node_filter.on.clone(),
            ssh_config,
            goal.requires_target_host(),
        )
        .await?;
    let n_targets = targets.len();

    let verbose = verbose || goal == Goal::DryActivate;
    let mut output = SimpleProgressOutput::new(verbose);
    let progress = output.get_sender();

    let mut deployment = Deployment::new(hive, targets, goal, progress);

    // FIXME: Configure limits
    let options = {
        let mut options = Options::default();
        options.set_gzip(!no_gzip);
        options.set_upload_keys(!no_keys);
        options.set_reboot(reboot);
        options.set_force_replace_unknown_profiles(force_replace_unknown_profiles);
        options.set_evaluator(evaluator);

        if no_substitute {
            options.set_substituters_push(!no_substitute);
        } else if use_substitute {
            options.set_substituters_push(use_substitute);
        }

        if keep_result {
            options.set_create_gc_roots(true);
        }

        if no_build_on_target {
            options.set_force_build_on_target(false);
        } else if build_on_target {
            options.set_force_build_on_target(true);
        }

        options
    };

    deployment.set_options(options);

    if no_keys && goal == Goal::UploadKeys {
        log::error!("--no-keys cannot be used when the goal is to upload keys");
        quit::with_code(1);
    }

    let parallelism_limit = {
        let mut limit = ParallelismLimit::default();
        limit.set_apply_limit({
            if parallel == 0 {
                n_targets
            } else {
                parallel
            }
        });
        limit
    };

    deployment.set_parallelism_limit(parallelism_limit);
    deployment.set_evaluation_node_limit(eval_node_limit);

    let (deployment, output) = tokio::join!(deployment.execute(), output.run_until_completion(),);

    deployment?;
    output?;

    Ok(())
}
