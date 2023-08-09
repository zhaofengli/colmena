use std::env;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{
    builder::{ArgPredicate, PossibleValuesParser, ValueParser},
    value_parser, Arg, ArgMatches, Command as ClapCommand, FromArgMatches,
};

use crate::nix::deployment::{
    Deployment, EvaluationNodeLimit, EvaluatorType, Goal, Options, ParallelismLimit,
};
use crate::nix::NodeFilter;
use crate::progress::SimpleProgressOutput;
use crate::util;
use crate::{error::ColmenaError, nix::hive::HiveArgs};

pub fn register_deploy_args(command: ClapCommand) -> ClapCommand {
    command
        .arg(Arg::new("eval-node-limit")
            .long("eval-node-limit")
            .value_name("LIMIT")
            .help("Evaluation node limit")
            .long_help(r#"Limits the maximum number of hosts to be evaluated at once.

The evaluation process is RAM-intensive. The default behavior is to limit the maximum number of host evaluated at the same time based on naive heuristics.

Set to 0 to disable the limit.
"#)
            .default_value("auto")
            .num_args(1)
            .value_parser(ValueParser::new(|s: &str| -> Result<EvaluationNodeLimit, String> {
                if s == "auto" {
                    return Ok(EvaluationNodeLimit::Heuristic);
                }

                match s.parse::<usize>() {
                    Ok(0) => Ok(EvaluationNodeLimit::None),
                    Ok(n) => Ok(EvaluationNodeLimit::Manual(n)),
                    Err(_) => Err(String::from("The value must be a valid number")),
                }
            })))
        .arg(Arg::new("parallel")
            .short('p')
            .long("parallel")
            .value_name("LIMIT")
            .help("Deploy parallelism limit")
            .long_help(r#"Limits the maximum number of hosts to be deployed in parallel.

Set to 0 to disable parallemism limit.
"#)
            .default_value("10")
            .num_args(1)
            .value_parser(value_parser!(usize)))
        .arg(Arg::new("keep-result")
            .long("keep-result")
            .help("Create GC roots for built profiles")
            .long_help(r#"Create GC roots for built profiles.

The built system profiles will be added as GC roots so that they will not be removed by the garbage collector.
The links will be created under .gcroots in the directory the Hive configuration is located.
"#)
            .num_args(0))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .num_args(0))
        .arg(Arg::new("no-keys")
            .long("no-keys")
            .help("Do not upload keys")
            .long_help(r#"Do not upload secret keys set in `deployment.keys`.

By default, Colmena will upload keys set in `deployment.keys` before deploying the new profile on a node.
To upload keys without building or deploying the rest of the configuration, use `colmena upload-keys`.
"#)
            .num_args(0))
        .arg(Arg::new("reboot")
            .long("reboot")
            .help("Reboot nodes after activation")
            .long_help("Reboots nodes after activation and waits for them to come back up.")
            .num_args(0))
        .arg(Arg::new("no-substitute")
            .long("no-substitute")
            .alias("no-substitutes")
            .help("Do not use substitutes")
            .long_help("Disables the use of substituters when copying closures to the remote host.")
            .num_args(0))
        .arg(Arg::new("no-gzip")
            .long("no-gzip")
            .help("Do not use gzip")
            .long_help("Disables the use of gzip when copying closures to the remote host.")
            .num_args(0))
        .arg(Arg::new("build-on-target")
            .long("build-on-target")
            .help("Build the system profiles on the target nodes")
            .long_help(r#"Build the system profiles on the target nodes themselves.

If enabled, the system profiles will be built on the target nodes themselves, not on the host running Colmena itself.
This overrides per-node perferences set in `deployment.buildOnTarget`.
To temporarily disable remote build on all nodes, use `--no-build-on-target`.
"#)
            .num_args(0))
        .arg(Arg::new("no-build-on-target")
            .long("no-build-on-target")
            .hide(true)
            .num_args(0))
        .arg(Arg::new("force-replace-unknown-profiles")
            .long("force-replace-unknown-profiles")
            .help("Ignore all targeted nodes deployment.replaceUnknownProfiles setting")
            .long_help(r#"If `deployment.replaceUnknownProfiles` is set for a target, using this switch
will treat deployment.replaceUnknownProfiles as though it was set true and perform unknown profile replacement."#)
            .num_args(0))
        .arg(Arg::new("evaluator")
            .long("evaluator")
            .help("The evaluator to use (experimental)")
            .long_help(r#"If set to `chunked` (default), evaluation of nodes will happen in batches. If set to `streaming`, the experimental streaming evaluator (nix-eval-jobs) will be used and nodes will be evaluated in parallel.

This is an experimental feature."#)
            .default_value("chunked")
            .value_parser(value_parser!(EvaluatorType)))
}

pub fn subcommand() -> ClapCommand {
    let command = ClapCommand::new("apply")
        .about("Apply configurations on remote machines")
        .arg(
            Arg::new("goal")
                .help("Deployment goal")
                .long_help(
                    r#"The goal of the deployment.

Same as the targets for switch-to-configuration, with the following extra pseudo-goals:

- build: Only build the system profiles
- push: Only copy the closures to remote nodes
- keys: Only upload the keys to the remote nodes

`switch` is the default goal unless `--reboot` is passed, in which case `boot` is the default.
"#,
                )
                .default_value("switch")
                .default_value_if("reboot", ArgPredicate::IsPresent, Some("boot"))
                .default_value("switch")
                .index(1)
                .value_parser(PossibleValuesParser::new([
                    "build",
                    "push",
                    "switch",
                    "boot",
                    "test",
                    "dry-activate",
                    "keys",
                ])),
        );
    let command = register_deploy_args(command);

    util::register_selector_args(command)
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let hive = HiveArgs::from_arg_matches(local_args)
        .unwrap()
        .into_hive()
        .await
        .unwrap();

    let ssh_config = env::var("SSH_CONFIG_FILE").ok().map(PathBuf::from);

    // FIXME: Just get_one::<Goal>
    let goal_arg = local_args.get_one::<String>("goal").unwrap();
    let goal = Goal::from_str(goal_arg).unwrap();

    // FIXME: Just get_one::<NodeFilter>
    let filter = local_args
        .get_one::<String>("on")
        .map(NodeFilter::new)
        .transpose()?;

    if filter.is_none() && goal != Goal::Build {
        // User did not specify node, we should check meta and see rules
        let meta = hive.get_meta_config().await?;
        if !meta.allow_apply_all {
            log::error!("No node filter is specified and meta.allowApplyAll is set to false.");
            log::error!("Hint: Filter the nodes with --on.");
            quit::with_code(1);
        }
    }

    let targets = hive
        .select_nodes(filter, ssh_config, goal.requires_target_host())
        .await?;
    let n_targets = targets.len();

    let verbose = local_args.get_flag("verbose") || goal == Goal::DryActivate;
    let mut output = SimpleProgressOutput::new(verbose);
    let progress = output.get_sender();

    let mut deployment = Deployment::new(hive, targets, goal, progress);

    // FIXME: Configure limits
    let options = {
        let mut options = Options::default();
        options.set_substituters_push(!local_args.get_flag("no-substitute"));
        options.set_gzip(!local_args.get_flag("no-gzip"));
        options.set_upload_keys(!local_args.get_flag("no-keys"));
        options.set_reboot(local_args.get_flag("reboot"));
        options.set_force_replace_unknown_profiles(
            local_args.get_flag("force-replace-unknown-profiles"),
        );
        options.set_evaluator(
            local_args
                .get_one::<EvaluatorType>("evaluator")
                .unwrap()
                .to_owned(),
        );

        if local_args.get_flag("keep-result") {
            options.set_create_gc_roots(true);
        }

        if local_args.get_flag("no-build-on-target") {
            options.set_force_build_on_target(false);
        } else if local_args.get_flag("build-on-target") {
            options.set_force_build_on_target(true);
        }

        options
    };

    deployment.set_options(options);

    if local_args.get_flag("no-keys") && goal == Goal::UploadKeys {
        log::error!("--no-keys cannot be used when the goal is to upload keys");
        quit::with_code(1);
    }

    let parallelism_limit = {
        let mut limit = ParallelismLimit::default();
        limit.set_apply_limit({
            let limit = local_args.get_one::<usize>("parallel").unwrap().to_owned();
            if limit == 0 {
                n_targets
            } else {
                limit
            }
        });
        limit
    };

    let evaluation_node_limit = local_args
        .get_one::<EvaluationNodeLimit>("eval-node-limit")
        .unwrap()
        .to_owned();

    deployment.set_parallelism_limit(parallelism_limit);
    deployment.set_evaluation_node_limit(evaluation_node_limit);

    let (deployment, output) = tokio::join!(deployment.execute(), output.run_until_completion(),);

    deployment?;
    output?;

    Ok(())
}
