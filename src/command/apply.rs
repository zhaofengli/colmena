use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Arg, App, SubCommand, ArgMatches};

use crate::nix::deployment::{
    Deployment,
    Goal,
    Target,
    DeploymentOptions,
    EvaluationNodeLimit,
    ParallelismLimit,
};
use crate::nix::host::local as localhost;
use crate::util;

pub fn register_deploy_args<'a, 'b>(command: App<'a, 'b>) -> App<'a, 'b> {
    command
        .arg(Arg::with_name("eval-node-limit")
            .long("eval-node-limit")
            .value_name("LIMIT")
            .help("Evaluation node limit")
            .long_help(r#"Limits the maximum number of hosts to be evaluated at once.

The evaluation process is RAM-intensive. The default behavior is to limit the maximum number of host evaluated at the same time based on naive heuristics.

Set to 0 to disable the limit.
"#)
            .default_value("auto")
            .takes_value(true)
            .validator(|s| {
                if s == "auto" {
                    return Ok(());
                }

                match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value must be a valid number")),
                }
            }))
        .arg(Arg::with_name("parallel")
            .short("p")
            .long("parallel")
            .value_name("LIMIT")
            .help("Deploy parallelism limit")
            .long_help(r#"Limits the maximum number of hosts to be deployed in parallel.

Set to 0 to disable parallemism limit.
"#)
            .default_value("10")
            .takes_value(true)
            .validator(|s| {
                match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value must be a valid number")),
                }
            }))
        .arg(Arg::with_name("keep-result")
            .long("keep-result")
            .help("Create GC roots for built profiles")
            .long_help(r#"Create GC roots for built profiles.

The built system profiles will be added as GC roots so that they will not be removed by the garbage collector.
The links will be created under .gcroots in the directory the Hive configuration is located.
"#)
            .takes_value(false))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .takes_value(false))
        .arg(Arg::with_name("no-keys")
            .long("no-keys")
            .help("Do not upload keys")
            .long_help(r#"Do not upload secret keys set in `deployment.keys`.

By default, Colmena will upload keys set in `deployment.keys` before deploying the new profile on a node.
To upload keys without building or deploying the rest of the configuration, use `colmena upload-keys`.
"#)
            .takes_value(false))
        .arg(Arg::with_name("no-substitutes")
            .long("no-substitutes")
            .help("Do not use substitutes")
            .long_help("Disables the use of substituters when copying closures to the remote host.")
            .takes_value(false))
        .arg(Arg::with_name("no-gzip")
            .long("no-gzip")
            .help("Do not use gzip")
            .long_help("Disables the use of gzip when copying closures to the remote host.")
            .takes_value(false))
        .arg(Arg::with_name("force-replace-unknown-profiles")
            .long("force-replace-unknown-profiles")
            .help("Ignore all targeted nodes deployment.replaceUnknownProfiles setting")
            .long_help(r#"If `deployment.replaceUnknownProfiles` is set for a target, using this switch
will treat deployment.replaceUnknownProfiles as though it was set true and perform unknown profile replacement."#)
            .takes_value(false))
}

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("apply")
        .about("Apply configurations on remote machines")
        .arg(Arg::with_name("goal")
            .help("Deployment goal")
            .long_help("Same as the targets for switch-to-configuration.\n\"push\" means only copying the closures to remote nodes.")
            .default_value("switch")
            .index(1)
            .possible_values(&["build", "push", "switch", "boot", "test", "dry-activate", "keys"]))
    ;
    let command = register_deploy_args(command);

    util::register_selector_args(command)
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) {
    let hive = util::hive_from_args(local_args).unwrap();
    let hive_base = hive.as_path().parent().unwrap().to_owned();

    log::info!("Enumerating nodes...");
    let all_nodes = hive.deployment_info().await.unwrap();

    let nix_options = hive.nix_options().await.unwrap();

    let selected_nodes = match local_args.value_of("on") {
        Some(filter) => {
            util::filter_nodes(&all_nodes, filter)
        }
        None => all_nodes.keys().cloned().collect(),
    };

    if selected_nodes.len() == 0 {
        log::warn!("No hosts matched. Exiting...");
        quit::with_code(2);
    }

    let ssh_config = env::var("SSH_CONFIG_FILE")
        .ok().map(PathBuf::from);

    // FIXME: This is ugly :/ Make an enum wrapper for this fake "keys" goal
    let goal_arg = local_args.value_of("goal").unwrap();
    let goal = if goal_arg == "keys" {
        Goal::Build
    } else {
        Goal::from_str(goal_arg).unwrap()
    };

    let build_only = goal == Goal::Build && goal_arg != "keys";

    let mut targets = HashMap::new();
    for node in &selected_nodes {
        let config = all_nodes.get(node).unwrap();
        let host = config.to_ssh_host();
        match host {
            Some(mut host) => {
                if let Some(ssh_config) = ssh_config.as_ref() {
                    host.set_ssh_config(ssh_config.clone());
                }

                targets.insert(
                    node.clone(),
                    Target::new(host.upcast(), config.clone()),
                );
            }
            None => {
                if build_only {
                    targets.insert(
                        node.clone(),
                        Target::new(localhost(nix_options.clone()), config.clone()),
                    );
                }
            }
        }
    }

    if targets.len() == all_nodes.len() {
        log::info!("Selected all {} nodes.", targets.len());
    } else if targets.len() == selected_nodes.len() {
        log::info!("Selected {} out of {} hosts.", targets.len(), all_nodes.len());
    } else {
        log::info!("Selected {} out of {} hosts ({} skipped)", targets.len(), all_nodes.len(), selected_nodes.len() - targets.len());
    }

    if targets.len() == 0 {
        log::warn!("No selected nodes are accessible over SSH. Exiting...");
        quit::with_code(2);
    }

    let mut deployment = Deployment::new(hive, targets, goal);

    let mut options = DeploymentOptions::default();
    options.set_substituters_push(!local_args.is_present("no-substitutes"));
    options.set_gzip(!local_args.is_present("no-gzip"));
    options.set_progress_bar(!local_args.is_present("verbose"));
    options.set_upload_keys(!local_args.is_present("no-keys"));
    options.set_force_replace_unknown_profiles(local_args.is_present("force-replace-unknown-profiles"));

    if local_args.is_present("keep-result") {
        options.set_gc_roots(hive_base.join(".gcroots"));
    }

    deployment.set_options(options);

    if local_args.is_present("no-keys") && goal_arg == "keys" {
        log::error!("--no-keys cannot be used when the goal is to upload keys");
        quit::with_code(1);
    }

    let mut parallelism_limit = ParallelismLimit::default();
    parallelism_limit.set_apply_limit({
        let limit = local_args.value_of("parallel").unwrap().parse::<usize>().unwrap();
        if limit == 0 {
            selected_nodes.len() // HACK
        } else {
            local_args.value_of("parallel").unwrap().parse::<usize>().unwrap()
        }
    });
    deployment.set_parallelism_limit(parallelism_limit);

    let evaluation_node_limit = match local_args.value_of("eval-node-limit").unwrap() {
        "auto" => EvaluationNodeLimit::Heuristic,
        number => {
            let number = number.parse::<usize>().unwrap();
            if number == 0 {
                EvaluationNodeLimit::None
            } else {
                EvaluationNodeLimit::Manual(number)
            }
        }
    };
    deployment.set_evaluation_node_limit(evaluation_node_limit);

    let deployment = Arc::new(deployment);

    if goal_arg == "keys" {
        deployment.upload_keys().await;
    } else {
        deployment.execute().await;
    }
}
