use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Arg, App, AppSettings, SubCommand, ArgMatches};
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::nix::NixError;
use crate::progress::{Progress, OutputStyle};
use crate::util::{self, CommandExecution};

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("exec")
        .about("Run a command on remote machines")
        .setting(AppSettings::TrailingVarArg)
        .arg(Arg::with_name("parallel")
            .short("p")
            .long("parallel")
            .value_name("LIMIT")
            .help("Deploy parallelism limit")
            .long_help(r#"Limits the maximum number of hosts to run the command in parallel.

In `colmena exec`, the parallelism limit is disabled (0) by default.
"#)
            .default_value("0")
            .takes_value(true)
            .validator(|s| {
                match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value must be a valid number")),
                }
            }))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .takes_value(false))
        .arg(Arg::with_name("command")
            .value_name("COMMAND")
            .last(true)
            .help("Command")
            .required(true)
            .multiple(true)
            .long_help(r#"Command to run

It's recommended to use -- to separate Colmena options from the command to run. For example:

    colmena exec --on @routers -- tcpdump -vni any ip[9] == 89
"#));

    util::register_selector_args(command)
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) {
    let hive = util::hive_from_args(local_args).await.unwrap();

    log::info!("Enumerating nodes...");
    let all_nodes = hive.deployment_info().await.unwrap();

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

    let mut hosts = HashMap::new();
    for node in &selected_nodes {
        let config = all_nodes.get(node).unwrap();
        let host = config.to_ssh_host();
        match host {
            Some(mut host) => {
                if let Some(ssh_config) = ssh_config.as_ref() {
                    host.set_ssh_config(ssh_config.clone());
                }

                hosts.insert(node.clone(), host);
            }
            None => {},
        }
    }

    if hosts.len() == all_nodes.len() {
        log::info!("Selected all {} nodes.", hosts.len());
    } else if hosts.len() == selected_nodes.len() {
        log::info!("Selected {} out of {} hosts.", hosts.len(), all_nodes.len());
    } else {
        log::info!("Selected {} out of {} hosts ({} skipped)", hosts.len(), all_nodes.len(), selected_nodes.len() - hosts.len());
    }

    if hosts.len() == 0 {
        log::warn!("No selected nodes are accessible over SSH. Exiting...");
        quit::with_code(2);
    }

    let mut progress = if local_args.is_present("verbose") {
        Progress::with_style(OutputStyle::Plain)
    } else {
        Progress::default()
    };

    let parallel_sp = Arc::new({
        let limit = local_args.value_of("parallel").unwrap()
            .parse::<usize>().unwrap();

        if limit > 0 {
            Some(Semaphore::new(limit))
        } else {
            None
        }
    });

    let label_width = hosts.keys().map(|n| n.len()).max().unwrap();
    progress.set_label_width(label_width);

    let progress = Arc::new(progress);
    let command: Arc<Vec<String>> = Arc::new(local_args.values_of("command").unwrap().map(|s| s.to_string()).collect());

    progress.run(|progress| async move {
        let mut futures = Vec::new();

        for (name, host) in hosts.drain() {
            let parallel_sp = parallel_sp.clone();
            let command = command.clone();
            let progress = progress.clone();

            futures.push(async move {
                let permit = match parallel_sp.as_ref() {
                    Some(sp) => Some(sp.acquire().await.unwrap()),
                    None => None,
                };

                let progress = progress.create_task_progress(name.clone());

                let command_v: Vec<&str> = command.iter().map(|s| s.as_str()).collect();
                let command = host.ssh(&command_v);
                let mut execution = CommandExecution::new(command);
                execution.set_progress_bar(progress.clone());

                match execution.run().await {
                    Ok(()) => {
                        progress.success("Exited");
                    }
                    Err(e) => {
                        if let NixError::NixFailure { exit_code } = e {
                            progress.failure(&format!("Exited with code {}", exit_code));
                        } else {
                            progress.failure(&format!("Error during execution: {}", e));
                        }
                    }
                }

                drop(permit);
            });
        }

        join_all(futures).await;
    }).await;
}
