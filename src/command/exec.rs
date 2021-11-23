use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Arg, App, AppSettings, SubCommand, ArgMatches};
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::nix::{NixError, NodeFilter};
use crate::job::{JobMonitor, JobState, JobType};
use crate::progress::SimpleProgressOutput;
use crate::util;

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

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) -> Result<(), NixError> {
    let hive = util::hive_from_args(local_args).await?;
    let ssh_config = env::var("SSH_CONFIG_FILE")
        .ok().map(PathBuf::from);

    let filter = local_args.value_of("on")
        .map(NodeFilter::new)
        .transpose()?;

    let mut targets = hive.select_nodes(filter, ssh_config, true).await?;

    let parallel_sp = Arc::new({
        let limit = local_args.value_of("parallel").unwrap()
            .parse::<usize>().unwrap();

        if limit > 0 {
            Some(Semaphore::new(limit))
        } else {
            None
        }
    });

    let command: Arc<Vec<String>> = Arc::new(local_args.values_of("command").unwrap().map(|s| s.to_string()).collect());

    let mut output = SimpleProgressOutput::new(local_args.is_present("verbose"));

    let (monitor, meta) = JobMonitor::new(output.get_sender());
    let meta = meta.run(|meta| async move {
        let mut futures = Vec::new();

        for (name, target) in targets.drain() {
            let parallel_sp = parallel_sp.clone();
            let command = command.clone();

            let mut host = target.into_host().unwrap();

            let job = meta.create_job(JobType::Execute, vec![ name.clone() ])?;

            futures.push(job.run_waiting(|job| async move {
                let permit = match parallel_sp.as_ref() {
                    Some(sp) => Some(sp.acquire().await.unwrap()),
                    None => None,
                };

                job.state(JobState::Running)?;

                let command_v: Vec<&str> = command.iter().map(|s| s.as_str()).collect();
                host.set_job(Some(job));
                host.run_command(&command_v).await?;

                drop(permit);

                Ok(())
            }));
        }

        join_all(futures).await;

        Ok(())
    });

    let (meta, monitor, output) = tokio::join!(
        meta,
        monitor.run_until_completion(),
        output.run_until_completion(),
    );

    meta?; monitor?; output?;

    Ok(())
}
