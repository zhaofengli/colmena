use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{value_parser, Arg, ArgMatches, Command as ClapCommand, FromArgMatches};
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::error::ColmenaError;
use crate::job::{JobMonitor, JobState, JobType};
use crate::nix::hive::HiveArgs;
use crate::nix::NodeFilter;
use crate::progress::SimpleProgressOutput;
use crate::util;

pub fn subcommand() -> ClapCommand {
    let command = ClapCommand::new("exec")
        .about("Run a command on remote machines")
        .arg(
            Arg::new("parallel")
                .short('p')
                .long("parallel")
                .value_name("LIMIT")
                .help("Deploy parallelism limit")
                .long_help(
                    r#"Limits the maximum number of hosts to run the command in parallel.

In `colmena exec`, the parallelism limit is disabled (0) by default.
"#,
                )
                .default_value("0")
                .num_args(1)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Be verbose")
                .long_help("Deactivates the progress spinner and prints every line of output.")
                .num_args(0),
        )
        .arg(
            Arg::new("command")
                .value_name("COMMAND")
                .trailing_var_arg(true)
                .help("Command")
                .required(true)
                .num_args(1..)
                .long_help(
                    r#"Command to run

It's recommended to use -- to separate Colmena options from the command to run. For example:

    colmena exec --on @routers -- tcpdump -vni any ip[9] == 89
"#,
                ),
        );

    util::register_selector_args(command)
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let hive = HiveArgs::from_arg_matches(local_args)
        .unwrap()
        .into_hive()
        .await
        .unwrap();
    let ssh_config = env::var("SSH_CONFIG_FILE").ok().map(PathBuf::from);

    // FIXME: Just get_one::<NodeFilter>
    let filter = local_args
        .get_one::<String>("on")
        .map(NodeFilter::new)
        .transpose()?;

    let mut targets = hive.select_nodes(filter, ssh_config, true).await?;

    let parallel_sp = Arc::new({
        let limit = local_args.get_one::<usize>("parallel").unwrap().to_owned();

        if limit > 0 {
            Some(Semaphore::new(limit))
        } else {
            None
        }
    });

    let command: Arc<Vec<String>> = Arc::new(
        local_args
            .get_many::<String>("command")
            .unwrap()
            .cloned()
            .collect(),
    );

    let mut output = SimpleProgressOutput::new(local_args.get_flag("verbose"));

    let (mut monitor, meta) = JobMonitor::new(output.get_sender());

    if let Some(width) = util::get_label_width(&targets) {
        monitor.set_label_width(width);
    }

    let meta = meta.run(|meta| async move {
        let mut futures = Vec::new();

        for (name, target) in targets.drain() {
            let parallel_sp = parallel_sp.clone();
            let command = command.clone();

            let mut host = target.into_host().unwrap();

            let job = meta.create_job(JobType::Execute, vec![name.clone()])?;

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

    meta?;
    monitor?;
    output?;

    Ok(())
}
