use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{ArgMatches, Args, Command as ClapCommand, FromArgMatches};
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::error::ColmenaError;
use crate::job::{JobMonitor, JobState, JobType};
use crate::nix::hive::HiveArgs;
use crate::nix::node_filter::NodeFilterOpts;
use crate::progress::SimpleProgressOutput;
use crate::util;

#[derive(Debug, Args)]
#[command(name = "exec", about = "Run a command on remote machines")]
struct Opts {
    #[arg(
        short,
        long,
        default_value_t = 0,
        value_name = "LIMIT",
        help = "Deploy parallelism limit",
        long_help = r#"Limits the maximum number of hosts to run the command in parallel.

In `colmena exec`, the parallelism limit is disabled (0) by default.
"#
    )]
    parallel: usize,
    #[arg(
        short,
        long,
        help = "Be verbose",
        long_help = "Deactivates the progress spinner and prints every line of output."
    )]
    verbose: bool,
    #[command(flatten)]
    nodes: NodeFilterOpts,
    #[arg(
        trailing_var_arg = true,
        required = true,
        value_name = "COMMAND",
        help = "Command",
        long_help = r#"Command to run

It's recommended to use -- to separate Colmena options from the command to run. For example:

    colmena exec --on @routers -- tcpdump -vni any ip[9] == 89
"#
    )]
    command: Vec<String>,
}

pub fn subcommand() -> ClapCommand {
    Opts::augment_args(ClapCommand::new("exec"))
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let hive = HiveArgs::from_arg_matches(local_args)
        .unwrap()
        .into_hive()
        .await
        .unwrap();
    let ssh_config = env::var("SSH_CONFIG_FILE").ok().map(PathBuf::from);

    let Opts {
        parallel,
        verbose,
        nodes,
        command,
    } = Opts::from_arg_matches(local_args).unwrap();

    let mut targets = hive.select_nodes(nodes.on, ssh_config, true).await?;

    let parallel_sp = Arc::new(if parallel > 0 {
        Some(Semaphore::new(parallel))
    } else {
        None
    });

    let command = Arc::new(command);

    let mut output = SimpleProgressOutput::new(verbose);

    let (mut monitor, meta) = JobMonitor::new(output.get_sender());

    if let Some(width) = util::get_label_width(&targets) {
        monitor.set_label_width(width);
    }

    let meta = meta.run(|meta| async move {
        let mut futures = Vec::new();

        for (name, target) in targets.drain() {
            let parallel_sp = parallel_sp.clone();
            let command = Arc::clone(&command);

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
