use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Arg, ArgMatches, Command as ClapCommand};
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::error::ColmenaError;
use crate::job::{JobMonitor, JobState, JobType};
use crate::nix::NodeFilter;
use crate::progress::SimpleProgressOutput;
use crate::util;

pub fn subcommand() -> ClapCommand<'static> {
    let command = ClapCommand::new("reboot")
        .about("Reboot remote machines")
        .trailing_var_arg(true)
        .arg(
            Arg::new("parallel")
                .short('p')
                .long("parallel")
                .value_name("LIMIT")
                .help("Deploy parallelism limit")
                .long_help(
                    r#"Limits the maximum number of hosts to reboot in parallel.

In `colmena reboot`, the parallelism limit is disabled (0) by default.
"#,
                )
                .default_value("0")
                .takes_value(true)
                .validator(|s| match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value must be a valid number")),
                }),
        );

    util::register_selector_args(command)
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let hive = util::hive_from_args(local_args).await?;
    let ssh_config = env::var("SSH_CONFIG_FILE").ok().map(PathBuf::from);

    let filter = local_args.value_of("on").map(NodeFilter::new).transpose()?;

    let mut targets = hive.select_nodes(filter, ssh_config, true).await?;

    let parallel_sp = Arc::new({
        let limit = local_args
            .value_of("parallel")
            .unwrap()
            .parse::<usize>()
            .unwrap();

        if limit > 0 {
            Some(Semaphore::new(limit))
        } else {
            None
        }
    });

    let mut output = SimpleProgressOutput::new(false);

    let (monitor, meta) = JobMonitor::new(output.get_sender());
    let meta = meta.run(|meta| async move {
        let mut futures = Vec::new();

        for (name, target) in targets.drain() {
            let parallel_sp = parallel_sp.clone();

            let mut host = target.into_host().unwrap();

            let job = meta.create_job(JobType::Execute, vec![name.clone()])?;

            futures.push(job.run_waiting(|job| async move {
                let permit = match parallel_sp.as_ref() {
                    Some(sp) => Some(sp.acquire().await.unwrap()),
                    None => None,
                };

                job.state(JobState::Running)?;

                host.set_job(Some(job));
                host.run_command(&["reboot"]).await?;

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
