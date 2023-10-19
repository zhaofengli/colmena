use std::time::Duration;

use clap::{ArgMatches, Command as ClapCommand};
use tokio::time;

use crate::error::{ColmenaError, ColmenaResult};
use crate::job::{JobMonitor, JobType};
use crate::nix::NodeName;
use crate::progress::{spinner::SpinnerOutput, ProgressOutput};

macro_rules! node {
    ($n:expr) => {
        NodeName::new($n.to_string()).unwrap()
    };
}

pub fn subcommand() -> ClapCommand {
    ClapCommand::new("test-progress")
        .about("Run progress spinner tests")
        .hide(true)
}

pub async fn run(global_args: &ArgMatches, _local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let mut output = SpinnerOutput::new(!global_args.get_one("disable-emoji").unwrap_or(&false));
    let (monitor, meta) = JobMonitor::new(output.get_sender());

    let meta_future = meta.run(|meta| async move {
        meta.message("Message from meta job".to_string())?;

        let nodes = vec![
            node!("alpha"),
            node!("beta"),
            node!("gamma"),
            node!("delta"),
            node!("epsilon"),
        ];
        let eval = meta.create_job(JobType::Evaluate, nodes)?;
        let eval = eval.run(|job| async move {
            for i in 0..10 {
                job.message(format!("eval: {}", i))?;
                time::sleep(Duration::from_secs(1)).await;
            }

            Ok(())
        });

        let build = meta.create_job(JobType::Build, vec![node!("alpha"), node!("beta")])?;
        let build = build.run(|_| async move {
            time::sleep(Duration::from_secs(5)).await;

            Ok(())
        });

        let (_, _) = tokio::join!(eval, build);

        Err(ColmenaError::Unsupported) as ColmenaResult<()>
    });

    let (monitor, output, ret) = tokio::join!(
        monitor.run_until_completion(),
        output.run_until_completion(),
        meta_future,
    );

    monitor?;
    output?;

    println!("Return Value -> {:?}", ret);

    Ok(())
}
