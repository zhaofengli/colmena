use std::time::Duration;

use clap::{App, AppSettings, SubCommand, ArgMatches};
use tokio::time;

use crate::nix::NixError;
use crate::progress::{Progress, OutputStyle};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("test-progress")
        .about("Run progress spinner tests")
        .setting(AppSettings::Hidden)
}

pub async fn run(_global_args: &ArgMatches<'_>, _local_args: &ArgMatches<'_>) -> Result<(), NixError> {
    let progress = Progress::with_style(OutputStyle::Condensed);
    let mut task = progress.create_task_progress(String::from("test"));

    for i in 0..10 {
        time::sleep(Duration::from_secs(2)).await;
        task.log(&format!("Very slow counter: {}", i));
    }

    task.success("Completed");

    Ok(())
}
