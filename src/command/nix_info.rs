use clap::{ArgMatches, Args, Command, FromArgMatches};

use crate::error::ColmenaError;
use crate::nix::evaluator::nix_eval_jobs::get_pinned_nix_eval_jobs;
use crate::nix::NixCheck;

#[derive(Debug, Args)]
#[command(
    name = "nix-info",
    about = "Show information about the current Nix installation"
)]
pub struct Opts {}

pub fn subcommand() -> Command {
    Opts::augment_args(Command::new("nix-info"))
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let Opts {} = Opts::from_arg_matches(local_args).unwrap();
    let check = NixCheck::detect().await;
    check.print_version_info();
    check.print_flakes_info(false);

    if let Some(pinned) = get_pinned_nix_eval_jobs() {
        log::info!("Using pinned nix-eval-jobs: {}", pinned);
    } else {
        log::info!("Using nix-eval-jobs from PATH");
    }

    Ok(())
}
