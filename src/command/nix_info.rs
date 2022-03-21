use clap::{ArgMatches, Command as ClapCommand};

use crate::error::ColmenaError;
use crate::nix::evaluator::nix_eval_jobs::get_pinned_nix_eval_jobs;
use crate::nix::NixCheck;

pub fn subcommand() -> ClapCommand<'static> {
    ClapCommand::new("nix-info").about("Show information about the current Nix installation")
}

pub async fn run(_global_args: &ArgMatches, _local_args: &ArgMatches) -> Result<(), ColmenaError> {
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
