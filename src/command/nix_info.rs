use clap::{App, ArgMatches};

use crate::nix::{NixCheck, NixError};

pub fn subcommand() -> App<'static> {
    App::new("nix-info")
        .about("Show information about the current Nix installation")
}

pub async fn run(_global_args: &ArgMatches, _local_args: &ArgMatches) -> Result<(), NixError> {
    let check = NixCheck::detect().await;
    check.print_version_info();
    check.print_flakes_info(false);

    Ok(())
}
