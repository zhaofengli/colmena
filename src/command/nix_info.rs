use clap::{App, SubCommand, ArgMatches};

use crate::nix::{NixCheck, NixError};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("nix-info")
        .about("Show information about the current Nix installation")
}

pub async fn run(_global_args: &ArgMatches<'_>, _local_args: &ArgMatches<'_>) -> Result<(), NixError> {
    let check = NixCheck::detect().await;
    check.print_version_info();
    check.print_flakes_info(false);

    Ok(())
}
