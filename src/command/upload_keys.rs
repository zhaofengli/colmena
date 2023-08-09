use clap::{builder::PossibleValuesParser, Arg, Args, Command as ClapCommand};

use crate::util;

pub use super::apply::run;
use super::apply::DeployOpts;

pub fn subcommand() -> ClapCommand {
    let command = ClapCommand::new("upload-keys")
        .about("Upload keys to remote hosts")
        .long_about(
            r#"Upload keys to remote hosts

This subcommand behaves as if you invoked `apply` with the pseudo `keys` goal."#,
        )
        .arg(
            Arg::new("goal")
                .hide(true)
                .default_value("keys")
                .value_parser(PossibleValuesParser::new(["keys"]))
                .num_args(1),
        );

    util::register_selector_args(DeployOpts::augment_args_for_update(command))
}
