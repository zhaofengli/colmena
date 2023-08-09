use clap::{builder::PossibleValuesParser, Arg, Args, Command as ClapCommand};

use crate::util;

pub use super::apply::run;
use super::apply::DeployOpts;

pub fn subcommand() -> ClapCommand {
    let command = ClapCommand::new("build")
        .about("Build configurations but not push to remote machines")
        .long_about(
            r#"Build configurations but not push to remote machines

This subcommand behaves as if you invoked `apply` with the `build` goal."#,
        )
        .arg(
            Arg::new("goal")
                .hide(true)
                .default_value("build")
                .value_parser(PossibleValuesParser::new(["build"]))
                .num_args(1),
        );

    util::register_selector_args(DeployOpts::augment_args_for_update(command))
}
