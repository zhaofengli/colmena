use clap::{Arg, Command as ClapCommand};

use crate::util;

use super::apply;
pub use super::apply::run;

pub fn subcommand() -> ClapCommand<'static> {
    let command = ClapCommand::new("build")
        .about("Build configurations but not push to remote machines")
        .long_about(r#"Build configurations but not push to remote machines

This subcommand behaves as if you invoked `apply` with the `build` goal."#)
        .arg(Arg::new("goal")
            .hide(true)
            .default_value("build")
            .possible_values(&["build"])
            .takes_value(true));

    let command = apply::register_deploy_args(command);

    util::register_selector_args(command)
}
