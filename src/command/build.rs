use clap::{Arg, App, SubCommand};

use crate::util;

use super::apply;
pub use super::apply::run;

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("build")
        .about("Build the configuration but not push to remote machines")
        .long_about(r#"Build the configuration but not push to remote machines

This subcommand behaves as if you invoked `apply` with the `build` goal."#)
        .arg(Arg::with_name("goal")
            .hidden(true)
            .default_value("build")
            .possible_values(&["build"])
            .takes_value(true));

    let command = apply::register_deploy_args(command);

    util::register_selector_args(command)
}
