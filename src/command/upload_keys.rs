use clap::{Arg, App, SubCommand};

use crate::util;

use super::apply;
pub use super::apply::run;

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("upload-keys")
        .about("Upload keys to remote hosts")
        .long_about(r#"Upload keys to remote hosts

This subcommand behaves as if you invoked `apply` with the pseudo `keys` goal."#)
        .arg(Arg::with_name("goal")
            .hidden(true)
            .default_value("keys")
            .possible_values(&["keys"])
            .takes_value(true));

    let command = apply::register_deploy_args(command);

    util::register_selector_args(command)
}
