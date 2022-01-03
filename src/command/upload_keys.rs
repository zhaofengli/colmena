use clap::{Arg, App};

use crate::util;

use super::apply;
pub use super::apply::run;

pub fn subcommand() -> App<'static> {
    let command = App::new("upload-keys")
        .about("Upload keys to remote hosts")
        .long_about(r#"Upload keys to remote hosts

This subcommand behaves as if you invoked `apply` with the pseudo `keys` goal."#)
        .arg(Arg::new("goal")
            .hide(true)
            .default_value("keys")
            .possible_values(&["keys"])
            .takes_value(true));

    let command = apply::register_deploy_args(command);

    util::register_selector_args(command)
}
