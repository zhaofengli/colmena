use clap::{Args, Command as ClapCommand};

use crate::{nix::Goal, util};

pub use super::apply::run;
use super::apply::DeployOpts;

#[derive(Debug, Args)]
#[command(
    name = "upload-keys",
    about = "Upload keys to remote hosts",
    long_about = r#"Upload keys to remote hosts

This subcommand behaves as if you invoked `apply` with the pseudo `keys` goal."#
)]
pub struct Opts {
    #[command(flatten)]
    deploy: DeployOpts,
    #[arg(hide = true, default_value_t = Goal::Build)]
    goal: Goal,
}

pub fn subcommand() -> ClapCommand {
    Opts::augment_args(ClapCommand::new("upload-keys"))
}
