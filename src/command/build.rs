use clap::Args;

use crate::nix::Goal;

pub use super::apply::run;
use super::apply::DeployOpts;

#[derive(Debug, Args)]
#[command(
    name = "build",
    about = "Build configurations but not push to remote machines",
    long_about = r#"Build configurations but not push to remote machines

This subcommand behaves as if you invoked `apply` with the `build` goal."#
)]
pub struct Opts {
    #[command(flatten)]
    deploy: DeployOpts,
    #[arg(hide = true, default_value_t = Goal::Build)]
    goal: Goal,
}
