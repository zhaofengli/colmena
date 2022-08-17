use clap::{ArgMatches, Command as ClapCommand};
use tokio::process::Command;

use crate::error::ColmenaError;
use crate::util;

pub fn subcommand() -> ClapCommand<'static> {
    ClapCommand::new("repl")
        .about("Start an interactive REPL with the complete configuration")
        .long_about(
            r#"Start an interactive REPL with the complete configuration

In the REPL, you can inspect the configuration interactively with tab
completion. The node configurations are accessible under the `nodes`
attribute set."#,
        )
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    let hive = util::hive_from_args(local_args).await?;

    let expr = hive.get_repl_expression();

    let status = Command::new("nix")
        .arg("repl")
        // `nix repl` is expected to be marked as experimental:
        // <https://github.com/NixOS/nix/issues/5604>
        .args(&["--experimental-features", "nix-command flakes"])
        .args(&["--expr", &expr])
        .status()
        .await?;

    if !status.success() {
        return Err(status.into());
    }

    Ok(())
}
