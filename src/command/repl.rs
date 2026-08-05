use std::io::Write;

use tempfile::Builder as TempFileBuilder;
use tokio::process::Command;

use crate::error::ColmenaResult;
use crate::nix::Hive;

pub async fn run(hive: Hive) -> ColmenaResult<()> {
    let expr = hive.get_repl_expression();

    let mut expr_file = TempFileBuilder::new()
        .prefix("colmena-repl-")
        .suffix(".nix")
        .tempfile()?;

    expr_file.write_all(expr.as_bytes())?;

    let mut repl_cmd = Command::new("nix");

    repl_cmd.arg("repl");

    // `nix repl` is expected to be marked as experimental:
    // <https://github.com/NixOS/nix/issues/5604>
    repl_cmd.args(["--experimental-features", "nix-command flakes"]);
    repl_cmd.arg("--file");

    let status = repl_cmd.arg(expr_file.path()).status().await?;

    if !status.success() {
        return Err(status.into());
    }

    Ok(())
}
