use std::io::Write;

use tempfile::Builder as TempFileBuilder;

use crate::error::ColmenaResult;
use crate::nix::{Hive, NixCommand};

pub async fn run(hive: Hive) -> ColmenaResult<()> {
    let mut flags = hive.nix_flags();

    // `nix repl --file` is incompatible with --pure-eval
    flags.set_pure_eval(false);

    let expr = hive.get_repl_expression();

    let mut expr_file = TempFileBuilder::new()
        .prefix("colmena-repl-")
        .suffix(".nix")
        .tempfile()?;

    expr_file.write_all(expr.as_bytes())?;

    let status = NixCommand::nix(flags)
        .arg("repl")
        .arg("--file")
        .arg(expr_file.path())
        .build()
        .status()
        .await?;

    if !status.success() {
        return Err(status.into());
    }

    Ok(())
}
