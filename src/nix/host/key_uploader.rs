//! Utilities for using the key uploader script.
//!
//! The key uploader is a simple shell script that reads the contents
//! of the secret file from stdin into a temporary file then atomically
//! replaces the destination file with the temporary file.

use std::borrow::Cow;
use std::path::Path;

use futures::future::join3;
use shell_escape::unix::escape;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Child;

use crate::nix::{Key, NixResult};
use crate::progress::TaskProgress;
use crate::util::capture_stream;

const SCRIPT_TEMPLATE: &'static str = include_str!("./key_uploader.template.sh");

pub fn generate_script<'a>(key: &'a Key, destination: &'a Path) -> Cow<'a, str> {
    let key_script = SCRIPT_TEMPLATE.to_string()
        .replace("%DESTINATION%", destination.to_str().unwrap())
        .replace("%USER%", &escape(key.user().into()))
        .replace("%GROUP%", &escape(key.group().into()))
        .replace("%PERMISSIONS%", &escape(key.permissions().into()))
        .trim_end_matches('\n').to_string();

    escape(key_script.into())
}

pub async fn feed_uploader(mut uploader: Child, key: &Key, progress: TaskProgress, logs: &mut String) -> NixResult<()> {
    let mut reader = key.reader().await?;
    let mut stdin = uploader.stdin.take().unwrap();

    tokio::io::copy(reader.as_mut(), &mut stdin).await?;
    stdin.flush().await?;
    drop(stdin);

    let stdout = BufReader::new(uploader.stdout.take().unwrap());
    let stderr = BufReader::new(uploader.stderr.take().unwrap());

    let futures = join3(
        capture_stream(stdout, progress.clone()),
        capture_stream(stderr, progress.clone()),
        uploader.wait(),
    );
    let (stdout_str, stderr_str, exit) = futures.await;
    logs.push_str(&stdout_str);
    logs.push_str(&stderr_str);

    let exit = exit?;

    if exit.success() {
        Ok(())
    } else {
        Err(exit.into())
    }
}
