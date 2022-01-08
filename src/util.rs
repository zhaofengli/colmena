use std::convert::TryFrom;
use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use clap::{App, Arg, ArgMatches};
use futures::future::join3;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::nix::{Flake, Hive, HivePath, NixResult, NixError, StorePath};
use super::nix::deployment::TargetNodeMap;
use super::job::JobHandle;

/// Non-interactive execution of an arbitrary command.
pub struct CommandExecution {
    command: Command,
    job: Option<JobHandle>,
    hide_stdout: bool,
    stdout: Option<String>,
    stderr: Option<String>,
}

/// Helper extensions for Commands.
#[async_trait]
pub trait CommandExt {
    /// Runs the command with stdout and stderr passed through to the user.
    async fn passthrough(&mut self) -> NixResult<()>;

    /// Runs the command, capturing the output as a String.
    async fn capture_output(&mut self) -> NixResult<String>;

    /// Runs the command, capturing deserialized output from JSON.
    async fn capture_json<T>(&mut self) -> NixResult<T> where T: DeserializeOwned;

    /// Runs the command, capturing a single store path.
    async fn capture_store_path(&mut self) -> NixResult<StorePath>;
}

impl CommandExecution {
    pub fn new(command: Command) -> Self {
        Self {
            command,
            job: None,
            hide_stdout: false,
            stdout: None,
            stderr: None,
        }
    }

    /// Sets the job associated with this execution.
    pub fn set_job(&mut self, job: Option<JobHandle>) {
        self.job = job;
    }

    /// Sets whether to hide stdout.
    pub fn set_hide_stdout(&mut self, hide_stdout: bool) {
        self.hide_stdout = hide_stdout;
    }

    /// Returns logs from the last invocation.
    pub fn get_logs(&self) -> (Option<&String>, Option<&String>) {
        (self.stdout.as_ref(), self.stderr.as_ref())
    }

    /// Runs the command.
    pub async fn run(&mut self) -> NixResult<()> {
        self.command.stdin(Stdio::null());
        self.command.stdout(Stdio::piped());
        self.command.stderr(Stdio::piped());

        self.stdout = Some(String::new());
        self.stderr = Some(String::new());

        let mut child = self.command.spawn()?;

        let stdout = BufReader::new(child.stdout.take().unwrap());
        let stderr = BufReader::new(child.stderr.take().unwrap());

        let stdout_job = if self.hide_stdout { None } else { self.job.clone() };

        let futures = join3(
            capture_stream(stdout, stdout_job, false),
            capture_stream(stderr, self.job.clone(), true),
            child.wait(),
        );

        let (stdout, stderr, wait) = futures.await;
        self.stdout = Some(stdout?);
        self.stderr = Some(stderr?);

        let exit = wait?;

        if exit.success() {
            Ok(())
        } else {
            Err(exit.into())
        }
    }
}

#[async_trait]
impl CommandExt for Command {
    /// Runs the command with stdout and stderr passed through to the user.
    async fn passthrough(&mut self) -> NixResult<()> {
        let exit = self
            .spawn()?
            .wait()
            .await?;

        if exit.success() {
            Ok(())
        } else {
            Err(exit.into())
        }
    }

    /// Captures output as a String.
    async fn capture_output(&mut self) -> NixResult<String> {
        // We want the user to see the raw errors
        let output = self
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?
            .wait_with_output()
            .await?;

        if output.status.success() {
            // FIXME: unwrap
            Ok(String::from_utf8(output.stdout).unwrap())
        } else {
            Err(output.status.into())
        }
    }

    /// Captures deserialized output from JSON.
    async fn capture_json<T>(&mut self) -> NixResult<T> where T: DeserializeOwned {
        let output = self.capture_output().await?;
        serde_json::from_str(&output).map_err(|_| NixError::BadOutput {
            output: output.clone()
        })
    }

    /// Captures a single store path.
    async fn capture_store_path(&mut self) -> NixResult<StorePath> {
        let output = self.capture_output().await?;
        let path = output.trim_end().to_owned();
        StorePath::try_from(path)
    }
}

#[async_trait]
impl CommandExt for CommandExecution {
    async fn passthrough(&mut self) -> NixResult<()> {
        self.run().await
    }

    /// Captures output as a String.
    async fn capture_output(&mut self) -> NixResult<String> {
        self.run().await?;
        let (stdout, _) = self.get_logs();

        Ok(stdout.unwrap().to_owned())
    }

    /// Captures deserialized output from JSON.
    async fn capture_json<T>(&mut self) -> NixResult<T> where T: DeserializeOwned {
        let output = self.capture_output().await?;
        serde_json::from_str(&output).map_err(|_| NixError::BadOutput {
            output: output.clone()
        })
    }

    /// Captures a single store path.
    async fn capture_store_path(&mut self) -> NixResult<StorePath> {
        let output = self.capture_output().await?;
        let path = output.trim_end().to_owned();
        StorePath::try_from(path)
    }
}

pub async fn hive_from_args(args: &ArgMatches) -> NixResult<Hive> {
    let path = match args.occurrences_of("config") {
        0 => {
            // traverse upwards until we find hive.nix
            let mut cur = std::env::current_dir()?;
            let mut file_path = None;

            loop {
                let flake = cur.join("flake.nix");
                if flake.is_file() {
                    file_path = Some(flake);
                    break;
                }

                let legacy = cur.join("hive.nix");
                if legacy.is_file() {
                    file_path = Some(legacy);
                    break;
                }

                match cur.parent() {
                    Some(parent) => {
                        cur = parent.to_owned();
                    }
                    None => {
                        break;
                    }
                }
            }

            if file_path.is_none() {
                log::error!("Could not find `hive.nix` or `flake.nix` in {:?} or any parent directory", std::env::current_dir()?);
            }

            file_path.unwrap()
        }
        _ => {
            let path = args.value_of("config").expect("The config arg should exist").to_owned();
            let fpath = canonicalize_cli_path(&path);

            if !fpath.exists() && path.contains(':') {
                // Treat as flake URI
                let flake = Flake::from_uri(path).await?;
                let hive_path = HivePath::Flake(flake);
                let mut hive = Hive::new(hive_path)?;

                if args.is_present("show-trace") {
                    hive.set_show_trace(true);
                }

                return Ok(hive);
            }

            fpath
        }
    };

    let hive_path = HivePath::from_path(path).await?;
    match &hive_path {
        HivePath::Legacy(p) => {
            log::info!("Using configuration: {}", p.to_string_lossy());
        }
        HivePath::Flake(flake) => {
            log::info!("Using flake: {}", flake.uri());
        }
    }

    let mut hive = Hive::new(hive_path)?;

    if args.is_present("show-trace") {
        hive.set_show_trace(true);
    }

    Ok(hive)
}

pub fn register_selector_args(command: App) -> App {
    command
        .arg(Arg::new("on")
            .long("on")
            .value_name("NODES")
            .help("Node selector")
            .long_help(r#"Select a list of nodes to deploy to.

The list is comma-separated and globs are supported. To match tags, prepend the filter by @. Valid examples:

- host1,host2,host3
- edge-*
- edge-*,core-*
- @a-tag,@tags-can-have-*"#)
            .takes_value(true))
}

fn canonicalize_cli_path(path: &str) -> PathBuf {
    if !path.starts_with('/') {
        format!("./{}", path).into()
    } else {
        path.into()
    }
}

pub async fn capture_stream<R>(mut stream: BufReader<R>, job: Option<JobHandle>, stderr: bool) -> NixResult<String>
    where R: AsyncRead + Unpin
{
    let mut log = String::new();

    loop {
        let mut line = String::new();
        let len = stream.read_line(&mut line).await?;

        if len == 0 {
            break;
        }

        let trimmed = line.trim_end();

        if let Some(job) = &job {
            if stderr {
                job.stderr(trimmed.to_string())?;
            } else {
                job.stdout(trimmed.to_string())?;
            }
        }

        log += trimmed;
        log += "\n";
    }

    Ok(log)
}

pub fn get_label_width(targets: &TargetNodeMap) -> Option<usize> {
    targets.keys().map(|n| n.len()).max()
}
