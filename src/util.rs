use std::path::PathBuf;
use std::process::Stdio;

use clap::{App, Arg, ArgMatches};
use futures::future::join3;
use tokio::io::{AsyncRead, AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::nix::{Flake, Hive, HivePath, NixResult};
use super::nix::deployment::TargetNodeMap;
use super::job::JobHandle;

/// Non-interactive execution of an arbitrary command.
pub struct CommandExecution {
    command: Command,
    job: Option<JobHandle>,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl CommandExecution {
    pub fn new(command: Command) -> Self {
        Self {
            command,
            job: None,
            stdout: None,
            stderr: None,
        }
    }

    /// Sets the job associated with this execution.
    pub fn set_job(&mut self, job: Option<JobHandle>) {
        self.job = job;
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

        let futures = join3(
            capture_stream(stdout, self.job.clone(), false),
            capture_stream(stderr, self.job.clone(), true),
            child.wait(),
        );

        let (stdout_str, stderr_str, wait) = futures.await;
        self.stdout = Some(stdout_str);
        self.stderr = Some(stderr_str);

        let exit = wait?;

        if exit.success() {
            Ok(())
        } else {
            Err(exit.into())
        }
    }
}

pub async fn hive_from_args(args: &ArgMatches<'_>) -> NixResult<Hive> {
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
    let mut hive = Hive::new(hive_path)?;

    if args.is_present("show-trace") {
        hive.set_show_trace(true);
    }

    Ok(hive)
}

pub fn register_selector_args<'a, 'b>(command: App<'a, 'b>) -> App<'a, 'b> {
    command
        .arg(Arg::with_name("on")
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

pub async fn capture_stream<R: AsyncRead + Unpin>(mut stream: BufReader<R>, job: Option<JobHandle>, stderr: bool) -> String {
    let mut log = String::new();

    loop {
        let mut line = String::new();
        let len = stream.read_line(&mut line).await.unwrap();

        if len == 0 {
            break;
        }

        let trimmed = line.trim_end();

        if let Some(job) = &job {
            if stderr {
                job.stderr(trimmed.to_string()).unwrap();
            } else {
                job.stdout(trimmed.to_string()).unwrap();
            }
        }

        log += trimmed;
        log += "\n";
    }

    log
}

pub fn get_label_width(targets: &TargetNodeMap) -> Option<usize> {
    targets.keys().map(|n| n.len()).max()
}
