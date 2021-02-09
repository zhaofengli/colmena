use std::collections::HashMap;
use std::convert::AsRef;
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;

use clap::{App, Arg, ArgMatches};
use console::style;
use futures::future::join3;
use glob::Pattern as GlobPattern;
use indicatif::ProgressBar;
use tokio::io::{AsyncRead, AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::nix::{NodeConfig, Hive, NixResult, NixError};

enum NodeFilter {
    NameFilter(GlobPattern),
    TagFilter(GlobPattern),
}

/// Non-interactive execution of an arbitrary Nix command.
pub struct CommandExecution {
    label: String,
    command: Command,
    progress_bar: Option<ProgressBar>,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl CommandExecution {
    pub fn new<S: AsRef<str>>(label: S, command: Command) -> Self {
        Self {
            label: label.as_ref().to_string(),
            command,
            progress_bar: None,
            stdout: None,
            stderr: None,
        }
    }

    /// Provides a ProgressBar to use to display output.
    pub fn set_progress_bar(&mut self, bar: ProgressBar) {
        self.progress_bar = Some(bar);
    }

    /// Retrieve logs from the last invocation.
    pub fn get_logs(&self) -> (Option<&String>, Option<&String>) {
        (self.stdout.as_ref(), self.stderr.as_ref())
    }

    /// Run the command.
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
            capture_stream(stdout, &self.label, self.progress_bar.clone()),
            capture_stream(stderr, &self.label, self.progress_bar.clone()),
            child.wait(),
        );

        let (stdout_str, stderr_str, wait) = futures.await;
        self.stdout = Some(stdout_str);
        self.stderr = Some(stderr_str);

        let exit = wait?;

        if exit.success() {
            Ok(())
        } else {
            Err(NixError::NixFailure { exit_code: exit.code().unwrap() })
        }
    }
}


pub fn hive_from_args(args: &ArgMatches<'_>) -> NixResult<Hive> {
    let path = match args.occurrences_of("config") {
        0 => {
            // traverse upwards until we find hive.nix
            let mut cur = std::env::current_dir()?;
            let mut hive_path = None;

            loop {
                let mut listing = match fs::read_dir(&cur) {
                    Ok(listing) => listing,
                    Err(e) => {
                        // This can very likely fail in shared environments
                        // where users aren't able to list /home. It's not
                        // unexpected.
                        //
                        // It may not be immediately obvious to the user that
                        // we are traversing upwards to find hive.nix.
                        log::warn!("Could not traverse up ({:?}) to find hive.nix: {}", cur, e);
                        break;
                    },
                };

                let found = listing.find_map(|rdirent| {
                    match rdirent {
                        Err(e) => Some(Err(e)),
                        Ok(f) => {
                            if f.file_name() == "hive.nix" {
                                Some(Ok(f))
                            } else {
                                None
                            }
                        }
                    }
                });

                if let Some(rdirent) = found {
                    let dirent = rdirent?;
                    hive_path = Some(dirent.path());
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

            if hive_path.is_none() {
                log::error!("Could not find `hive.nix` in {:?} or any parent directory", std::env::current_dir()?);
            }

            hive_path.unwrap()
        }
        _ => {
            let path = args.value_of("config").expect("The config arg should exist").to_owned();
            canonicalize_cli_path(path)
        }
    };

    let mut hive = Hive::new(path)?;

    if args.is_present("show-trace") {
        hive.show_trace(true);
    }

    Ok(hive)
}

pub fn filter_nodes(nodes: &HashMap<String, NodeConfig>, filter: &str) -> Vec<String> {
    let filters: Vec<NodeFilter> = filter.split(",").map(|pattern| {
        use NodeFilter::*;
        if let Some(tag_pattern) = pattern.strip_prefix("@") {
            TagFilter(GlobPattern::new(tag_pattern).unwrap())
        } else {
            NameFilter(GlobPattern::new(pattern).unwrap())
        }
    }).collect();

    if filters.len() > 0 {
        nodes.iter().filter_map(|(name, node)| {
            for filter in filters.iter() {
                use NodeFilter::*;
                match filter {
                    TagFilter(pat) => {
                        // Welp
                        for tag in node.tags() {
                            if pat.matches(tag) {
                                return Some(name);
                            }
                        }
                    }
                    NameFilter(pat) => {
                        if pat.matches(name) {
                            return Some(name)
                        }
                    }
                }
            }

            None
        }).cloned().collect()
    } else {
        nodes.keys().cloned().collect()
    }
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

fn canonicalize_cli_path(path: String) -> PathBuf {
    if !path.starts_with("/") {
        format!("./{}", path).into()
    } else {
        path.into()
    }
}

pub async fn capture_stream<R: AsyncRead + Unpin>(mut stream: BufReader<R>, label: &str, mut progress_bar: Option<ProgressBar>) -> String {
    let mut log = String::new();

    loop {
        let mut line = String::new();
        let len = stream.read_line(&mut line).await.unwrap();

        if len == 0 {
            break;
        }

        let trimmed = line.trim_end();
        if let Some(progress_bar) = progress_bar.as_mut() {
            progress_bar.set_message(trimmed);
        } else {
            eprintln!("{} | {}", style(label).cyan(), trimmed);
        }

        log += trimmed;
        log += "\n";
    }

    log
}
