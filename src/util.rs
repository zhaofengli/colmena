use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;

use clap::{App, Arg, ArgMatches};
use glob::Pattern as GlobPattern;

use super::nix::{DeploymentConfig, Hive, NixResult};

enum NodeFilter {
    NameFilter(GlobPattern),
    TagFilter(GlobPattern),
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

pub fn filter_nodes(nodes: &HashMap<String, DeploymentConfig>, filter: &str) -> Vec<String> {
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
            .help("Select a list of machines")
            .long_help(r#"The list is comma-separated and globs are supported. To match tags, prepend the filter by @.
Valid examples:

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
