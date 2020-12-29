use std::collections::HashMap;

use clap::{Arg, App};
use glob::Pattern as GlobPattern;

use super::nix::DeploymentConfig;

enum NodeFilter {
    NameFilter(GlobPattern),
    TagFilter(GlobPattern),
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

pub fn register_common_args<'a, 'b>(command: App<'a, 'b>) -> App<'a, 'b> {
    command
        .arg(Arg::with_name("config")
            .short("f")
            .long("config")
            .help("Path to a Hive expression")
            .default_value("hive.nix")
            .required(true))
        .arg(Arg::with_name("show-trace")
            .long("show-trace")
            .help("Show debug information for Nix commands")
            .long_help("Passes --show-trace to Nix commands")
            .takes_value(false))
}

pub fn register_selector_args<'a, 'b>(command: App<'a, 'b>) -> App<'a, 'b> {
    let command = register_common_args(command);

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
