use clap::{Arg, App};
use glob::Pattern as GlobPattern;

pub fn filter_nodes(nodes: &Vec<String>, filter: &str) -> Vec<String> {
    let filters: Vec<GlobPattern> = filter.split(",").map(|pattern| GlobPattern::new(pattern).unwrap()).collect();

    if filters.len() > 0 {
        nodes.iter().filter(|name| {
            for filter in filters.iter() {
                if filter.matches(name) {
                    return true;
                }
            }

            false
        }).cloned().collect()
    } else {
        nodes.to_owned()
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
        .arg(Arg::with_name("on")
            .long("on")
            .help("Select a list of machines")
            .long_help(r#"The list is comma-separated and globs are supported.
Valid examples:

- host1,host2,host3
- edge-*
- edge-*,core-*"#)
            .takes_value(true))
}
