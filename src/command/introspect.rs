use std::path::PathBuf;

use clap::{Arg, App, SubCommand, ArgMatches};

use crate::nix::Hive;

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("introspect")
        .about("Evaluate expressions using the complete configuration.")
        .long_about(r#"Your expression should take an attribute set with keys `pkgs`, `lib` and `nodes` (like a NixOS module) and return a JSON-serializable value.

For example, to retrieve the configuration of one node, you may write something like:

    { nodes, ... }: nodes.node-a.config.networking.hostName
"#)
        .arg(Arg::with_name("expression_file")
            .index(1)
            .help("The .nix file containing the expression")
            .takes_value(true))
        .arg(Arg::with_name("expression")
            .short("E")
            .help("The Nix expression")
            .takes_value(true))
        .arg(Arg::with_name("config")
            .short("f")
            .long("config")
            .help("Path to a Hive expression")
            .default_value("hive.nix")
            .required(true))
        ;

    command
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) {
    let mut hive = Hive::from_config_arg(local_args).unwrap();

    if !(local_args.is_present("expression") ^ local_args.is_present("expression_file")) {
        eprintln!("Either an expression (-E) xor a .nix file containing an expression should be specified, not both.");
        quit::with_code(1);
    }

    let expression = if local_args.is_present("expression") {
        local_args.value_of("expression").unwrap().to_string()
    } else {
        let path: PathBuf = local_args.value_of("expression_file").unwrap().into();
        format!("import {}", path.canonicalize().expect("Could not generate absolute path to expression file.").to_str().unwrap())
    };

    let result = hive.introspect(expression).await.unwrap();
    println!("{}", result);
}
