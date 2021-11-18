use std::path::PathBuf;

use clap::{Arg, App, AppSettings, SubCommand, ArgMatches};

use crate::util;
use crate::nix::NixError;

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("eval")
        .about("Evaluate expressions using the complete configuration")
        .long_about(r#"Evaluate expressions using the complete configuration

Your expression should take an attribute set with keys `pkgs`, `lib` and `nodes` (like a NixOS module) and return a JSON-serializable value.

For example, to retrieve the configuration of one node, you may write something like:

    { nodes, ... }: nodes.node-a.config.networking.hostName
"#)
        .arg(Arg::with_name("expression_file")
            .index(1)
            .value_name("FILE")
            .help("The .nix file containing the expression")
            .takes_value(true))
        .arg(Arg::with_name("expression")
            .short("E")
            .value_name("EXPRESSION")
            .help("The Nix expression")
            .takes_value(true))
        .arg(Arg::with_name("instantiate")
            .long("instantiate")
            .help("Actually instantiate the expression")
            .takes_value(false))
}

pub fn deprecated_alias() -> App<'static, 'static> {
    subcommand()
        .name("introspect")
        .setting(AppSettings::Hidden)
}

pub async fn run(global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) -> Result<(), NixError> {
    if let Some("introspect") = global_args.subcommand_name() {
        log::warn!("`colmena introspect` has been renamed to `colmena eval`. Please update your scripts.");
    }

    let hive = util::hive_from_args(local_args).await?;

    if !(local_args.is_present("expression") ^ local_args.is_present("expression_file")) {
        log::error!("Either an expression (-E) or a .nix file containing an expression should be specified, not both.");
        quit::with_code(1);
    }

    let expression = if local_args.is_present("expression") {
        local_args.value_of("expression").unwrap().to_string()
    } else {
        let path: PathBuf = local_args.value_of("expression_file").unwrap().into();
        format!("import {}", path.canonicalize().expect("Could not generate absolute path to expression file.").to_str().unwrap())
    };

    let instantiate = local_args.is_present("instantiate");
    let result = hive.introspect(expression, instantiate).await?;

    if instantiate {
        print!("{}", result);
    } else {
        println!("{}", result);
    }

    Ok(())
}
