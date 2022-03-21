use std::path::PathBuf;

use clap::{Arg, ArgMatches, Command as ClapCommand};

use crate::error::ColmenaError;
use crate::util;

pub fn subcommand() -> ClapCommand<'static> {
    subcommand_gen("eval")
}

pub fn deprecated_alias() -> ClapCommand<'static> {
    subcommand_gen("introspect").hide(true)
}

fn subcommand_gen(name: &str) -> ClapCommand<'static> {
    ClapCommand::new(name)
        .about("Evaluate an expression using the complete configuration")
        .long_about(r#"Evaluate an expression using the complete configuration

Your expression should take an attribute set with keys `pkgs`, `lib` and `nodes` (like a NixOS module) and return a JSON-serializable value.

For example, to retrieve the configuration of one node, you may write something like:

    { nodes, ... }: nodes.node-a.config.networking.hostName
"#)
        .arg(Arg::new("expression_file")
            .index(1)
            .value_name("FILE")
            .help("The .nix file containing the expression")
            .takes_value(true))
        .arg(Arg::new("expression")
            .short('E')
            .value_name("EXPRESSION")
            .help("The Nix expression")
            .takes_value(true))
        .arg(Arg::new("instantiate")
            .long("instantiate")
            .help("Actually instantiate the expression")
            .takes_value(false))
}

pub async fn run(global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    if let Some("introspect") = global_args.subcommand_name() {
        log::warn!(
            "`colmena introspect` has been renamed to `colmena eval`. Please update your scripts."
        );
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
        format!(
            "import {}",
            path.canonicalize()
                .expect("Could not generate absolute path to expression file.")
                .to_str()
                .unwrap()
        )
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
