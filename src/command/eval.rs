use std::path::PathBuf;

use clap::{value_parser, Arg, ArgMatches, Command as ClapCommand, FromArgMatches};

use crate::error::ColmenaError;
use crate::nix::hive::HiveArgs;

pub fn subcommand() -> ClapCommand {
    subcommand_gen("eval")
}

pub fn deprecated_alias() -> ClapCommand {
    subcommand_gen("introspect").hide(true)
}

fn subcommand_gen(name: &'static str) -> ClapCommand {
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
            .num_args(1)
            .value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("expression")
            .short('E')
            .value_name("EXPRESSION")
            .help("The Nix expression")
            .num_args(1))
        .arg(Arg::new("instantiate")
            .long("instantiate")
            .help("Actually instantiate the expression")
            .num_args(0))
}

pub async fn run(global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    if let Some("introspect") = global_args.subcommand_name() {
        log::warn!(
            "`colmena introspect` has been renamed to `colmena eval`. Please update your scripts."
        );
    }

    let hive = HiveArgs::from_arg_matches(local_args)
        .unwrap()
        .into_hive()
        .await
        .unwrap();

    if !(local_args.contains_id("expression") ^ local_args.contains_id("expression_file")) {
        log::error!("Either an expression (-E) or a .nix file containing an expression should be specified, not both.");
        quit::with_code(1);
    }

    let expression = if local_args.contains_id("expression") {
        local_args
            .get_one::<String>("expression")
            .unwrap()
            .to_owned()
    } else {
        let path = local_args
            .get_one::<PathBuf>("expression_file")
            .unwrap()
            .to_owned();
        format!(
            "import {}",
            path.canonicalize()
                .expect("Could not generate absolute path to expression file.")
                .to_str()
                .unwrap()
        )
    };

    let instantiate = local_args.get_flag("instantiate");
    let result = hive.introspect(expression, instantiate).await?;

    if instantiate {
        print!("{}", result);
    } else {
        println!("{}", result);
    }

    Ok(())
}
