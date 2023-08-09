use std::path::PathBuf;

use clap::{ArgMatches, Args, Command as ClapCommand, FromArgMatches};

use crate::error::ColmenaError;
use crate::nix::hive::HiveArgs;

#[derive(Debug, Args)]
#[command(
    name = "eval",
    alias = "introspect",
    about = "Evaluate an expression using the complete configuration",
    long_about = r#"Evaluate an expression using the complete configuration

Your expression should take an attribute set with keys `pkgs`, `lib` and `nodes` (like a NixOS module) and return a JSON-serializable value.

For example, to retrieve the configuration of one node, you may write something like:

    { nodes, ... }: nodes.node-a.config.networking.hostName
"#
)]
pub struct Opts {
    #[arg(short = 'E', value_name = "EXPRESSION", help = "The Nix expression")]
    expression: Option<String>,
    #[arg(long, help = "Actually instantiate the expression")]
    instantiate: bool,
    #[arg(
        value_name = "FILE",
        help = "The .nix file containing the expression",
        conflicts_with("expression")
    )]
    expression_file: Option<PathBuf>,
}

pub fn subcommand() -> ClapCommand {
    Opts::augment_args(ClapCommand::new("eval"))
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

    let Opts {
        instantiate,
        expression,
        expression_file,
    } = Opts::from_arg_matches(local_args).expect("Failed to parse args");

    let expression = expression_file
        .map(|path| {
            format!(
                "import {}",
                path.canonicalize()
                    .expect("Could not generate absolute path to expression file.")
                    .to_str()
                    .unwrap()
            )
        })
        .or(expression);

    let Some(expression) = expression else {
        log::error!("Provide either an expression (-E) or a .nix file containing an expression.");
        quit::with_code(1);
    };

    let result = hive.introspect(expression, instantiate).await?;

    if instantiate {
        print!("{}", result);
    } else {
        println!("{}", result);
    }

    Ok(())
}
