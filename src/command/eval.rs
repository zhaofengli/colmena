use std::path::PathBuf;

use clap::Args;

use crate::error::ColmenaError;
use crate::nix::Hive;

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
    /// The Nix expression
    #[arg(short = 'E', value_name = "EXPRESSION")]
    expression: Option<String>,

    /// Actually instantiate the expression
    #[arg(long)]
    instantiate: bool,

    /// The .nix file containing the expression
    #[arg(value_name = "FILE", conflicts_with("expression"))]
    expression_file: Option<PathBuf>,
}

pub async fn run(
    hive: Hive,
    Opts {
        expression,
        instantiate,
        expression_file,
    }: Opts,
) -> Result<(), ColmenaError> {
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
