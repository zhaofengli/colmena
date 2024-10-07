//! Global CLI Setup.

use std::env;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use const_format::{concatcp, formatcp};
use env_logger::fmt::WriteStyle;

use crate::{
    command::{self, apply::DeployOpts},
    error::ColmenaResult,
    nix::{hive::EvaluationMethod, Hive, HivePath},
};

/// Base URL of the manual, without the trailing slash.
const MANUAL_URL_BASE: &str = "https://colmena.cli.rs";

/// URL to the manual.
///
/// We maintain CLI and Nix API stability for each minor version.
/// This ensures that the user always sees accurate documentations, and we can
/// easily perform updates to the manual after a release.
const MANUAL_URL: &str = concatcp!(
    MANUAL_URL_BASE,
    "/",
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR")
);

/// The note shown when the user is using a pre-release version.
///
/// API stability cannot be guaranteed for pre-release versions.
/// Links to the version currently in development automatically
/// leads the user to the unstable manual.
const MANUAL_DISCREPANCY_NOTE: &str = "\nNote: You are using a pre-release version of Colmena, so the supported options may be different from what's in the manual.";

static LONG_ABOUT: &str = formatcp!(
    r#"NixOS deployment tool

Colmena helps you deploy to multiple hosts running NixOS.
For more details, read the manual at <{}>.

{}"#,
    MANUAL_URL,
    if !env!("CARGO_PKG_VERSION_PRE").is_empty() {
        MANUAL_DISCREPANCY_NOTE
    } else {
        ""
    }
);

static CONFIG_HELP: &str = formatcp!(
    r#"If this argument is not specified, Colmena will search upwards from the current working directory for a file named "flake.nix" or "hive.nix". This behavior is disabled if --config/-f is given explicitly.

For a sample configuration, check the manual at <{}>.
"#,
    MANUAL_URL
);

/// Display order in `--help` for arguments that should be shown first.
///
/// Currently reserved for -f/--config.
const HELP_ORDER_FIRST: usize = 100;

/// Display order in `--help` for arguments that are not very important.
const HELP_ORDER_LOW: usize = 2000;

/// When to display color.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorWhen {
    /// Detect automatically.
    #[default]
    Auto,

    /// Always display colors.
    Always,

    /// Never display colors.
    Never,
}

impl std::fmt::Display for ColorWhen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        })
    }
}

#[derive(Parser)]
#[command(
    name = "Colmena",
    bin_name = "colmena",
    author = "Zhaofeng Li <hello@zhaofeng.li>",
    version = env!("CARGO_PKG_VERSION"),
    about = "NixOS deployment tool",
    long_about = LONG_ABOUT,
)]
struct Opts {
    #[arg(
        short = 'f',
        long,
        value_name = "CONFIG",
        help = "Path to a Hive expression, a flake.nix, or a Nix Flake URI",
        long_help = CONFIG_HELP,
        display_order = HELP_ORDER_FIRST,
        global = true,
    )]
    config: Option<HivePath>,
    #[arg(
        long,
        help = "Show debug information for Nix commands",
        long_help = "Passes --show-trace to Nix commands",
        global = true
    )]
    show_trace: bool,
    #[arg(
        long,
        help = "Allow impure expressions",
        long_help = "Passes --impure to Nix commands",
        global = true
    )]
    impure: bool,
    #[arg(
        long,
        help = "Passes an arbitrary option to Nix commands",
        long_help = r#"Passes arbitrary options to Nix commands

This only works when building locally.
"#,
        global = true,
        num_args = 2,
        value_names = ["NAME", "VALUE"],
    )]
    nix_option: Vec<String>,
    #[arg(
        long,
        default_value_t,
        help = "Use direct flake evaluation (experimental)",
        long_help = r#"If enabled, flakes will be evaluated using `nix eval`. This requires the flake to depend on Colmena as an input and expose a compatible `colmenaHive` output:

  outputs = { self, colmena, ... }: {
    colmenaHive = colmena.lib.makeHive self.outputs.colmena;
    colmena = ...;
  };

This is an experimental feature."#,
        global = true
    )]
    experimental_flake_eval: bool,
    #[arg(
        long,
        value_name = "WHEN",
        default_value_t,
        global = true,
        display_order = HELP_ORDER_LOW,
        help = "When to colorize the output",
        long_help = r#"When to colorize the output. By default, Colmena enables colorized output when the terminal supports it.

It's also possible to specify the preference using environment variables. See <https://bixense.com/clicolors>.
"#,
    )]
    color: ColorWhen,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Apply(command::apply::Opts),
    #[cfg(target_os = "linux")]
    ApplyLocal(command::apply_local::Opts),
    #[command(
        about = "Build configurations but not push to remote machines",
        long_about = r#"Build configurations but not push to remote machines

This subcommand behaves as if you invoked `apply` with the `build` goal."#
    )]
    Build {
        #[command(flatten)]
        deploy: DeployOpts,
    },
    Eval(command::eval::Opts),
    #[command(
        about = "Upload keys to remote hosts",
        long_about = r#"Upload keys to remote hosts

This subcommand behaves as if you invoked `apply` with the pseudo `keys` goal."#
    )]
    UploadKeys {
        #[command(flatten)]
        deploy: DeployOpts,
    },
    Exec(command::exec::Opts),
    #[command(
        about = "Start an interactive REPL with the complete configuration",
        long_about = r#"Start an interactive REPL with the complete configuration

In the REPL, you can inspect the configuration interactively with tab
completion. The node configurations are accessible under the `nodes`
attribute set."#
    )]
    Repl,
    #[command(about = "Show information about the current Nix installation")]
    NixInfo,
    #[cfg(debug_assertions)]
    #[command(about = "Run progress spinner tests", hide = true)]
    TestProgress,
    #[command(about = "Generate shell auto-completion files (Internal)", hide = true)]
    GenCompletions {
        shell: Shell,
    },
}

async fn get_hive(opts: &Opts) -> ColmenaResult<Hive> {
    let path = match &opts.config {
        Some(path) => path.clone(),
        None => {
            // traverse upwards until we find hive.nix
            let mut cur = std::env::current_dir()?;
            let mut file_path = None;

            loop {
                let flake = cur.join("flake.nix");
                if flake.is_file() {
                    file_path = Some(flake);
                    break;
                }

                let legacy = cur.join("hive.nix");
                if legacy.is_file() {
                    file_path = Some(legacy);
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

            if file_path.is_none() {
                log::error!(
                    "Could not find `hive.nix` or `flake.nix` in {:?} or any parent directory",
                    std::env::current_dir()?
                );
            }

            HivePath::from_path(file_path.unwrap()).await?
        }
    };

    match &path {
        HivePath::Legacy(p) => {
            log::info!("Using configuration: {}", p.to_string_lossy());
        }
        HivePath::Flake(flake) => {
            log::info!("Using flake: {}", flake.uri());
        }
    }

    let mut hive = Hive::new(path).await?;

    if opts.show_trace {
        hive.set_show_trace(true);
    }

    if opts.impure {
        hive.set_impure(true);
    }

    if opts.experimental_flake_eval {
        log::warn!("Using direct flake evaluation (experimental)");
        hive.set_evaluation_method(EvaluationMethod::FlakeApply);
    }

    for chunks in opts.nix_option.chunks_exact(2) {
        let [name, value] = chunks else {
            unreachable!()
        };
        hive.add_nix_option(name.clone(), value.clone());
    }

    Ok(hive)
}

pub async fn run() {
    let opts = Opts::parse();

    set_color_pref(&opts.color);
    init_logging();

    if let Command::GenCompletions { shell } = opts.command {
        print_completions(shell, &mut Opts::command());
        return;
    }

    let hive = get_hive(&opts).await.expect("Failed to get flake or hive");

    use crate::troubleshooter::run_wrapped as r;

    match opts.command {
        Command::Apply(args) => r(command::apply::run(hive, args), opts.config).await,
        #[cfg(target_os = "linux")]
        Command::ApplyLocal(args) => r(command::apply_local::run(hive, args), opts.config).await,
        Command::Eval(args) => r(command::eval::run(hive, args), opts.config).await,
        Command::Exec(args) => r(command::exec::run(hive, args), opts.config).await,
        Command::NixInfo => r(command::nix_info::run(), opts.config).await,
        Command::Repl => r(command::repl::run(hive), opts.config).await,
        #[cfg(debug_assertions)]
        Command::TestProgress => r(command::test_progress::run(), opts.config).await,
        Command::Build { deploy } => {
            let args = command::apply::Opts {
                deploy,
                goal: crate::nix::Goal::Build,
            };
            r(command::apply::run(hive, args), opts.config).await
        }
        Command::UploadKeys { deploy } => {
            let args = command::apply::Opts {
                deploy,
                goal: crate::nix::Goal::UploadKeys,
            };
            r(command::apply::run(hive, args), opts.config).await
        }
        Command::GenCompletions { .. } => unreachable!(),
    }
}

fn print_completions(shell: Shell, cmd: &mut clap::Command) {
    let bin_name = cmd
        .get_bin_name()
        .expect("Must have a bin_name")
        .to_string();

    clap_complete::generate(shell, cmd, bin_name, &mut std::io::stdout());
}

fn set_color_pref(when: &ColorWhen) {
    if when != &ColorWhen::Auto {
        clicolors_control::set_colors_enabled(when == &ColorWhen::Always);
    }
}

fn init_logging() {
    if env::var("RUST_LOG").is_err() {
        // HACK
        env::set_var("RUST_LOG", "info")
    }

    // make env_logger conform to our detection logic
    let style = if clicolors_control::colors_enabled() {
        WriteStyle::Always
    } else {
        WriteStyle::Never
    };

    env_logger::builder()
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false)
        .write_style(style)
        .init();
}
