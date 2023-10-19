//! Global CLI Setup.

use std::env;

use clap::{
    builder::PossibleValue, value_parser, Arg, ArgAction, ArgMatches, ColorChoice,
    Command as ClapCommand, ValueEnum,
};
use clap_complete::Shell;
use const_format::{concatcp, formatcp};
use env_logger::fmt::WriteStyle;

use crate::command;

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

macro_rules! register_command {
    ($module:ident, $app:ident) => {
        $app = $app.subcommand(command::$module::subcommand());
    };
}

macro_rules! handle_command {
    ($module:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches(stringify!($module)) {
            crate::troubleshooter::run_wrapped(&$matches, &sub_matches, command::$module::run)
                .await;
            return;
        }
    };
    ($name:expr, $module:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches($name) {
            crate::troubleshooter::run_wrapped(&$matches, &sub_matches, command::$module::run)
                .await;
            return;
        }
    };
}

/// When to display color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorWhen {
    /// Detect automatically.
    Auto,

    /// Always display colors.
    Always,

    /// Never display colors.
    Never,
}

impl ValueEnum for ColorWhen {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Auto, Self::Always, Self::Never]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        match self {
            Self::Auto => Some(PossibleValue::new("auto")),
            Self::Always => Some(PossibleValue::new("always")),
            Self::Never => Some(PossibleValue::new("never")),
        }
    }
}

pub fn build_cli(include_internal: bool) -> ClapCommand {
    let version = env!("CARGO_PKG_VERSION");
    let mut app = ClapCommand::new("Colmena")
        .bin_name("colmena")
        .version(version)
        .author("Zhaofeng Li <hello@zhaofeng.li>")
        .about("NixOS deployment tool")
        .long_about(LONG_ABOUT)
        .arg_required_else_help(true)
        .arg(Arg::new("config")
            .short('f')
            .long("config")
            .value_name("CONFIG")
            .help("Path to a Hive expression, a flake.nix, or a Nix Flake URI")
            .long_help(Some(CONFIG_HELP))
            .display_order(HELP_ORDER_FIRST)

            // The default value is a lie (sort of)!
            //
            // The default behavior is to search upwards from the
            // current working directory for a file named "flake.nix"
            // or "hive.nix". This behavior is disabled if --config/-f
            // is explicitly supplied by the user (occurrences_of > 0).
            .default_value("hive.nix")
            .global(true))
        .arg(Arg::new("show-trace")
            .long("show-trace")
            .help("Show debug information for Nix commands")
            .long_help("Passes --show-trace to Nix commands")
            .global(true)
            .num_args(0))
        .arg(Arg::new("impure")
            .long("impure")
            .help("Allow impure expressions")
            .long_help("Passes --impure to Nix commands")
            .global(true)
            .num_args(0))
        .arg(Arg::new("nix-option")
            .long("nix-option")
            .help("Passes an arbitrary option to Nix commands")
            .long_help(r#"Passes arbitrary options to Nix commands

This only works when building locally.
"#)
            .global(true)
            .num_args(2)
            .value_names(["NAME", "VALUE"])
            .action(ArgAction::Append))
        .arg(Arg::new("color")
            .long("color")
            .help("When to colorize the output")
            .long_help(r#"When to colorize the output. By default, Colmena enables colorized output when the terminal supports it.

It's also possible to specify the preference using environment variables. See <https://bixense.com/clicolors>.
"#)
            .display_order(HELP_ORDER_LOW)
            .value_name("WHEN")
            .value_parser(value_parser!(ColorWhen))
            .default_value("auto")
            .global(true))
        .arg(Arg::new("disable-emoji")
            .long("disable-emoji")
            .help("Disable emoji spinners in output").long_help("Use plain braille pattern spinners instead of emoji")
            .display_order(HELP_ORDER_LOW)
            .global(true)
            .num_args(0)
        );

    if include_internal {
        app = app.subcommand(
            ClapCommand::new("gen-completions")
                .about("Generate shell auto-completion files (Internal)")
                .hide(true)
                .arg(
                    Arg::new("shell")
                        .index(1)
                        .value_parser(value_parser!(Shell))
                        .required(true)
                        .num_args(1),
                ),
        );

        // deprecated alias
        app = app.subcommand(command::eval::deprecated_alias());

        #[cfg(debug_assertions)]
        register_command!(test_progress, app);
    }

    register_command!(apply, app);
    #[cfg(target_os = "linux")]
    register_command!(apply_local, app);
    register_command!(build, app);
    register_command!(eval, app);
    register_command!(upload_keys, app);
    register_command!(exec, app);
    register_command!(repl, app);
    register_command!(nix_info, app);

    // This does _not_ take the --color flag into account (haven't
    // parsed yet), only the CLICOLOR environment variable.
    if clicolors_control::colors_enabled() {
        app.color(ColorChoice::Always)
    } else {
        app
    }
}

pub async fn run() {
    let mut app = build_cli(true);
    let matches = app.clone().get_matches();

    set_color_pref(matches.get_one("color").unwrap());
    init_logging();

    handle_command!(apply, matches);
    #[cfg(target_os = "linux")]
    handle_command!("apply-local", apply_local, matches);
    handle_command!(build, matches);
    handle_command!(eval, matches);
    handle_command!("upload-keys", upload_keys, matches);
    handle_command!(exec, matches);
    handle_command!(repl, matches);
    handle_command!("nix-info", nix_info, matches);

    #[cfg(debug_assertions)]
    handle_command!("test-progress", test_progress, matches);

    if let Some(args) = matches.subcommand_matches("gen-completions") {
        return gen_completions(args);
    }

    // deprecated alias
    handle_command!("introspect", eval, matches);

    app.print_long_help().unwrap();
    println!();
}

fn gen_completions(args: &ArgMatches) {
    let mut app = build_cli(false);
    let shell = args.get_one::<Shell>("shell").unwrap().to_owned();

    clap_complete::generate(shell, &mut app, "colmena", &mut std::io::stdout());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_debug_assert() {
        build_cli(true).debug_assert()
    }
}
