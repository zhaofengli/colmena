//! Global CLI Setup.

use std::env;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use const_format::concatcp;
use env_logger::fmt::WriteStyle;
use lazy_static::lazy_static;

use crate::command;

/// Base URL of the manual, without the trailing slash.
const MANUAL_URL_BASE: &str = "https://zhaofengli.github.io/colmena";

/// URL to the manual.
///
/// We maintain CLI and Nix API stability for each minor version.
/// This ensures that the user always sees accurate documentations, and we can
/// easily perform updates to the manual after a release.
const MANUAL_URL: &str = concatcp!(MANUAL_URL_BASE, "/", env!("CARGO_PKG_VERSION_MAJOR"), ".", env!("CARGO_PKG_VERSION_MINOR"));

/// The note shown when the user is using a pre-release version.
///
/// API stability cannot be guaranteed for pre-release versions.
/// Links to the version currently in development automatically
/// leads the user to the unstable manual.
const MANUAL_DISCREPANCY_NOTE: &str = "Note: You are using a pre-release version of Colmena, so the supported options may be different from what's in the manual.";

lazy_static! {
    static ref LONG_ABOUT: String = {
        let mut message = format!(r#"NixOS deployment tool

Colmena helps you deploy to multiple hosts running NixOS.
For more details, read the manual at <{}>.

"#, MANUAL_URL);

        if !env!("CARGO_PKG_VERSION_PRE").is_empty() {
            message += MANUAL_DISCREPANCY_NOTE;
        }

        message
    };

    static ref CONFIG_HELP: String = {
        format!(r#"If this argument is not specified, Colmena will search upwards from the current working directory for a file named "flake.nix" or "hive.nix". This behavior is disabled if --config/-f is given explicitly.

For a sample configuration, check the manual at <{}>.
"#, MANUAL_URL)
    };
}

macro_rules! register_command {
    ($module:ident, $app:ident) => {
        $app = $app.subcommand(command::$module::subcommand());
    };
}

macro_rules! handle_command {
    ($module:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches(stringify!($module)) {
            crate::troubleshooter::run_wrapped(
                &$matches, &sub_matches,
                command::$module::run,
            ).await;
            return;
        }
    };
    ($name:expr, $module:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches($name) {
            crate::troubleshooter::run_wrapped(
                &$matches, &sub_matches,
                command::$module::run,
            ).await;
            return;
        }
    };
}

pub fn build_cli(include_internal: bool) -> App<'static, 'static> {
    let version = env!("CARGO_PKG_VERSION");
    let mut app = App::new("Colmena")
        .bin_name("colmena")
        .version(version)
        .author("Zhaofeng Li <hello@zhaofeng.li>")
        .about("NixOS deployment tool")
        .long_about(LONG_ABOUT.as_str())
        .global_setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("config")
            .short("f")
            .long("config")
            .value_name("CONFIG")
            .help("Path to a Hive expression, a flake.nix, or a Nix Flake URI")

            // The default value is a lie (sort of)!
            //
            // The default behavior is to search upwards from the
            // current working directory for a file named "flake.nix"
            // or "hive.nix". This behavior is disabled if --config/-f
            // is explicitly supplied by the user (occurrences_of > 0).
            .default_value("hive.nix")
            .long_help(&CONFIG_HELP)
            .global(true))
        .arg(Arg::with_name("show-trace")
            .long("show-trace")
            .help("Show debug information for Nix commands")
            .long_help("Passes --show-trace to Nix commands")
            .global(true)
            .takes_value(false))
        .arg(Arg::with_name("color")
            .long("color")
            .help("When to colorize the output")
            .long_help(r#"When to colorize the output. By default, Colmena enables colorized output when the terminal supports it.

It's also possible to specify the preference using environment variables. See <https://bixense.com/clicolors>.
"#)
            .value_name("WHEN")
            .possible_values(&["auto", "always", "never"])
            .default_value("auto")
            .global(true));

    if include_internal {
        app = app.subcommand(SubCommand::with_name("gen-completions")
            .about("Generate shell auto-completion files (Internal)")
            .setting(AppSettings::Hidden)
            .arg(Arg::with_name("shell")
                .index(1)
                .required(true)
                .takes_value(true)));

        app = app.subcommand(SubCommand::with_name("gen-help-markdown")
            .about("Generate CLI usage guide as Markdown (Internal)")
            .setting(AppSettings::Hidden));

        // deprecated alias
        app = app.subcommand(command::eval::deprecated_alias());

        register_command!(test_progress, app);
    }

    register_command!(apply, app);
    register_command!(apply_local, app);
    register_command!(build, app);
    register_command!(eval, app);
    register_command!(upload_keys, app);
    register_command!(exec, app);
    register_command!(nix_info, app);

    app
}

pub async fn run() {
    let mut app = build_cli(true);
    let matches = app.clone().get_matches();

    set_color_pref(matches.value_of("color").unwrap());
    init_logging();

    handle_command!(apply, matches);
    handle_command!("apply-local", apply_local, matches);
    handle_command!(build, matches);
    handle_command!(eval, matches);
    handle_command!("upload-keys", upload_keys, matches);
    handle_command!(exec, matches);
    handle_command!("nix-info", nix_info, matches);

    // deprecated alias
    handle_command!("introspect", eval, matches);

    handle_command!("test-progress", test_progress, matches);

    if let Some(args) = matches.subcommand_matches("gen-completions") {
        return gen_completions(args);
    }

    if matches.subcommand_matches("gen-help-markdown").is_some() {
        return gen_help_markdown();
    };

    app.print_long_help().unwrap();
    println!();
}

fn gen_completions(args: &ArgMatches<'_>) {
    let mut app = build_cli(false);
    let shell: clap::Shell = args.value_of("shell").unwrap()
        .parse().unwrap();

    app.gen_completions_to("colmena", shell, &mut std::io::stdout());
}

fn gen_help_markdown() {
    // This is tailered only for the manual, with output injected to `reference/cli.md`.
    // <pre><div class="hljs">
    let mut commands = vec![
        build_cli(false),
        command::apply::subcommand(),
        command::apply_local::subcommand(),
        command::build::subcommand(),
        command::upload_keys::subcommand(),
        command::eval::subcommand(),
        command::exec::subcommand(),
        command::nix_info::subcommand(),
    ];

    for command in commands.drain(..) {
        let full_command = match command.get_name() {
            "Colmena" => "colmena".to_string(),
            sub => format!("colmena {}", sub),
        };

        let mut command = {
            let c = command
                .setting(AppSettings::ColoredHelp)
                .setting(AppSettings::ColorAlways);

            if full_command != "colmena" {
                c.bin_name(&full_command)
            } else {
                c
            }
        };

        println!("## `{}`", full_command);
        print!("<pre><div class=\"hljs\">");

        let help_message = {
            let mut bytes = Vec::new();
            command.write_long_help(&mut bytes).unwrap();
            String::from_utf8(bytes).unwrap()
        };

        let help_html = ansi_to_html::convert(&help_message, true, true)
            .expect("Could not convert terminal output to HTML");

        print!("{}", help_html);
        println!("</div></pre>");
    }
}

fn set_color_pref(cli: &str) {
    if cli != "auto" {
        clicolors_control::set_colors_enabled(cli == "always");
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
        .write_style(style)
        .init();
}
