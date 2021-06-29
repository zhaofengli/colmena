//! Global CLI Setup.

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use crate::command;

macro_rules! register_command {
    ($module:ident, $app:ident) => {
        $app = $app.subcommand(command::$module::subcommand());
    };
}

macro_rules! handle_command {
    ($module:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches(stringify!($module)) {
            command::$module::run(&$matches, &sub_matches).await;
            return;
        }
    };
    ($name:expr, $module:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches($name) {
            command::$module::run(&$matches, &sub_matches).await;
            return;
        }
    };
}

pub fn build_cli(include_internal: bool) -> App<'static, 'static> {
    let mut app = App::new("Colmena")
        .bin_name("colmena")
        .version("0.1.0")
        .author("Zhaofeng Li <hello@zhaofeng.li>")
        .about("NixOS deployment tool")
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
            .long_help(r#"If this argument is not specified, Colmena will search upwards from the current working directory for a file named "flake.nix" or "hive.nix". This behavior is disabled if --config/-f is given explicitly.

For a sample configuration, see <https://github.com/zhaofengli/colmena>.
"#)
            .global(true))
        .arg(Arg::with_name("show-trace")
            .long("show-trace")
            .help("Show debug information for Nix commands")
            .long_help("Passes --show-trace to Nix commands")
            .global(true)
            .takes_value(false));

    if include_internal {
        app = app.subcommand(SubCommand::with_name("gen-completions")
            .about("Generate shell auto-completion files (Internal)")
            .setting(AppSettings::Hidden)
            .arg(Arg::with_name("shell")
                .index(1)
                .required(true)
                .takes_value(true)));
    }

    register_command!(apply, app);
    register_command!(apply_local, app);
    register_command!(build, app);
    register_command!(introspect, app);
    register_command!(upload_keys, app);
    register_command!(exec, app);
    register_command!(nix_info, app);

    app
}

pub async fn run() {
    let mut app = build_cli(true);
    let matches = app.clone().get_matches();

    handle_command!(apply, matches);
    handle_command!("apply-local", apply_local, matches);
    handle_command!(build, matches);
    handle_command!(introspect, matches);
    handle_command!("upload-keys", upload_keys, matches);
    handle_command!(exec, matches);
    handle_command!("nix-info", nix_info, matches);

    if let Some(args) = matches.subcommand_matches("gen-completions") {
        return gen_completions(args);
    }

    app.print_long_help().unwrap();
    println!();
}

fn gen_completions(args: &ArgMatches<'_>) {
    let mut app = build_cli(false);
    let shell: clap::Shell = args.value_of("shell").unwrap()
        .parse().unwrap();

    app.gen_completions_to("colmena", shell, &mut std::io::stdout());
}
