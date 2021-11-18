//! Global CLI Setup.

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use lazy_static::lazy_static;

use crate::command;

lazy_static! {
    static ref CONFIG_HELP: String = {
        format!(r#"If this argument is not specified, Colmena will search upwards from the current working directory for a file named "flake.nix" or "hive.nix". This behavior is disabled if --config/-f is given explicitly.

For a sample configuration, see <https://zhaofengli.github.io/colmena/{}>.
"#, env!("CARGO_PKG_VERSION"))
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
    let version = env!("CARGO_PKG_VERSION");
    let mut app = App::new("Colmena")
        .bin_name("colmena")
        .version(version)
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
            .long_help(&CONFIG_HELP)
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

    if let Some(_) = matches.subcommand_matches("gen-help-markdown") {
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
