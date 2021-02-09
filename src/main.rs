use std::env;
use clap::{App, AppSettings, Arg};

mod nix;
mod command;
mod progress;
mod util;

macro_rules! command {
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

macro_rules! bind_command {
    ($module:ident, $app:ident) => {
        $app = $app.subcommand(command::$module::subcommand());
    };
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    init_logging();

    let mut app = App::new("Colmena")
        .version("0.1.0")
        .author("Zhaofeng Li <hello@zhaofeng.li>")
        .about("NixOS deployment tool")
        .global_setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("config")
            .short("f")
            .long("config")
            .value_name("CONFIG")
            .help("Path to a Hive expression")

            // The default value is a lie (sort of)!
            //
            // The default behavior is to search upwards from the
            // current working directory for a file named "hive.nix".
            // This behavior is disabled if --config/-f is explicitly
            // supplied by the user (occurrences_of > 0).
            .default_value("hive.nix")
            .long_help(r#"If this argument is not specified, Colmena will search upwards from the current working directory for a file named "hive.nix". This behavior is disabled if --config/-f is given explicitly.

For a sample configuration, see <https://github.com/zhaofengli/colmena>.
"#)
            .global(true))
        .arg(Arg::with_name("show-trace")
            .long("show-trace")
            .help("Show debug information for Nix commands")
            .long_help("Passes --show-trace to Nix commands")
            .global(true)
            .takes_value(false));

    bind_command!(apply, app);
    bind_command!(apply_local, app);
    bind_command!(build, app);
    bind_command!(introspect, app);
    bind_command!(upload_keys, app);

    let matches = app.clone().get_matches();

    command!(apply, matches);
    command!("apply-local", apply_local, matches);
    command!(build, matches);
    command!(introspect, matches);
    command!("upload-keys", upload_keys, matches);

    app.print_long_help().unwrap();
}

fn init_logging() {
    if env::var("RUST_LOG").is_err() {
        // HACK
        env::set_var("RUST_LOG", "info")
    }
    env_logger::builder()
        .format_timestamp(None)
        .format_module_path(false)
        .init();
}
