use clap::{App, AppSettings};

mod nix;
mod command;
mod progress;
mod deployment;
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
    let mut app = App::new("Colmena")
        .version("0.1.0")
        .author("Zhaofeng Li <hello@zhaofeng.li>")
        .about("NixOS deployment tool")
        .global_setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ArgRequiredElseHelp);

    bind_command!(apply, app);
    bind_command!(apply_local, app);
    bind_command!(build, app);
    bind_command!(introspect, app);

    let matches = app.get_matches();

    command!(apply, matches);
    command!("apply-local", apply_local, matches);
    command!(build, matches);
    command!(introspect, matches);
}
