use clap::{App, AppSettings};

mod nix;
mod command;
mod progress;
mod deployment;
mod util;

macro_rules! command {
    ($name:ident, $matches:ident) => {
        if let Some(sub_matches) = $matches.subcommand_matches(stringify!($name)) {
            command::$name::run(&$matches, &sub_matches).await;
            return;
        }
    }
}

macro_rules! bind_command {
    ($name:ident, $app:ident) => {
        $app = $app.subcommand(command::$name::subcommand());
    }
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
    bind_command!(build, app);
    bind_command!(introspect, app);

    let matches = app.get_matches();

    command!(apply, matches);
    command!(build, matches);
    command!(introspect, matches);
}
