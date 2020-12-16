use clap::{App, AppSettings};

mod nix;
mod command;
mod progress;
mod deployment;
mod util;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    let matches = App::new("Colmena")
        .version("0.1.0")
        .author("Zhaofeng Li <hello@zhaofeng.li>")
        .about("NixOS deployment tool")
        .global_setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(command::apply::subcommand())
        .subcommand(command::build::subcommand())
        .get_matches();

    if let Some(sub_matches) = matches.subcommand_matches("build") {
        command::build::run(&matches, &sub_matches).await;
        return Ok(());
    }
    if let Some(sub_matches) = matches.subcommand_matches("apply") {
        command::apply::run(&matches, &sub_matches).await;
        return Ok(());
    }

    Ok(())
}
