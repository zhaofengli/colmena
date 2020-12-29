use clap::{Arg, App, SubCommand, ArgMatches};

use crate::nix::Hive;
use crate::util;

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("build")
        .about("Build the configuration")
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .takes_value(false));

    util::register_selector_args(command)
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) {
    let mut hive = Hive::from_args(local_args).unwrap();

    println!("Enumerating nodes...");
    let all_nodes = hive.deployment_info().await.unwrap();

    let selected_nodes = match local_args.value_of("on") {
        Some(filter) => {
            util::filter_nodes(&all_nodes, filter)
        }
        None => all_nodes.keys().cloned().collect(),
    };

    if selected_nodes.len() == 0 {
        println!("No hosts matched. Exiting...");
        quit::with_code(2);
    }

    if selected_nodes.len() == all_nodes.len() {
        println!("Building all node configurations...");
    } else {
        println!("Selected {} out of {} hosts. Building node configurations...", selected_nodes.len(), all_nodes.len());
    }

    hive.build_selected(selected_nodes).await.unwrap();

    println!("Success!");
}
