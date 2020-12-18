use clap::{Arg, App, SubCommand, ArgMatches};

use crate::nix::{Hive, DeploymentTask, DeploymentGoal};
use crate::deployment::deploy;
use crate::util;

pub fn subcommand() -> App<'static, 'static> {
    let command = SubCommand::with_name("apply")
        .about("Apply the configuration")
        .arg(Arg::with_name("goal")
            .help("Deployment goal")
            .long_help("Same as the targets for switch-to-configuration.\n\"push\" means only copying the closures to remote nodes.")
            .default_value("switch")
            .index(1)
            .possible_values(&["push", "switch", "boot", "test", "dry-activate"]))
        .arg(Arg::with_name("parallel")
            .short("p")
            .long("parallel")
            .help("Parallelism limit")
            .long_help("Set to 0 to disable parallemism limit.")
            .default_value("10")
            .takes_value(true)
            .validator(|s| {
                match s.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value must be a valid number")),
                }
            }))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .takes_value(false));

    util::register_common_args(command)
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) {
    let mut hive = Hive::from_config_arg(local_args).unwrap();

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

    // Some ugly argument mangling :/
    let profiles = hive.build_selected(selected_nodes).await.unwrap();
    let goal = DeploymentGoal::from_str(local_args.value_of("goal").unwrap()).unwrap();
    let verbose = local_args.is_present("verbose");

    let max_parallelism = local_args.value_of("parallel").unwrap().parse::<usize>().unwrap();
    let max_parallelism = match max_parallelism {
        0 => None,
        _ => Some(max_parallelism),
    };

    let mut task_list: Vec<DeploymentTask> = Vec::new();
    for (name, profile) in profiles.iter() {
        let task = DeploymentTask::new(
            name.clone(),
            all_nodes.get(name).unwrap().to_host(),
            profile.clone(),
            goal,
        );
        task_list.push(task);
    }

    println!("Applying configurations...");

    deploy(task_list, max_parallelism, !verbose).await;
}
