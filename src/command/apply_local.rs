use std::env;

use clap::{Arg, App, SubCommand, ArgMatches};
use tokio::fs;
use tokio::process::Command;

use crate::nix::{Hive, DeploymentTask, DeploymentGoal, Host};
use crate::nix::host;

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("apply-local")
        .about("Apply configurations on the local machine")
        .arg(Arg::with_name("goal")
            .help("Deployment goal")
            .long_help("Same as the targets for switch-to-configuration.\n\"push\" is noop in apply-local.")
            .default_value("switch")
            .index(1)
            .possible_values(&["push", "switch", "boot", "test", "dry-activate"]))
        .arg(Arg::with_name("config")
            .short("f")
            .long("config")
            .help("Path to a Hive expression")
            .default_value("hive.nix")
            .required(true))
        .arg(Arg::with_name("sudo")
            .long("sudo")
            .help("Attempt to escalate privileges if not run as root")
            .takes_value(false))
        .arg(Arg::with_name("we-are-launched-by-sudo")
            .long("we-are-launched-by-sudo")
            .hidden(true)
            .takes_value(false))
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) {
    // Sanity check: Are we running NixOS?
    if let Ok(os_release) = fs::read_to_string("/etc/os-release").await {
        if !os_release.contains("ID=nixos\n") {
            eprintln!("\"apply-local\" only works on NixOS machines.");
            quit::with_code(5);
        }
    } else {
        eprintln!("Coult not detect the OS version from /etc/os-release.");
        quit::with_code(5);
    }

    // Escalate privileges?
    {
        let euid: u32 = unsafe { libc::geteuid() };
        if euid != 0 {
            if local_args.is_present("we-are-launched-by-sudo") {
                eprintln!("Failed to escalate privileges. We are still not root despite a successful sudo invocation.");
                quit::with_code(3);
            }

            if local_args.is_present("sudo") {
                escalate().await;
            } else {
                eprintln!("Colmena was not started by root. This is probably not going to work.");
                eprintln!("Hint: Add the --sudo flag.");
            }
        }
    }

    let mut hive = Hive::from_config_arg(local_args).unwrap();
    let hostname = hostname::get().expect("Could not get hostname")
        .to_string_lossy().into_owned();
    let goal = DeploymentGoal::from_str(local_args.value_of("goal").unwrap()).unwrap();

    println!("Enumerating nodes...");
    let all_nodes = hive.deployment_info().await.unwrap();

    let target: Box<dyn Host> = {
        if let Some(info) = all_nodes.get(&hostname) {
            if !info.allows_local_deployment() {
                eprintln!("Local deployment is not enabled for host {}.", hostname);
                eprintln!("Hint: Set deployment.allowLocalDeployment to true.");
                quit::with_code(2);
            }
            host::local()
        } else {
            eprintln!("Host {} is not present in the Hive configuration.", hostname);
            quit::with_code(2);
        }
    };

    println!("Building local node configuration...");
    let profile = {
        let selected_nodes: Vec<String> = vec![hostname.clone()];
        let mut profiles = hive.build_selected(selected_nodes).await
            .expect("Failed to build local configurations");
        profiles.remove(&hostname).unwrap()
    };

    let mut task = DeploymentTask::new(hostname, target, profile, goal);
    task.execute().await.unwrap();
}

async fn escalate() -> ! {
    // Restart ourselves with sudo
    let argv: Vec<String> = env::args().collect();

    let exit = Command::new("sudo")
        .arg("--")
        .args(argv)
        .arg("--we-are-launched-by-sudo")
        .spawn()
        .expect("Failed to run sudo to escalate privileges")
        .wait()
        .await
        .expect("Failed to wait on child");

    // Exit with the same exit code
    quit::with_code(exit.code().unwrap());
}
