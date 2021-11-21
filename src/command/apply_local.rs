use std::env;
use std::collections::HashMap;
use std::sync::Arc;

use clap::{Arg, App, SubCommand, ArgMatches};
use tokio::fs;
use tokio::process::Command;

use crate::nix::deployment::{
    Deployment,
    Goal,
    Target,
    DeploymentOptions,
};
use crate::nix::{NixError, NodeName, host};
use crate::util;

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("apply-local")
        .about("Apply configurations on the local machine")
        .arg(Arg::with_name("goal")
            .help("Deployment goal")
            .long_help("Same as the targets for switch-to-configuration.\n\"push\" is noop in apply-local.")
            .default_value("switch")
            .index(1)
            .possible_values(&["push", "switch", "boot", "test", "dry-activate"]))
        .arg(Arg::with_name("sudo")
            .long("sudo")
            .help("Attempt to escalate privileges if not run as root"))
        .arg(Arg::with_name("sudo-command")
            .long("sudo-command")
            .value_name("COMMAND")
            .help("Command to use to escalate privileges")
            .default_value("sudo")
            .takes_value(true))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .takes_value(false))
        .arg(Arg::with_name("no-keys")
            .long("no-keys")
            .help("Do not deploy keys")
            .long_help(r#"Do not deploy secret keys set in `deployment.keys`.

By default, Colmena will deploy keys set in `deployment.keys` before activating the profile on this host.
"#)
            .takes_value(false))
        .arg(Arg::with_name("node")
            .long("node")
            .help("Override the node name to use")
            .takes_value(true))
        .arg(Arg::with_name("we-are-launched-by-sudo")
            .long("we-are-launched-by-sudo")
            .hidden(true)
            .takes_value(false))
}

pub async fn run(_global_args: &ArgMatches<'_>, local_args: &ArgMatches<'_>) -> Result<(), NixError> {
    // Sanity check: Are we running NixOS?
    if let Ok(os_release) = fs::read_to_string("/etc/os-release").await {
        if !os_release.contains("ID=nixos\n") {
            log::error!("\"apply-local\" only works on NixOS machines.");
            quit::with_code(5);
        }
    } else {
        log::error!("Could not detect the OS version from /etc/os-release.");
        quit::with_code(5);
    }

    // Escalate privileges?
    {
        let euid: u32 = unsafe { libc::geteuid() };
        if euid != 0 {
            if local_args.is_present("we-are-launched-by-sudo") {
                log::error!("Failed to escalate privileges. We are still not root despite a successful sudo invocation.");
                quit::with_code(3);
            }

            if local_args.is_present("sudo") {
                let sudo = local_args.value_of("sudo-command").unwrap();

                escalate(sudo).await;
            } else {
                log::warn!("Colmena was not started by root. This is probably not going to work.");
                log::warn!("Hint: Add the --sudo flag.");
            }
        }
    }

    let hive = util::hive_from_args(local_args).await.unwrap();
    let hostname = {
        let s = if local_args.is_present("node") {
            local_args.value_of("node").unwrap().to_owned()
        } else {
            hostname::get().expect("Could not get hostname")
                .to_string_lossy().into_owned()
        };

        NodeName::new(s)?
    };
    let goal = Goal::from_str(local_args.value_of("goal").unwrap()).unwrap();

    let target: Target = {
        if let Some(info) = hive.deployment_info_for(&hostname).await.unwrap() {
            let nix_options = hive.nix_options().await.unwrap();
            if !info.allows_local_deployment() {
                log::error!("Local deployment is not enabled for host {}.", hostname.as_str());
                log::error!("Hint: Set deployment.allowLocalDeployment to true.");
                quit::with_code(2);
            }
            Target::new(
                host::local(nix_options),
                info.clone(),
            )
        } else {
            log::error!("Host {} is not present in the Hive configuration.", hostname.as_str());
            quit::with_code(2);
        }
    };

    let mut targets = HashMap::new();
    targets.insert(hostname.clone(), target);

    let mut deployment = Deployment::new(hive, targets, goal);
    let mut options = DeploymentOptions::default();
    options.set_upload_keys(!local_args.is_present("no-upload-keys"));
    options.set_progress_bar(!local_args.is_present("verbose"));
    deployment.set_options(options);

    let deployment = Arc::new(deployment);
    let success = deployment.execute().await;

    if !success {
        quit::with_code(10);
    }

    Ok(())
}

async fn escalate(sudo: &str) -> ! {
    // Restart ourselves with sudo
    let argv: Vec<String> = env::args().collect();

    let exit = Command::new(sudo)
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
