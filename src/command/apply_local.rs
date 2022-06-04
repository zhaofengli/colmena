use regex::Regex;
use std::collections::HashMap;

use clap::{Arg, Command as ClapCommand, ArgMatches};
use tokio::fs;

use crate::error::ColmenaError;
use crate::nix::deployment::{
    Deployment,
    Goal,
    TargetNode,
    Options,
};
use crate::nix::{NodeName, host::Local as LocalHost};
use crate::progress::SimpleProgressOutput;
use crate::util;

pub fn subcommand() -> ClapCommand<'static> {
    ClapCommand::new("apply-local")
        .about("Apply configurations on the local machine")
        .arg(Arg::new("goal")
            .help("Deployment goal")
            .long_help("Same as the targets for switch-to-configuration.\n\"push\" is noop in apply-local.")
            .default_value("switch")
            .index(1)
            .possible_values(&["push", "switch", "boot", "test", "dry-activate", "keys"]))
        .arg(Arg::new("sudo")
            .long("sudo")
            .help("Attempt to escalate privileges if not run as root"))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .takes_value(false))
        .arg(Arg::new("no-keys")
            .long("no-keys")
            .help("Do not deploy keys")
            .long_help(r#"Do not deploy secret keys set in `deployment.keys`.

By default, Colmena will deploy keys set in `deployment.keys` before activating the profile on this host.
"#)
            .takes_value(false))
        .arg(Arg::new("node")
            .long("node")
            .help("Override the node name to use")
            .takes_value(true))

        // Removed
        .arg(Arg::new("sudo-command")
            .long("sudo-command")
            .value_name("COMMAND")
            .help("Removed: Configure deployment.privilegeEscalationCommand in node configuration")
            .hide(true)
            .takes_value(true))
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    if local_args.occurrences_of("sudo-command") > 0 {
        log::error!("--sudo-command has been removed. Please configure it in deployment.privilegeEscalationCommand in the node configuration.");
        quit::with_code(1);
    }

    // Sanity check: Are we running NixOS?
    if let Ok(os_release) = fs::read_to_string("/etc/os-release").await {
        let re = Regex::new(r#"ID="?nixos"?"#).unwrap();
        if !re.is_match(&os_release) {
            log::error!("\"apply-local\" only works on NixOS machines.");
            quit::with_code(5);
        }
    } else {
        log::error!("Could not detect the OS version from /etc/os-release.");
        quit::with_code(5);
    }

    let escalate_privileges = local_args.is_present("sudo");
    let verbose = local_args.is_present("verbose") || escalate_privileges; // cannot use spinners with interactive sudo

    {
        let euid: u32 = unsafe { libc::geteuid() };
        if euid != 0 && !escalate_privileges {
            log::warn!("Colmena was not started by root. This is probably not going to work.");
            log::warn!("Hint: Add the --sudo flag.");
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

    let target = {
        if let Some(info) = hive.deployment_info_single(&hostname).await.unwrap() {
            let nix_options = hive.nix_options_with_builders().await.unwrap();
            if !info.allows_local_deployment() {
                log::error!("Local deployment is not enabled for host {}.", hostname.as_str());
                log::error!("Hint: Set deployment.allowLocalDeployment to true.");
                quit::with_code(2);
            }
            let mut host = LocalHost::new(nix_options);
            if escalate_privileges {
                let command = info.privilege_escalation_command().to_owned();
                host.set_privilege_escalation_command(Some(command));
            }

            TargetNode::new(
                hostname.clone(),
                Some(host.upcast()),
                info.clone(),
            )
        } else {
            log::error!("Host \"{}\" is not present in the Hive configuration.", hostname.as_str());
            quit::with_code(2);
        }
    };

    let mut targets = HashMap::new();
    targets.insert(hostname.clone(), target);

    let mut output = SimpleProgressOutput::new(verbose);
    let progress = output.get_sender();

    let mut deployment = Deployment::new(hive, targets, goal, progress);

    let options = {
        let mut options = Options::default();
        options.set_upload_keys(!local_args.is_present("no-keys"));
        options
    };

    deployment.set_options(options);

    let (deployment, output) = tokio::join!(
        deployment.execute(),
        output.run_until_completion(),
    );

    deployment?; output?;

    Ok(())
}
