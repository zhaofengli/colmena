use regex::Regex;
use std::collections::HashMap;
use std::str::FromStr;

use clap::{builder::PossibleValuesParser, Arg, ArgMatches, Command as ClapCommand};
use tokio::fs;

use crate::error::ColmenaError;
use crate::nix::deployment::{Deployment, Goal, Options, TargetNode};
use crate::nix::{host::Local as LocalHost, NodeName};
use crate::progress::SimpleProgressOutput;
use crate::util;

pub fn subcommand() -> ClapCommand {
    ClapCommand::new("apply-local")
        .about("Apply configurations on the local machine")
        .arg(Arg::new("goal")
            .help("Deployment goal")
            .long_help("Same as the targets for switch-to-configuration.\n\"push\" is noop in apply-local.")
            .default_value("switch")
            .index(1)
            .value_parser(PossibleValuesParser::new([
                "push",
                "switch",
                "boot",
                "test",
                "dry-activate",
                "keys",
            ])))
        .arg(Arg::new("sudo")
            .long("sudo")
            .help("Attempt to escalate privileges if not run as root")
            .num_args(0))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Be verbose")
            .long_help("Deactivates the progress spinner and prints every line of output.")
            .num_args(0))
        .arg(Arg::new("no-keys")
            .long("no-keys")
            .help("Do not deploy keys")
            .long_help(r#"Do not deploy secret keys set in `deployment.keys`.

By default, Colmena will deploy keys set in `deployment.keys` before activating the profile on this host.
"#)
            .num_args(0))
        .arg(Arg::new("node")
            .long("node")
            .value_name("NODE")
            .help("Override the node name to use")
            .num_args(1))

        // Removed
        .arg(Arg::new("sudo-command")
            .long("sudo-command")
            .value_name("COMMAND")
            .help("Removed: Configure deployment.privilegeEscalationCommand in node configuration")
            .hide(true)
            .num_args(1))
}

pub async fn run(_global_args: &ArgMatches, local_args: &ArgMatches) -> Result<(), ColmenaError> {
    if local_args.contains_id("sudo-command") {
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

    let escalate_privileges = local_args.get_flag("sudo");
    let verbose = local_args.get_flag("verbose") || escalate_privileges; // cannot use spinners with interactive sudo

    {
        let euid: u32 = unsafe { libc::geteuid() };
        if euid != 0 && !escalate_privileges {
            log::warn!("Colmena was not started by root. This is probably not going to work.");
            log::warn!("Hint: Add the --sudo flag.");
        }
    }

    let hive = util::hive_from_args(local_args).await.unwrap();
    let hostname = {
        let s = if local_args.contains_id("node") {
            local_args.get_one::<String>("node").unwrap().to_owned()
        } else {
            hostname::get()
                .expect("Could not get hostname")
                .to_string_lossy()
                .into_owned()
        };

        NodeName::new(s)?
    };
    let goal = Goal::from_str(local_args.get_one::<String>("goal").unwrap()).unwrap();

    let target = {
        if let Some(info) = hive.deployment_info_single(&hostname).await.unwrap() {
            let nix_options = hive.nix_flags_with_builders().await.unwrap();
            if !info.allows_local_deployment() {
                log::error!(
                    "Local deployment is not enabled for host {}.",
                    hostname.as_str()
                );
                log::error!("Hint: Set deployment.allowLocalDeployment to true.");
                quit::with_code(2);
            }
            let mut host = LocalHost::new(nix_options);
            if escalate_privileges {
                let command = info.privilege_escalation_command().to_owned();
                host.set_privilege_escalation_command(Some(command));
            }

            TargetNode::new(hostname.clone(), Some(host.upcast()), info.clone())
        } else {
            log::error!(
                "Host \"{}\" is not present in the Hive configuration.",
                hostname.as_str()
            );
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
        options.set_upload_keys(!local_args.get_flag("no-keys"));
        options
    };

    deployment.set_options(options);

    let (deployment, output) = tokio::join!(deployment.execute(), output.run_until_completion(),);

    deployment?;
    output?;

    Ok(())
}
