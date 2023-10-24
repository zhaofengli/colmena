use regex::Regex;
use std::collections::HashMap;

use clap::Args;
use tokio::fs;

use crate::error::ColmenaError;

use crate::nix::deployment::{Deployment, Goal, Options, TargetNode};
use crate::nix::Hive;
use crate::nix::{host::Local as LocalHost, NodeName};
use crate::progress::SimpleProgressOutput;

#[derive(Debug, Args)]
#[command(
    name = "apply-local",
    about = "Apply configurations on the local machine"
)]
pub struct Opts {
    #[arg(
        help = "Deployment goal",
        value_name = "GOAL",
        default_value_t,
        long_help = "Same as the targets for switch-to-configuration.\n\"push\" is noop in apply-local."
    )]
    goal: Goal,
    #[arg(long, help = "Attempt to escalate privileges if not run as root")]
    sudo: bool,
    #[arg(
        short,
        long,
        help = "Be verbose",
        long_help = "Deactivates the progress spinner and prints every line of output."
    )]
    verbose: bool,
    #[arg(
        long,
        help = "Do not deploy keys",
        long_help = r#"Do not deploy secret keys set in `deployment.keys`.

By default, Colmena will deploy keys set in `deployment.keys` before activating the profile on this host.
"#
    )]
    no_keys: bool,
    #[arg(long, help = "Override the node name to use")]
    node: Option<String>,
    #[arg(
        long,
        value_name = "COMMAND",
        hide = true,
        help = "Removed: Configure deployment.privilegeEscalationCommand in node configuration"
    )]
    sudo_command: Option<String>,
}

pub async fn run(
    hive: Hive,
    Opts {
        goal,
        sudo,
        verbose,
        no_keys,
        node,
        sudo_command,
    }: Opts,
) -> Result<(), ColmenaError> {
    if sudo_command.is_some() {
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

    let verbose = verbose || sudo; // cannot use spinners with interactive sudo

    {
        let euid: u32 = unsafe { libc::geteuid() };
        if euid != 0 && !sudo {
            log::warn!("Colmena was not started by root. This is probably not going to work.");
            log::warn!("Hint: Add the --sudo flag.");
        }
    }

    let hostname = NodeName::new(node.unwrap_or_else(|| {
        hostname::get()
            .expect("Could not get hostname")
            .to_string_lossy()
            .into_owned()
    }))?;

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
            if sudo {
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
        options.set_upload_keys(!no_keys);
        options
    };

    deployment.set_options(options);

    let (deployment, output) = tokio::join!(deployment.execute(), output.run_until_completion());

    deployment?;
    output?;

    Ok(())
}
