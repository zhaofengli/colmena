use itertools::Itertools;

use crate::{
    error::ColmenaError,
    nix::{node_filter::NodeFilterOpts, Hive},
};
use clap::Args;
use serde::Serialize;

#[derive(Debug, Args)]
#[command(name = "list", about = "List nodes in the Hive")]
pub struct Opts {
    #[arg(long, help = "Output node list in JSON format")]
    json: bool,

    #[command(flatten)]
    node_filter: NodeFilterOpts,
}

#[derive(Debug, Serialize)]
struct Row {
    name: String,
    ssh_host: Option<String>,
    tags: Vec<String>,
}

impl Row {
    fn table_tags(&self) -> String {
        format!("[{}]", self.tags.join(", "))
    }

    fn table_ssh_host(&self) -> String {
        self.ssh_host
            .clone()
            .unwrap_or_else(|| "[no host]".to_owned())
    }

    fn table_name(&self) -> String {
        self.name.clone()
    }
}

pub async fn run(hive: Hive, opts: Opts) -> Result<(), ColmenaError> {
    let targets = hive
        .select_nodes(opts.node_filter.on.clone(), None, false)
        .await?;

    let rows = targets
        .values()
        .sorted_by(|node1, node2| node1.name().cmp(&node2.name()))
        .map(|node| Row {
            name: node.name().to_owned(),
            ssh_host: node
                .config()
                .to_ssh_host()
                .map(|ssh_host| ssh_host.ssh_target()),
            tags: node.config().tags().to_vec(),
        })
        .collect::<Vec<_>>();

    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).expect("Failed to serialize nodes")
        );
        return Ok(());
    } else {
        let max_name_len = rows
            .iter()
            .map(|row| row.table_name().len())
            .max()
            .unwrap_or(0);
        let max_ssh_host_len = rows
            .iter()
            .map(|row| row.table_ssh_host().len())
            .max()
            .unwrap_or(0);
        let max_tags_len = rows
            .iter()
            .map(|row| row.table_tags().len())
            .max()
            .unwrap_or(0);

        for row in rows {
            println!(
                "{:max_name_len$} {:max_ssh_host_len$} {:max_tags_len$}",
                row.table_name(),
                row.table_ssh_host(),
                row.table_tags(),
            );
        }
    }

    Ok(())
}
