#![deny(unused_must_use)]

mod cli;
mod command;
mod error;
mod job;
mod nix;
mod progress;
mod troubleshooter;
mod util;

#[tokio::main]
#[quit::main]
async fn main() {
    cli::run().await;
}
