#![deny(unused_must_use)]

mod error;
mod nix;
mod cli;
mod command;
mod progress;
mod job;
mod troubleshooter;
mod util;

#[tokio::main]
async fn main() {
    cli::run().await;
}
