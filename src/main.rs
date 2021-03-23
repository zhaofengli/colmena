use std::env;

mod nix;
mod cli;
mod command;
mod progress;
mod util;

#[tokio::main]
async fn main() {
    init_logging();
    cli::run().await;
}

fn init_logging() {
    if env::var("RUST_LOG").is_err() {
        // HACK
        env::set_var("RUST_LOG", "info")
    }
    env_logger::builder()
        .format_timestamp(None)
        .format_module_path(false)
        .init();
}
