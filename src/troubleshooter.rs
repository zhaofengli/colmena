//! Automatic troubleshooter.
//!
//! Tries to provide some useful hints when things go wrong.

use std::env;
use std::future::Future;

use clap::{parser::ValueSource as ClapValueSource, ArgMatches};
use snafu::ErrorCompat;

use crate::error::ColmenaError;

/// Runs a closure and tries to troubleshoot if it returns an error.
pub async fn run_wrapped<'a, F, U, T>(
    global_args: &'a ArgMatches,
    local_args: &'a ArgMatches,
    f: U,
) -> T
where
    U: FnOnce(&'a ArgMatches, &'a ArgMatches) -> F,
    F: Future<Output = Result<T, ColmenaError>>,
{
    match f(global_args, local_args).await {
        Ok(r) => r,
        Err(error) => {
            log::error!("-----");
            log::error!("Operation failed with error: {}", error);

            if let Err(own_error) = troubleshoot(global_args, local_args, &error) {
                log::error!(
                    "Error occurred while trying to troubleshoot another error: {}",
                    own_error
                );
            }

            // Ensure we exit with a code
            quit::with_code(1);
        }
    }
}

fn troubleshoot(
    global_args: &ArgMatches,
    _local_args: &ArgMatches,
    error: &ColmenaError,
) -> Result<(), ColmenaError> {
    if let ColmenaError::NoFlakesSupport = error {
        // People following the tutorial might put hive.nix directly
        // in their Colmena checkout, and encounter NoFlakesSupport
        // because Colmena always prefers flake.nix when it exists.

        if let Some(ClapValueSource::DefaultValue) = global_args.value_source("config") {
            let cwd = env::current_dir()?;
            if cwd.join("flake.nix").is_file() && cwd.join("hive.nix").is_file() {
                eprintln!(
                    "Hint: You have both flake.nix and hive.nix in the current directory, and"
                );
                eprintln!("      Colmena will always prefer flake.nix if it exists.");
                eprintln!();
                eprintln!("      Try passing `-f hive.nix` explicitly if this is what you want.");
            }
        };
    }

    if let Some(bt) = ErrorCompat::backtrace(error) {
        if backtrace_enabled() {
            eprintln!("Backtrace:");
            eprint!("{:?}", bt);
        } else {
            eprintln!("Hint: Backtrace available - Use `RUST_BACKTRACE=1` environment variable to display a backtrace");
        }
    }

    Ok(())
}

fn backtrace_enabled() -> bool {
    match env::var("RUST_BACKTRACE") {
        Ok(backtrace_conf) => backtrace_conf != "0",
        _ => false,
    }
}
