//! Automatic troubleshooter.
//!
//! Tries to provide some useful hints when things go wrong.

use std::env;
use std::future::Future;

use snafu::ErrorCompat;

use crate::error::ColmenaError;

/// Runs a closure and tries to troubleshoot if it returns an error.
pub async fn run_wrapped<F, T>(f: F) -> T
where
    F: Future<Output = Result<T, ColmenaError>>,
{
    match f.await {
        Ok(r) => r,
        Err(error) => {
            tracing::error!("-----");
            tracing::error!("Operation failed with error: {}", error);

            if let Err(own_error) = troubleshoot(&error) {
                tracing::error!(
                    "Error occurred while trying to troubleshoot another error: {}",
                    own_error
                );
            }

            // Ensure we exit with a code
            quit::with_code(1);
        }
    }
}

fn troubleshoot(error: &ColmenaError) -> Result<(), ColmenaError> {
    if let Some(bt) = ErrorCompat::backtrace(error) {
        if backtrace_enabled() {
            eprintln!("Backtrace:");
            eprint!("{:?}", bt);
        } else {
            eprintln!(
                "Hint: Backtrace available - Use `RUST_BACKTRACE=1` environment variable to display a backtrace"
            );
        }
    }

    Ok(())
}

fn backtrace_enabled() -> bool {
    matches!(env::var("RUST_BACKTRACE"), Ok(backtrace_conf) if backtrace_conf != "0")
}
