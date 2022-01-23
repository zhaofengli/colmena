//! nix-eval-jobs evaluator.
//!
//! This evaluator can evaluate attributes in parallel.
//!
//! During build time, the nix-eval-jobs binary may be pinned by setting
//! the `NIX_EVAL_JOBS` environment variable.

use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use async_stream::stream;
use async_trait::async_trait;
use futures::Stream;
use serde::Deserialize;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::error::{ColmenaResult, ColmenaError};
use crate::job::{JobHandle, null_job_handle};
use crate::nix::{StorePath, NixExpression, NixOptions};
use crate::util::capture_stream;
use super::{DrvSetEvaluator, EvalResult, EvalError, AttributeOutput, AttributeError};

/// The pinned nix-eval-jobs binary.
pub const NIX_EVAL_JOBS: Option<&str> = option_env!("NIX_EVAL_JOBS");

pub struct NixEvalJobs {
    executable: PathBuf,
    job: JobHandle,
}

/// A line in the eval output.
#[derive(Deserialize)]
#[serde(untagged)]
enum EvalLine {
    Derivation(EvalLineDerivation),
    Error(EvalLineAttributeError),
}

/// An output from nix-eval-jobs.
///
/// This is nix-eval-jobs's version of `AttributeOutput`.
#[derive(Deserialize)]
struct EvalLineDerivation {
    #[serde(rename = "attr")]
    attribute: String,

    #[serde(rename = "drvPath")]
    drv_path: StorePath,
}

/// An error from nix-eval-jobs.
///
/// This is nix-eval-jobs's version of `AttributeError`.
#[derive(Deserialize)]
struct EvalLineAttributeError {
    #[serde(rename = "attr")]
    attribute: String,

    #[serde(rename = "error")]
    error: String,
}

#[async_trait]
impl DrvSetEvaluator for NixEvalJobs {
    async fn evaluate(&self, expression: &dyn NixExpression, options: NixOptions) -> ColmenaResult<Pin<Box<dyn Stream<Item = EvalResult>>>> {
        let expr_file = {
            let mut f = NamedTempFile::new()?;
            f.write_all(expression.expression().as_bytes())?;
            f.into_temp_path()
        };

        let mut command = Command::new(&self.executable);
        command
            .arg("--impure")
            .args(&["--workers", "10"]) // FIXME: Configurable
            .arg(&expr_file);

        command.args(options.to_args());

        if expression.requires_flakes() {
            command.args(&["--experimental-features", "flakes"]);
        }

        let mut child = command
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let stderr = BufReader::new(child.stderr.take().unwrap());

        let job = self.job.clone();
        tokio::spawn(async move {
            capture_stream(stderr, Some(job), true).await
        });

        Ok(Box::pin(stream! {
            loop {
                let mut line = String::new();
                let len = {
                    let r = stdout.read_line(&mut line).await
                        .map_err(|e| EvalError::Global(e.into()));

                    match r {
                        Ok(v) => v,
                        Err(e) => {
                            yield Err(e);
                            break;
                        }
                    }
                };

                if len == 0 {
                    // Stream ended, wait for exit code
                    let r = child.wait().await
                        .map_err(|e| EvalError::Global(e.into()));

                    let status = match r {
                        Ok(v) => v,
                        Err(e) => {
                            yield Err(e);
                            break;
                        }
                    };

                    if !status.success() {
                        yield Err(EvalError::Global(status.into()));
                    }

                    break;
                }

                let trimmed = line.trim();
                match serde_json::from_str::<EvalLine>(trimmed) {
                    Ok(el) => {
                        yield el.into();
                    }
                    Err(e) => {
                        let bad_output = ColmenaError::BadOutput {
                            output: e.to_string(),
                        };

                        yield Err(EvalError::Global(bad_output));
                        break;
                    }
                }
            }

            drop(expr_file);
        }))
    }

    fn set_job(&mut self, job: JobHandle) {
        self.job = job;
    }
}

impl Default for NixEvalJobs {
    fn default() -> Self {
        let binary = NIX_EVAL_JOBS.unwrap_or("nix-eval-jobs");

        Self {
            executable: PathBuf::from(binary),
            job: null_job_handle(),
        }
    }
}

impl From<EvalLineDerivation> for AttributeOutput {
    fn from(eld: EvalLineDerivation) -> Self {
        Self {
            attribute: eld.attribute,
            drv_path: eld.drv_path,
        }
    }
}

impl From<EvalLineAttributeError> for AttributeError {
    fn from(ele: EvalLineAttributeError) -> Self {
        Self {
            attribute: ele.attribute,
            error: ele.error,
        }
    }
}

impl From<EvalLine> for EvalResult {
    fn from(el: EvalLine) -> Self {
        match el {
            EvalLine::Derivation(eld) => Ok(eld.into()),
            EvalLine::Error(ele) => Err(EvalError::Attribute(ele.into())),
        }
    }
}

/// Returns the pinned nix-eval-jobs executable.
///
/// This is used for informational purposes in `colmena nix-info`.
pub fn get_pinned_nix_eval_jobs() -> Option<&'static str> {
    NIX_EVAL_JOBS
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_test::block_on;
    use tokio_stream::StreamExt;

    #[test]
    fn test_eval() {
        let evaluator = NixEvalJobs::default();
        let expr = r#"with import <nixpkgs> {}; { a = pkgs.hello; b = pkgs.bash; }"#.to_string();

        block_on(async move {
            let mut stream = evaluator.evaluate(&expr, NixOptions::default()).await.unwrap();
            let mut count = 0;

            while let Some(value) = stream.next().await {
                eprintln!("Got {:?}", value);
                assert!(value.is_ok());

                count += 1;
            }

            assert_eq!(2, count);
        });
    }

    #[test]
    fn test_global_error() {
        let evaluator = NixEvalJobs::default();
        let expr = r#"gibberish"#.to_string();

        block_on(async move {
            let mut stream = evaluator.evaluate(&expr, NixOptions::default()).await.unwrap();
            let mut count = 0;

            while let Some(value) = stream.next().await {
                eprintln!("Got {:?}", value);
                assert!(value.is_err());
                count += 1;
            }

            assert_eq!(1, count);
        });
    }

    #[test]
    fn test_attribute_error() {
        let evaluator = NixEvalJobs::default();
        let expr = r#"with import <nixpkgs> {}; { a = pkgs.hello; b = throw "an error"; }"#.to_string();

        block_on(async move {
            let mut stream = evaluator.evaluate(&expr, NixOptions::default()).await.unwrap();
            let mut count = 0;

            while let Some(value) = stream.next().await {
                eprintln!("Got {:?}", value);

                match value {
                    Ok(v) => {
                        assert_eq!("a", v.attribute);
                    }
                    Err(e) => {
                        match e {
                            EvalError::Attribute(a) => {
                                assert_eq!("b", a.attribute);
                            }
                            _ => {
                                panic!("Expected an attribute error, got {:?}", e);
                            }
                        }
                    }
                }
                count += 1;
            }

            assert_eq!(2, count);
        });
    }
}
