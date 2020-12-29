use std::cmp::min;
use std::sync::Arc;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};
use futures::future::join_all;
use tokio::sync::Mutex;

use crate::nix::DeploymentTask;
use crate::progress::get_spinner_styles;

/// User-facing deploy routine
pub async fn deploy(tasks: Vec<DeploymentTask>, max_parallelism: Option<usize>, progress_bar: bool) {
    let parallelism = match max_parallelism {
        Some(limit) => {
            min(limit, tasks.len())
        }
        None => {
            tasks.len()
        }
    };

    let node_name_alignment = tasks.iter().map(|task| task.name().len()).max().unwrap();

    let multi = Arc::new(MultiProgress::new());
    let root_bar = Arc::new(multi.add(ProgressBar::new(tasks.len() as u64)));
    multi.set_draw_target(ProgressDrawTarget::stderr_nohz());

    {
        let (spinner_style, _) = get_spinner_styles(node_name_alignment);
        root_bar.set_message("Running...");
        root_bar.set_style(spinner_style);
        root_bar.inc(0);
    }

    let tasks = Arc::new(Mutex::new(tasks));
    let result_list: Arc<Mutex<Vec<(DeploymentTask, bool)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut futures = Vec::new();

    for _ in 0..parallelism {
        let tasks = tasks.clone();
        let result_list = result_list.clone();
        let multi = multi.clone();
        let (spinner_style, failing_spinner_style) = get_spinner_styles(node_name_alignment);

        let root_bar = root_bar.clone();

        let future = tokio::spawn(async move {
            // Perform tasks until there's none
            loop {
                let (task, remaining) = {
                    let mut tasks = tasks.lock().await;
                    let task = tasks.pop();
                    let remaining = tasks.len();
                    (task, remaining)
                };

                if task.is_none() {
                    // We are donzo!
                    return;
                }

                let mut task = task.unwrap();

                let bar = multi.add(ProgressBar::new(100));
                bar.set_style(spinner_style.clone());
                bar.set_prefix(task.name());
                bar.set_message("Starting...");
                bar.inc(0);

                if progress_bar {
                    task.set_progress_bar(bar.clone()).await;
                }

                match task.execute().await {
                    Ok(_) => {
                        bar.finish_with_message(task.goal().success_str().unwrap());

                        let mut result_list = result_list.lock().await;
                        result_list.push((task, true));
                    },
                    Err(_) => {
                        bar.set_style(failing_spinner_style.clone());
                        bar.abandon_with_message("Failed");

                        let mut result_list = result_list.lock().await;
                        result_list.push((task, false));
                    },
                }

                root_bar.inc(1);

                if remaining == 0 {
                    root_bar.finish_with_message("Finished");
                }
            }
        });

        futures.push(future);
    }

    if progress_bar {
        futures.push(tokio::task::spawn_blocking(move || {
            multi.join().unwrap();
        }));
    }

    join_all(futures).await;

    let mut result_list = result_list.lock().await;
    for (task, success) in result_list.drain(..) {
        if !success {
            let name = task.name().to_owned();
            let host = task.to_host().await;

            print!("Failed to deploy to {}. ", name);
            if let Some(logs) = host.dump_logs().await {
                if let Some(lines) = logs.chunks(10).rev().next() {
                    println!("Last {} lines of logs:", lines.len());
                    for line in lines {
                        println!("{}", line);
                    }
                } else {
                    println!("The log is empty.");
                }
            } else {
                println!("Logs are not available for this target.");
            }
        }
    }
}
