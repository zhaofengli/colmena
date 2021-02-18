//! Progress display utilities.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use atty::Stream;
use console::Style;
use futures::join;

use indicatif::{
    MultiProgress,
    ProgressStyle as IndicatifStyle,
    ProgressBar as IndicatifBar,
};

pub fn get_spinner_styles(label_width: usize) -> (IndicatifStyle, IndicatifStyle) {
    let template = format!("{{prefix:>{}.bold.dim}} {{spinner}} {{elapsed}} {{wide_msg}}", label_width);

    (
        IndicatifStyle::default_spinner()
        .tick_chars("🕛🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚✅")
        .template(&template),

        IndicatifStyle::default_spinner()
        .tick_chars("❌❌")
        .template(&template),
    )
}

pub enum OutputStyle {
    /// Show condensed progress bars with fancy spinners.
    ///
    /// Not usable in a non-interactive environment.
    Condensed,

    /// Output log lines directly to console.
    Plain,
}

/// Parallel progress display.
///
/// Currently a simple wrapper over MultiProgress.
/// Sometimes we need to log directly to the console, in case
/// stdout is not connected to a TTY or the user requests
/// verbose logging via `--verbose`.
///
/// This is normally only usable as Arc<Progress>.
pub struct Progress {
    multi: Option<Arc<MultiProgress>>, // eww

    /// Width of the labels for alignment
    label_width: usize,
}

impl Progress {
    pub fn with_style(output_style: OutputStyle) -> Self {
        let multi = match output_style {
            OutputStyle::Condensed => Some(Arc::new(Self::init_multi())),
            OutputStyle::Plain => None,
        };

        Self {
            multi,
            label_width: 10,
        }
    }

    pub fn set_label_width(&mut self, width: usize) {
        self.label_width = width;
    }

    /// Returns a handle for a task to display progress information.
    pub fn create_task_progress(&self, label: String) -> TaskProgress {
        let mut progress = TaskProgress::new(label.clone(), self.label_width);

        if let Some(multi) = self.multi.as_ref() {
            let bar = multi.add(IndicatifBar::new(100));
            let (style, _) = get_spinner_styles(self.label_width);
            bar.set_prefix(&label);
            bar.set_style(style);
            bar.enable_steady_tick(100);

            progress.set_bar(bar);
        }

        progress
    }

    /// Runs code that may initate multiple tasks.
    pub async fn run<F: Future, U>(self: Arc<Self>, func: U) -> F::Output
        where U: FnOnce(Arc<Progress>) -> F
    {
        if let Some(multi) = self.multi.as_ref() {
            let multi = multi.clone();
            let finished = Arc::new(AtomicBool::new(false));

            let redraw_future = {
                let finished = finished.clone();
                tokio::task::spawn_blocking(move || {
                    while !finished.load(Ordering::SeqCst) {
                        multi.join().unwrap();
                        thread::sleep(Duration::from_millis(100));
                    }
                    multi.join().unwrap();
                })
            };
            let func_future = {
                let finished = finished.clone();
                async move {
                    let result = func(self).await;
                    finished.store(true, Ordering::SeqCst);
                    // root_bar.finish_and_clear();
                    result
                }
            };

            let (func_result, _) = join!(func_future, redraw_future);
            func_result
        } else {
            // Plain output. Simple.
            func(self.clone()).await
        }
    }

    fn init_multi() -> MultiProgress {
        let multi = MultiProgress::new();
        multi
    }

    fn detect_output() -> OutputStyle {
        if atty::is(Stream::Stdout) {
            OutputStyle::Condensed
        } else {
            OutputStyle::Plain
        }
    }
}

impl Default for Progress {
    fn default() -> Self {
        let style = Self::detect_output();
        Self::with_style(style)
    }
}

/// Progress display for a single task.
#[derive(Debug, Clone)]
pub struct TaskProgress {
    label: String,
    label_width: usize,
    bar: Option<IndicatifBar>,
    quiet: bool,
}

impl TaskProgress {
    pub fn new(label: String, label_width: usize) -> Self {
        Self {
            label,
            label_width,
            bar: None,
            quiet: false,
        }
    }

    fn set_bar(&mut self, bar: IndicatifBar) {
        self.bar = Some(bar);
    }

    /// Displays a new line of log.
    pub fn log(&mut self, message: &str) {
        if self.quiet {
            return;
        }

        if let Some(bar) = self.bar.as_ref() {
            bar.set_message(message);
        } else {
            let style = Style::new().bold();
            self.plain_print(style, message);
        }
    }

    /// Marks the task as successful and leave the spinner intact.
    pub fn success(self, message: &str) {
        if self.quiet {
            return;
        }

        if let Some(bar) = self.bar.as_ref() {
            bar.finish_with_message(message);
        } else {
            let style = Style::new().bold().green();
            self.plain_print(style, message);
        }
    }

    /// Marks the task as successful and remove the spinner.
    pub fn success_quiet(self) {
        if self.quiet {
            return;
        }

        if let Some(bar) = self.bar.as_ref() {
            bar.finish_and_clear();
        }
    }

    /// Marks the task as unsuccessful.
    pub fn failure(self, message: &str) {
        if self.quiet {
            return;
        }

        if let Some(bar) = self.bar.as_ref() {
            let (_, fail_style) = get_spinner_styles(self.label_width);
            bar.set_style(fail_style);
            bar.abandon_with_message(message);
        } else {
            let style = Style::new().bold().red();
            self.plain_print(style, message);
        }
    }

    pub fn failure_err<E: std::error::Error>(self, error: &E) {
        self.failure(&error.to_string())
    }

    fn plain_print(&self, style: Style, line: &str) {
        eprintln!("{:>width$} | {}", style.apply_to(&self.label), line, width = self.label_width);
    }
}

impl Default for TaskProgress {
    /// Creates a TaskProgress that does nothing.
    fn default() -> Self {
        Self {
            label: String::new(),
            label_width: 0,
            bar: None,
            quiet: true,
        }
    }
}
