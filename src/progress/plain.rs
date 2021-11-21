//! Plain output.

use async_trait::async_trait;
use console::Style as ConsoleStyle;

use crate::nix::NixResult;
use super::{
    DEFAULT_LABEL_WIDTH,
    ProgressOutput,
    Sender,
    Receiver,
    Message,
    Line,
    LineStyle,
    create_channel,
};

pub struct PlainOutput {
    sender: Option<Sender>,
    receiver: Receiver,
    label_width: usize,
}

impl PlainOutput {
    pub fn new() -> Self {
        let (sender, receiver) = create_channel();

        Self {
            sender: Some(sender),
            receiver,
            label_width: DEFAULT_LABEL_WIDTH,
        }
    }

    fn print(&self, line: Line) {
        if line.noisy {
            return;
        }

        let label_style = match line.style {
            LineStyle::Normal => {
                ConsoleStyle::new().bold()
            }
            LineStyle::Success => {
                ConsoleStyle::new().bold().green()
            }
            LineStyle::SuccessNoop => {
                ConsoleStyle::new().bold().green().dim()
            }
            LineStyle::Failure => {
                ConsoleStyle::new().bold().red()
            }
        };

        let text_style = match line.style {
            LineStyle::Normal => {
                ConsoleStyle::new()
            }
            LineStyle::Success => {
                ConsoleStyle::new().green()
            }
            LineStyle::SuccessNoop => {
                ConsoleStyle::new().dim()
            }
            LineStyle::Failure => {
                ConsoleStyle::new().red()
            }
        };

        eprintln!("{:>width$} | {}",
            label_style.apply_to(line.label),
            text_style.apply_to(line.text),
            width = self.label_width,
        );
    }
}

#[async_trait]
impl ProgressOutput for PlainOutput {
    async fn run_until_completion(mut self) -> NixResult<Self> {
        loop {
            let message = self.receiver.recv().await;

            if message.is_none() {
                log::info!("All senders dropped");
                return Ok(self);
            }

            let message = message.unwrap();

            match message {
                Message::Complete => {
                    return Ok(self);
                }
                Message::Print(line) => {
                    self.print(line);
                }
                Message::PrintMeta(line) => {
                    self.print(line);
                }
                Message::HintLabelWidth(width) => {
                    if width > self.label_width {
                        self.label_width = width;
                    }
                }
            }
        }
    }

    fn get_sender(&mut self) -> Option<Sender> {
        self.sender.take()
    }
}
