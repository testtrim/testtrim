// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use console::{Emoji, style};
use dashmap::DashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::{Log, warn};
use tracing::Subscriber;
use tracing::span::{Attributes, Id};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::ui::{RawUiInformation, UiStage};

static BUILD: Emoji<'_, '_> = Emoji("🔨  ", "");
static DISCOVER: Emoji<'_, '_> = Emoji("🔍  ", "");
static DATABASE: Emoji<'_, '_> = Emoji("🗃️  ", "");
static TARGET: Emoji<'_, '_> = Emoji("🎯  ", "");

#[derive(Default)]
struct SpanData {
    raw_ui_information: RawUiInformation,
    message_bar: Option<ProgressBar>,
    subcommand_bar: Option<ProgressBar>,
}

pub struct GetTestIdentifiersConsole {
    root: MultiProgress,
    ongoing_spans: DashMap<Id, SpanData>,
}

impl GetTestIdentifiersConsole {
    pub fn new<T: Log + 'static>(no_progress: bool, logger: T) -> Self {
        let root = MultiProgress::new();
        if no_progress {
            root.set_draw_target(ProgressDrawTarget::hidden());
        }
        LogWrapper::new(root.clone(), logger).try_init().unwrap();
        Self {
            root,
            ongoing_spans: DashMap::new(),
        }
    }
}

impl<S> Layer<S> for GetTestIdentifiersConsole
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    #[allow(clippy::literal_string_with_formatting_args)] // with_template looks like format args, but isn't
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let mut raw_ui_information = RawUiInformation::default();
        attrs.record(&mut raw_ui_information);

        let mut span_data = SpanData {
            raw_ui_information,
            ..SpanData::default()
        };

        if let Some(step) = &span_data.raw_ui_information.ui_stage {
            let progress_bar = ProgressBar::new_spinner();
            // Note: must add to the `MultiProgress` before calling any method on the bar which might cause a draw; so
            // we organize this code so that it's the first thing we do.
            let progress_bar = self.root.add(progress_bar);
            progress_bar.enable_steady_tick(std::time::Duration::from_millis(100));
            progress_bar.set_style(
                ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}] {msg}").unwrap(),
            );
            match step {
                UiStage::Compiling => {
                    progress_bar.set_message(format!(
                        "{} {BUILD}Compiling...",
                        style("[1/4]").bold().dim(),
                    ));
                }
                UiStage::ListingTests => {
                    progress_bar.set_message(format!(
                        "{} {DISCOVER}Listing test cases ...",
                        style("[2/4]").bold().dim(),
                    ));
                }
                UiStage::FindingAncestorCommit => {
                    progress_bar.set_message(format!(
                        "{} {DATABASE}Searching for ancestor commit with coverage data ...",
                        style("[3/4]").bold().dim(),
                    ));
                }
                UiStage::ComputeTestCases => {
                    progress_bar.set_message(format!(
                        "{} {TARGET}Computing test cases to execute ...",
                        style("[4/4]").bold().dim(),
                    ));
                }
                other => {
                    warn!("get-test-identifiers didn't expect to encounter ui_stage {other:?}");
                    self.root.remove(&progress_bar);
                    return;
                }
            };
            span_data.message_bar = Some(progress_bar);
        }

        if span_data.raw_ui_information.is_subcommand {
            let progress_bar = ProgressBar::new_spinner();
            // Note: must add to the `MultiProgress` before calling any method on the bar which might cause a draw; so
            // we organize this code so that it's the first thing we do.
            let progress_bar = self.root.add(progress_bar);
            progress_bar.enable_steady_tick(std::time::Duration::from_millis(100));
            progress_bar.set_style(
                ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}]     {msg}")
                    .unwrap(),
            );
            let mut msg: String = String::with_capacity(64);
            if let Some(bin) = &span_data.raw_ui_information.subcommand_binary {
                msg += bin;
            }
            if let Some(args) = &span_data.raw_ui_information.subcommand_args {
                msg += " ";
                if args.len() > 50 {
                    msg += &args[..50]; // snip to first 50 chars
                } else {
                    msg += args;
                }
            }
            progress_bar.set_message(msg);
            span_data.subcommand_bar = Some(progress_bar);
        }

        self.ongoing_spans.insert(id.clone(), span_data);
    }

    fn on_close(&self, id: Id, _ctx: Context<'_, S>) {
        let Some((_, span_data)) = self.ongoing_spans.remove(&id) else {
            return;
        };

        if let Some(subcommand_bar) = span_data.subcommand_bar {
            self.root.remove(&subcommand_bar);
        }

        if let Some(message_bar) = span_data.message_bar {
            // if stderr isn't a terminal then progress bar output will be suppressed, but I'd like to still get the timings
            // of each element displayed as completed:
            #[allow(clippy::print_stderr)]
            if !console::Term::stderr().is_term() {
                let elapsed = message_bar.elapsed();
                let msg = message_bar.message();
                eprintln!("{msg} [elapsed: {:.3}s]", elapsed.as_secs_f64());
            }
            message_bar.finish();
            // If we remove the progress bar from the MultiProgress, then the effect of `finish` (which is to leave the
            // last message) or `finish_with_msg` (not currently used but might be) is gone because the bar disappears.
            // That's probably not what I want... so I guess leave it?
            //
            // self.root.remove(&progress_bar);
        }
    }
}
