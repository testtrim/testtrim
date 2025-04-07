// SPDX-FileCopyrightText: 2025 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Mutex;

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
static TEST: Emoji<'_, '_> = Emoji("🧪  ", "");
static WRITE_DB: Emoji<'_, '_> = Emoji("📝  ", "");

#[derive(Default)]
struct SpanData {
    raw_ui_information: RawUiInformation,
    message_bar: Option<ProgressBar>,
    subcommand_bar: Option<ProgressBar>,
    was_test: bool,
}

pub struct RunTestsConsole {
    root: MultiProgress,
    ongoing_spans: DashMap<Id, SpanData>,
    run_tests: Mutex<Option<ProgressBar>>,
}

impl RunTestsConsole {
    pub fn new<T: Log + 'static>(no_progress: bool, logger: T) -> Self {
        let root = MultiProgress::new();
        if no_progress {
            root.set_draw_target(ProgressDrawTarget::hidden());
        }
        LogWrapper::new(root.clone(), logger).try_init().unwrap();
        Self {
            root,
            ongoing_spans: DashMap::new(),
            run_tests: Mutex::new(None),
        }
    }
}

impl<S> Layer<S> for RunTestsConsole
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
            progress_bar.enable_steady_tick(std::time::Duration::from_millis(250));
            progress_bar.set_style(
                ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}] {msg}").unwrap(),
            );
            match step {
                UiStage::Compiling => {
                    progress_bar.set_message(format!(
                        "{} {BUILD}Compiling...",
                        style("[1/6]").bold().dim(),
                    ));
                }
                UiStage::ListingTests => {
                    progress_bar.set_message(format!(
                        "{} {DISCOVER}Listing test cases ...",
                        style("[2/6]").bold().dim(),
                    ));
                }
                UiStage::FindingAncestorCommit => {
                    progress_bar.set_message(format!(
                        "{} {DATABASE}Searching for ancestor commit with coverage data ...",
                        style("[3/6]").bold().dim(),
                    ));
                }
                UiStage::ComputeTestCases => {
                    progress_bar.set_message(format!(
                        "{} {TARGET}Computing test cases to execute ...",
                        style("[4/6]").bold().dim(),
                    ));
                }
                UiStage::RunTests => {
                    // FIXME: maybe? make this progress bar appear at the bottom of the MultiProcess, even if RunSingleTest starts
                    progress_bar.set_message(format!(
                        "{} {TEST}Running tests ...",
                        style("[5/6]").bold().dim(),
                    ));
                    if let Some(test_count) = span_data.raw_ui_information.test_count {
                        progress_bar.set_length(test_count);
                        progress_bar.set_style(
                            ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}] {msg} {wide_bar:.cyan/blue} {pos}/{len}").unwrap(),
                        );
                    }
                    let mut run_tests = self.run_tests.lock().unwrap();
                    *run_tests = Some(progress_bar.clone());
                }
                UiStage::RunSingleTest => {
                    if let Some(test_case) = &span_data.raw_ui_information.test_case {
                        progress_bar.set_message(format!(
                            "          {} ...",
                            style(test_case).bold().dim()
                        ));
                    } else {
                        progress_bar.set_message(format!(
                            "          {} ...",
                            style("Unknown test").bold().dim()
                        ));
                    }
                    span_data.was_test = true;
                }
                UiStage::WriteCoverageData => {
                    // FIXME: add WriteCoverageData instrumentation to cmd
                    progress_bar.set_message(format!(
                        "{} {WRITE_DB}Writing coverage data to DB ...",
                        style("[6/6]").bold().dim(),
                    ));
                }
                other => {
                    warn!("run-tests didn't expect to encounter ui_stage {other:?}");
                    self.root.remove(&progress_bar);
                    return;
                }
            }
            span_data.message_bar = Some(progress_bar);
        }

        if span_data.raw_ui_information.is_subcommand {
            let progress_bar = ProgressBar::new_spinner();
            // Note: must add to the `MultiProgress` before calling any method on the bar which might cause a draw; so
            // we organize this code so that it's the first thing we do.
            let progress_bar = self.root.add(progress_bar);
            progress_bar.enable_steady_tick(std::time::Duration::from_millis(100));
            progress_bar.set_style(
                ProgressStyle::with_template(
                    "{spinner:.blue} [{elapsed_precise}]             cmd: {msg}",
                )
                .unwrap(),
            );
            let mut msg: String = String::with_capacity(64);
            if let Some(bin) = &span_data.raw_ui_information.subcommand_binary {
                msg += bin;
            }
            if let Some(args) = &span_data.raw_ui_information.subcommand_args {
                msg += " ";
                let substr = args.chars().take(50).collect::<String>();
                msg.push_str(&substr);
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
            if span_data.was_test {
                // Don't keep "Run test" bars around as multiple of these are run concurrently in batches.  Once
                // completed remove them.
                self.root.remove(&message_bar);
            } else {
                // `finish()` leaves the bar completed but visible in the MultiProgress.
                message_bar.finish();
            }
        }

        if span_data.was_test {
            let run_tests = self.run_tests.lock().unwrap();
            if let Some(run_tests) = &*run_tests {
                run_tests.inc(1);
            }
        }
    }
}
