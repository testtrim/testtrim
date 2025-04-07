// SPDX-FileCopyrightText: 2025 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Mutex;

use console::{Emoji, style};
use dashmap::DashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::Log;
use tracing::Subscriber;
use tracing::span::{Attributes, Id};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::ui::{RawUiInformation, UiStage};

static BUILD: Emoji<'_, '_> = Emoji("🔨  ", "");
static TRASH: Emoji<'_, '_> = Emoji("🗑️  ", "");
static TARGET: Emoji<'_, '_> = Emoji("🎯  ", "");
static TEST: Emoji<'_, '_> = Emoji("🧪  ", "");
static COMMITS: Emoji<'_, '_> = Emoji("🗃️  ", "");

#[derive(Default)]
struct SpanData {
    raw_ui_information: RawUiInformation,
    message_bar: Option<ProgressBar>,
    subcommand_bar: Option<ProgressBar>,
    // pretty dumb relative to using an enum... or making these "behavior" flags rather than "what is was" flags.
    hide_when_finished: bool,
    was_simulate_commit: bool,
    was_test: bool,
}

pub struct SimulateHistoryConsole {
    root: MultiProgress,
    ongoing_spans: DashMap<Id, SpanData>,
    simulate_commits: Mutex<Option<ProgressBar>>,
    run_tests: Mutex<Option<ProgressBar>>,
}

impl SimulateHistoryConsole {
    pub fn new<T: Log + 'static>(no_progress: bool, logger: T) -> Self {
        let root = MultiProgress::new();
        if no_progress {
            root.set_draw_target(ProgressDrawTarget::hidden());
        }
        LogWrapper::new(root.clone(), logger).try_init().unwrap();
        Self {
            root,
            ongoing_spans: DashMap::new(),
            simulate_commits: Mutex::new(None),
            run_tests: Mutex::new(None),
        }
    }
}

impl<S> Layer<S> for SimulateHistoryConsole
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
            let make_progress_bar = || {
                let progress_bar = ProgressBar::new_spinner();
                // Note: must add to the `MultiProgress` before calling any method on the bar which might cause a draw; so
                // we organize this code so that it's the first thing we do.
                let progress_bar = self.root.add(progress_bar);
                progress_bar.enable_steady_tick(std::time::Duration::from_millis(250));
                progress_bar.set_style(
                    ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}] {msg}")
                        .unwrap(),
                );
                progress_bar
            };
            let mut progress_bar: Option<ProgressBar> = None;
            match step {
                // Too detailed for simulate history:
                UiStage::ListingTests
                | UiStage::FindingAncestorCommit
                | UiStage::ComputeTestCases
                | UiStage::WriteCoverageData => {}

                UiStage::ClearProjectData => {
                    let internal = make_progress_bar();
                    internal.set_message(format!(
                        "{} {TRASH}Clearing project data ...",
                        style("[1/3]").bold().dim(),
                    ));
                    progress_bar = Some(internal);
                }
                UiStage::IdentifyTestCommits => {
                    let internal = make_progress_bar();
                    internal.set_message(format!(
                        "{} {TARGET}Identifying target commits for simulation ...",
                        style("[2/3]").bold().dim(),
                    ));
                    progress_bar = Some(internal);
                }
                UiStage::SimulateCommits => {
                    let internal = make_progress_bar();
                    internal.set_message(format!(
                        "{} {COMMITS}Simulating commits ...",
                        style("[3/3]").bold().dim(),
                    ));
                    if let Some(commit_count) = span_data.raw_ui_information.commit_count {
                        internal.set_length(commit_count);
                        internal.set_style(
                            ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}] {msg} {wide_bar:.red/red} {pos}/{len}").unwrap(),
                        );
                    }
                    let mut simulate_commits = self.simulate_commits.lock().unwrap();
                    *simulate_commits = Some(internal.clone());
                    progress_bar = Some(internal);
                }
                UiStage::SimulateSingleCommit => {
                    let internal = make_progress_bar();
                    if let Some(commit_identifier) = &span_data.raw_ui_information.commit_identifier
                    {
                        internal.set_message(format!(
                            "          Simulating {} ...",
                            style(commit_identifier).bold().dim()
                        ));
                    } else {
                        internal.set_message(format!(
                            "          Simulating {} ...",
                            style("Unknown commit?").bold().dim()
                        ));
                    }
                    span_data.hide_when_finished = true;
                    span_data.was_simulate_commit = true;
                    progress_bar = Some(internal);
                }
                UiStage::Compiling => {
                    let internal = make_progress_bar();
                    internal.set_message(format!("        {BUILD}Compiling...",));
                    progress_bar = Some(internal);
                    span_data.hide_when_finished = true;
                }
                UiStage::RunTests => {
                    let internal = make_progress_bar();
                    internal.set_message(format!("        {TEST}Running tests ...",));
                    if let Some(test_count) = span_data.raw_ui_information.test_count {
                        internal.set_length(test_count);
                        internal.set_style(
                            ProgressStyle::with_template("{spinner:.blue} [{elapsed_precise}] {msg} {wide_bar:.cyan/blue} {pos}/{len}").unwrap(),
                        );
                    }
                    let mut run_tests = self.run_tests.lock().unwrap();
                    *run_tests = Some(internal.clone());
                    progress_bar = Some(internal);
                    span_data.hide_when_finished = true;
                }
                UiStage::RunSingleTest => {
                    span_data.hide_when_finished = true;
                    span_data.was_test = true;
                }
            }
            span_data.message_bar = progress_bar;
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
            if span_data.hide_when_finished {
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

        if span_data.was_simulate_commit {
            let simulate_commits = self.simulate_commits.lock().unwrap();
            if let Some(simulate_commits) = &*simulate_commits {
                simulate_commits.inc(1);
            }
        }
    }
}
