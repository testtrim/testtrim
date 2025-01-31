// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use dashmap::DashMap;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{
    Metadata,
    field::Visit,
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context};

use crate::util::duration_to_seconds;

#[derive(Debug)]
struct SpanData {
    perftrace: Option<String>,
    entered_at: Option<Instant>,
    exited_at: Option<Instant>,
}

impl Visit for SpanData {
    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "perftrace" {
            self.perftrace = Some(String::from(value));
        }
    }
}

pub struct PerformanceStorage {
    span_storage: DashMap<Id, SpanData>,
}

#[derive(Serialize)]
pub struct RunTestTiming {
    /// Time spent compiling project and discovering currently available tests.
    #[serde(serialize_with = "duration_to_seconds")]
    pub discover_tests: Duration,
    /// Time spent finding the ancestor commit and reading coverage data from DB.
    #[serde(serialize_with = "duration_to_seconds")]
    pub read_historical_coverage_data: Duration,
    /// Time spent figuring out which tests to execute.
    #[serde(serialize_with = "duration_to_seconds")]
    pub test_determination: Duration,
    /// Time spent figuring out more tests via platform-specific means (eg. external dependencies).
    #[serde(serialize_with = "duration_to_seconds")]
    pub addt_platform_specific_test_determination: Duration,
    /// Time spent running tests; note that this is cumulative time across concurrent test runners, not wall-clock time.
    #[serde(serialize_with = "duration_to_seconds")]
    pub run_tests: Duration,
    /// Time spent reading newly output coverage data after a test run; note that this is cumulative time across
    /// concurrent test runners, not wall-clock time.
    #[serde(serialize_with = "duration_to_seconds")]
    pub read_new_coverage_data: Duration,
    /// Time spent writing new coverage data to the DB.
    #[serde(serialize_with = "duration_to_seconds")]
    pub write_new_coverage_data: Duration,
}

impl Default for PerformanceStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceStorage {
    #[must_use]
    pub fn new() -> Self {
        PerformanceStorage {
            span_storage: DashMap::new(),
        }
    }

    pub fn clear(&self) {
        self.span_storage.clear();
    }

    /// For every span marked with perftrace, accumulate all the time in those spans by their perftrace value.
    ///
    /// If spans were executed in parallel, the cumulative time of each parallel task will be counted separately.  eg. 5
    /// parallel 1 second tasks would show 5 seconds of cumulative time.
    fn aggregate_cumulative_time(&self) -> HashMap<String, Duration> {
        let mut accumulated_time: HashMap<String, Duration> = HashMap::new();
        for thingy in &self.span_storage {
            if let (Some(perftrace), Some(entered_at), Some(exited_at)) =
                (&thingy.perftrace, &thingy.entered_at, &thingy.exited_at)
            {
                let addt_duration = exited_at.duration_since(*entered_at);

                match accumulated_time.get(perftrace) {
                    Some(duration) => {
                        accumulated_time
                            .insert(perftrace.clone(), duration.saturating_add(addt_duration));
                    }
                    None => {
                        accumulated_time.insert(perftrace.clone(), addt_duration);
                    }
                }
            }
        }
        accumulated_time
    }

    #[allow(clippy::print_stdout)]
    pub fn print(&self) {
        let accumulated_time = self.aggregate_cumulative_time();
        for (trace, duration) in &accumulated_time {
            println!("{trace}: {} s", duration.as_secs_f64());
        }
    }

    #[must_use]
    pub fn interpret_run_test_timing(&self) -> RunTestTiming {
        let accumulated_time = self.aggregate_cumulative_time();
        let m = |str: &str| *accumulated_time.get(str).unwrap_or(&Duration::ZERO);
        //   - perftrace="discover-tests" -- discover tests / build
        //   - perftrace="read-coverage-data" -- find ancestor commit and read coverage data
        //   - perftrace="analyze-tests-to-run" -- figure out which tests to run
        //   - perftrace="platform-specific-test-cases" -- analyze coverage data for ext. dependencies
        //   - perftrace="run-test" -- run tests
        //   - perftrace="parse-test-data" -- parse coverage data
        //   - perftrace="write-coverage-data" -- write coverage data after test run
        RunTestTiming {
            discover_tests: m("discover-tests"),
            read_historical_coverage_data: m("read-coverage-data"),
            test_determination: m("analyze-tests-to-run"),
            addt_platform_specific_test_determination: m("platform-specific-test-cases"),
            run_tests: m("run-test"),
            read_new_coverage_data: m("parse-test-data"),
            write_new_coverage_data: m("write-coverage-data"),
        }
    }
}

pub struct PerformanceStoringLayer {
    storage: Arc<PerformanceStorage>,
}

impl PerformanceStoringLayer {
    #[must_use]
    pub fn new(storage: Arc<PerformanceStorage>) -> Self {
        PerformanceStoringLayer { storage }
    }
}

impl<S> Layer<S> for PerformanceStoringLayer
where
    S: tracing::Subscriber,
{
    fn enabled(&self, _metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        true
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let mut span_data = SpanData {
            perftrace: None,
            entered_at: None,
            exited_at: None,
        };
        attrs.record(&mut span_data);
        self.storage.span_storage.insert(id.clone(), span_data);
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
        if let Some(mut span_data) = self.storage.span_storage.get_mut(span) {
            values.record(span_data.value_mut());
        }
        // else case can occur after storage is clear()'d
    }

    fn on_enter(&self, span: &Id, _ctx: Context<'_, S>) {
        if let Some(mut span_data) = self.storage.span_storage.get_mut(span) {
            // For futures we seem to enter and exit the span multiple times, probably each time it is polled.
            // Capturing the first enter and last exit is the right approach for measuring the entire span length.
            if span_data.entered_at.is_none() {
                span_data.entered_at = Some(Instant::now());
            }
        }
        // else case can occur after storage is clear()'d
    }

    fn on_exit(&self, span: &Id, _ctx: Context<'_, S>) {
        if let Some(mut span_data) = self.storage.span_storage.get_mut(span) {
            span_data.exited_at = Some(Instant::now());
        }
        // else case can occur after storage is clear()'d
    }
}
