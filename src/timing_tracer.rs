// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use dashmap::DashMap;
use log::warn;
use rand::{thread_rng, RngCore};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{
    field::Visit,
    span::{Attributes, Id, Record},
    Event, Metadata, Subscriber,
};

use crate::util::duration_to_seconds;

// FIXME: in the future it might make more sense to use the tracing-subscriber library to create a "Layer" that does
// this performance tracing work.  That would allow us to have a truely useful tracing subscriber for the traditional
// use-case, and a separate implementation for our performance timing tracing that just handles that use-case.  But for
// now we're only using tracing for performance data capture, so it's simpler to just use a Subscriber that has that
// single purpose.

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

    /// For every span marked with perftrace, accumulate all the time in those spans by their perftrace value.
    ///
    /// If spans were executed in parallel, the cumulative time of each parallel task will be counted separately.  eg. 5
    /// parallel 1 second tasks would show 5 seconds of cumulative time.
    fn aggregate_cumulative_time(&self) -> HashMap<String, Duration> {
        let mut accumulated_time: HashMap<String, Duration> = HashMap::new();
        for thingy in &self.span_storage {
            if let Some(perftrace) = &thingy.perftrace
                && let Some(entered_at) = &thingy.entered_at
                && let Some(exited_at) = &thingy.exited_at
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

pub struct PerformanceStoringTracingSubscriber {
    storage: Arc<PerformanceStorage>,
}

impl PerformanceStoringTracingSubscriber {
    #[must_use]
    pub fn new(storage: Arc<PerformanceStorage>) -> Self {
        PerformanceStoringTracingSubscriber { storage }
    }
}

impl Subscriber for PerformanceStoringTracingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let span_id = Id::from_u64(thread_rng().next_u64());

        let mut span_data = SpanData {
            perftrace: None,
            entered_at: None,
            exited_at: None,
        };
        span.record(&mut span_data);

        self.storage.span_storage.insert(span_id.clone(), span_data);

        span_id
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        if let Some(mut span_data) = self.storage.span_storage.get_mut(span) {
            values.record(span_data.value_mut());
        } else {
            warn!("record({span:?}) referenced a span that was not stored in span_storage");
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, span: &Id) {
        if let Some(mut span_data) = self.storage.span_storage.get_mut(span) {
            // for futures we seem to enter and exit the span multiple times, probably each time it is polled; I guess
            // that in the spirit of measuring the entire length of the span capturing the first enter and last exit is
            // the right thing to do
            if span_data.entered_at.is_none() {
                span_data.entered_at = Some(Instant::now());
            }
        } else {
            warn!("enter({span:?}) referenced a span that was not stored in span_storage");
        }
    }

    fn exit(&self, span: &Id) {
        if let Some(mut span_data) = self.storage.span_storage.get_mut(span) {
            span_data.exited_at = Some(Instant::now());
        } else {
            warn!("exit({span:?}) referenced a span that was not stored in span_storage");
        }
    }
}
