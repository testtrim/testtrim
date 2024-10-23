// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, marker::PhantomData, path::PathBuf, sync::Arc};

use anyhow::Result;
use log::{error, info};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::info_span;

use crate::{
    cmd::get_test_identifiers::{get_target_test_cases, AncestorSearchMode},
    commit_coverage_data::CoverageIdentifier,
    db::{CoverageDatabase, DieselCoverageDatabase},
    errors::{RunTestsCommandErrors, RunTestsErrors, TestFailure},
    platform::{
        rust::RustTestPlatform, ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform,
    },
    scm::{git::GitScm, Scm, ScmCommit},
    timing_tracer::{PerformanceStorage, PerformanceStoringTracingSubscriber},
};

use super::cli::{GetTestIdentifierMode, SourceMode};

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub fn cli(test_selection_mode: &GetTestIdentifierMode, source_mode: &SourceMode, jobs: &u16) {
    let perf_storage = Arc::new(PerformanceStorage::new());
    let my_subscriber = PerformanceStoringTracingSubscriber::new(perf_storage.clone());

    tracing::subscriber::with_default(my_subscriber, || {
        match run_tests::<_, _, _, _, _, _, RustTestPlatform>(
            test_selection_mode,
            &GitScm {},
            source_mode,
            jobs,
        ) {
            Ok(out) => {
                println!("successfully executed tests");
                println!(
                    "target test cases were {} of {}, {}%",
                    out.target_test_cases.len(),
                    out.all_test_cases.len(),
                    100 * out.target_test_cases.len() / out.all_test_cases.len(),
                );
            }
            Err(err) => {
                if let Some(RunTestsErrors::TestExecutionFailures(ref test_failures)) =
                    err.downcast_ref::<RunTestsErrors>()
                {
                    println!("{} test(s) failed:", test_failures.len());
                    for failure in test_failures {
                        println!();
                        println!("Test: {}", failure.test_identifier);
                        match failure.failure {
                            TestFailure::NonZeroExitCode {
                                ref exit_code,
                                ref stdout,
                                ref stderr,
                            } => {
                                if let Some(ref exit_code) = exit_code {
                                    println!("\tprocess exited with code {}", exit_code);
                                }
                                if !stdout.is_empty() {
                                    println!("\tstdout:");
                                    for line in stdout.lines() {
                                        println!("\t{}", line);
                                    }
                                }
                                if !stderr.is_empty() {
                                    println!("\tstderr:");
                                    for line in stderr.lines() {
                                        println!("\t{}", line);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    error!("error occurred in run_tests: {:?}", err)
                }
            }
        }
    });

    // FIXME: probably not the right choice to print this to stdout; maybe log info?
    println!("Performance stats:");
    perf_storage.print();
}

pub struct RunTestsOutput<Commit: ScmCommit, TI: TestIdentifier, CTI: ConcreteTestIdentifier<TI>> {
    // Test discovery and analysis results
    pub all_test_cases: HashSet<CTI>,
    pub target_test_cases: HashSet<CTI>,
    pub ancestor_commit: Option<Commit>,

    // Change discovery results
    pub files_changed: Option<HashSet<PathBuf>>,
    pub external_dependencies_changed: Option<usize>,

    // FIXME: add profiling return data:
    //   - time taken to discover tests / build, time taken to run tests, time "added by testtrim" for reading coverage
    //     data, analyzing coverage data, and writing coverage data
    test_identifier_type: PhantomData<TI>,
}

pub fn run_tests<Commit, MyScm, TI, CI, TD, CTI, TP>(
    mode: &GetTestIdentifierMode,
    scm: &MyScm,
    source_mode: &SourceMode,
    jobs: &u16,
) -> Result<RunTestsOutput<Commit, TI, CTI>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI, CI, TD, CTI>,
{
    let save_coverage_data = match source_mode {
        SourceMode::Automatic => scm.is_working_dir_clean()?,
        SourceMode::CleanCommit => {
            if !scm.is_working_dir_clean()? {
                return Err(RunTestsCommandErrors::CleanCommitWorkingDirectoryDirty.into());
            } else {
                true
            }
        }
        SourceMode::OverrideCleanCommit => true,
        SourceMode::WorkingTree => false,
    };

    let ancestor_search_mode = match source_mode {
        SourceMode::Automatic => {
            if scm.is_working_dir_clean()? {
                AncestorSearchMode::SkipHeadCommit
            } else {
                AncestorSearchMode::AllCommits
            }
        }
        SourceMode::CleanCommit | SourceMode::OverrideCleanCommit => {
            AncestorSearchMode::SkipHeadCommit
        }
        SourceMode::WorkingTree => AncestorSearchMode::AllCommits,
    };
    info!(
        "source_mode: {:?}, save_coverage_data: {}, ancestor_search_mode: {:?}",
        source_mode, save_coverage_data, ancestor_search_mode
    );

    let test_cases =
        get_target_test_cases::<Commit, MyScm, _, _, _, _, TP>(mode, scm, ancestor_search_mode)?;

    let mut coverage_data = TP::run_tests(&test_cases.target_test_cases, *jobs)?;
    for tc in &test_cases.all_test_cases {
        coverage_data.add_existing_test(tc.test_identifier().clone());
    }

    info!("successfully ran tests");

    if save_coverage_data {
        let commit_sha = scm.get_commit_identifier(&scm.get_head_commit()?);

        let ancestor_commit_sha = test_cases
            .ancestor_commit
            .as_ref()
            .map(|c| scm.get_commit_identifier(c));

        info_span!("save_coverage_data", perftrace = "write-coverage-data").in_scope(|| {
            DieselCoverageDatabase::new_sqlite_from_default_path().save_coverage_data(
                &coverage_data,
                &commit_sha,
                ancestor_commit_sha.as_deref(),
            )
        })?;
    }

    Ok(RunTestsOutput {
        all_test_cases: test_cases.all_test_cases,
        target_test_cases: test_cases.target_test_cases,
        ancestor_commit: test_cases.ancestor_commit,

        files_changed: test_cases.files_changed,
        external_dependencies_changed: test_cases.external_dependencies_changed,

        test_identifier_type: PhantomData,
    })
}
