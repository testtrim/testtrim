// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    borrow::Cow, collections::HashSet, marker::PhantomData, path::PathBuf, process::ExitCode,
    sync::Arc,
};

use anyhow::{Context, Result};
use log::{error, info};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{info_span, instrument::WithSubscriber, Instrument as _};

use crate::{
    cmd::get_test_identifiers::{get_target_test_cases, tags, AncestorSearchMode},
    coverage::{
        commit_coverage_data::CoverageIdentifier, create_db_infallible, CoverageDatabase, Tag,
    },
    errors::{RunTestsCommandErrors, RunTestsErrors, TestFailure},
    platform::{
        dotnet::DotnetTestPlatform, golang::GolangTestPlatform, rust::RustTestPlatform,
        ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform,
    },
    scm::{git::GitScm, Scm, ScmCommit},
    timing_tracer::{PerformanceStorage, PerformanceStoringTracingSubscriber},
};

use super::cli::{
    autodetect_test_project_type, GetTestIdentifierMode, PlatformTaggingMode, SourceMode,
    TestProjectType,
};

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub async fn cli(
    test_project_type: TestProjectType,
    test_selection_mode: GetTestIdentifierMode,
    source_mode: SourceMode,
    jobs: u16,
    user_tags: &[Tag],
    platform_tagging_mode: PlatformTaggingMode,
) -> ExitCode {
    let test_project_type = if test_project_type == TestProjectType::AutoDetect {
        autodetect_test_project_type()
    } else {
        test_project_type
    };
    match test_project_type {
        TestProjectType::AutoDetect => panic!("autodetect failed"),
        TestProjectType::Rust => {
            specific_cli::<_, _, _, _, RustTestPlatform>(
                test_selection_mode,
                source_mode,
                jobs,
                user_tags,
                platform_tagging_mode,
            )
            .await
        }
        TestProjectType::Dotnet => {
            specific_cli::<_, _, _, _, DotnetTestPlatform>(
                test_selection_mode,
                source_mode,
                jobs,
                user_tags,
                platform_tagging_mode,
            )
            .await
        }
        TestProjectType::Golang => {
            specific_cli::<_, _, _, _, GolangTestPlatform>(
                test_selection_mode,
                source_mode,
                jobs,
                user_tags,
                platform_tagging_mode,
            )
            .await
        }
    }
}

async fn specific_cli<TI, CI, TD, CTI, TP>(
    test_selection_mode: GetTestIdentifierMode,
    source_mode: SourceMode,
    jobs: u16,
    user_tags: &[Tag],
    platform_tagging_mode: PlatformTaggingMode,
) -> ExitCode
where
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    let perf_storage = Arc::new(PerformanceStorage::new());
    let my_subscriber = PerformanceStoringTracingSubscriber::new(perf_storage.clone());

    let tags = tags::<TP>(user_tags, platform_tagging_mode);

    let exit_code = async {
        match run_tests::<_, _, _, _, _, _, TP>(
            test_selection_mode,
            &GitScm {},
            source_mode,
            jobs,
            &tags,
            &create_db_infallible(),
        )
        .await
        {
            Ok(out) => {
                println!("successfully executed tests");
                println!(
                    "target test cases were {} of {}, {}%",
                    out.target_test_cases.len(),
                    out.all_test_cases.len(),
                    100 * out.target_test_cases.len() / out.all_test_cases.len(),
                );
                ExitCode::SUCCESS
            }
            Err(RunTestsCommandErrors::RunTestsErrors(RunTestsErrors::TestExecutionFailures(
                ref test_failures,
            ))) => {
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
                                println!(
                                    "\ttest failed when test process exited with code {exit_code}"
                                );
                            }
                            if !stdout.is_empty() {
                                println!("\tstdout:");
                                for line in stdout.lines() {
                                    println!("\t{line}");
                                }
                            }
                            if !stderr.is_empty() {
                                println!("\tstderr:");
                                for line in stderr.lines() {
                                    println!("\t{line}");
                                }
                            }
                        }
                    }
                }
                ExitCode::FAILURE
            }
            Err(err) => {
                error!("error occurred in run_tests: {err:?}");
                ExitCode::FAILURE
            }
        }
    }
    .with_subscriber(my_subscriber)
    .await;

    // FIXME: probably not the right choice to print this to stdout; maybe log info?
    println!("Performance stats:");
    perf_storage.print();

    exit_code
}

pub struct RunTestsOutput<Commit: ScmCommit, TI: TestIdentifier, CTI: ConcreteTestIdentifier<TI>> {
    // Test discovery and analysis results
    pub all_test_cases: HashSet<CTI>,
    pub target_test_cases: HashSet<CTI>,
    pub ancestor_commit: Option<Commit>,

    // Change discovery results
    pub files_changed: Option<HashSet<PathBuf>>,
    pub external_dependencies_changed: Option<usize>,

    test_identifier_type: PhantomData<TI>,
}

pub async fn run_tests<Commit, MyScm, TI, CI, TD, CTI, TP>(
    mode: GetTestIdentifierMode,
    scm: &MyScm,
    source_mode: SourceMode,
    jobs: u16,
    tags: &[Tag],
    coverage_db: &impl CoverageDatabase,
) -> Result<RunTestsOutput<Commit, TI, CTI>, RunTestsCommandErrors>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    let save_coverage_data = match source_mode {
        SourceMode::Automatic => scm.is_working_dir_clean()?,
        SourceMode::CleanCommit => {
            if !scm.is_working_dir_clean()? {
                return Err(RunTestsCommandErrors::CleanCommitWorkingDirectoryDirty);
            }
            true
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

    let test_cases = get_target_test_cases::<Commit, MyScm, _, _, _, _, TP>(
        mode,
        scm,
        ancestor_search_mode,
        tags,
        coverage_db,
    )
    .await?;

    let mut coverage_data = TP::run_tests(test_cases.target_test_cases.keys(), jobs).await?;
    for tc in &test_cases.all_test_cases {
        coverage_data.add_existing_test(tc.test_identifier().clone());
    }

    info!("successfully ran tests");

    if save_coverage_data {
        let files_changed = match test_cases.files_changed {
            Some(ref files_changed) => Cow::Borrowed(files_changed),
            None => Cow::Owned(scm.get_all_repo_files()?),
        };
        TP::analyze_changed_files(&files_changed, &mut coverage_data)?;

        let commit_identifier = scm.get_commit_identifier(&scm.get_head_commit()?);

        let ancestor_commit_identifier = test_cases
            .ancestor_commit
            .as_ref()
            .map(|c| scm.get_commit_identifier(c));

        async move {
            coverage_db
                .save_coverage_data::<TP>(
                    &TP::project_name()?,
                    &coverage_data,
                    &commit_identifier,
                    ancestor_commit_identifier.as_deref(),
                    tags,
                )
                .await
                .context("save_coverage_data")
        }
        .instrument(info_span!(
            "save_coverage_data",
            perftrace = "write-coverage-data"
        ))
        .await?;
    }

    Ok(RunTestsOutput {
        all_test_cases: test_cases.all_test_cases,
        target_test_cases: test_cases.target_test_cases.keys().cloned().collect(),
        ancestor_commit: test_cases.ancestor_commit,

        files_changed: test_cases.files_changed,
        external_dependencies_changed: test_cases.external_dependencies_changed,

        test_identifier_type: PhantomData,
    })
}
