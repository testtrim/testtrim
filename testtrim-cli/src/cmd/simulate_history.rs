// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    io,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use log::{error, info, trace, warn};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::instrument::WithSubscriber;

use crate::{
    cmd::{cli::PlatformTaggingMode, get_test_identifiers, run_tests::run_tests},
    coverage::{CoverageDatabase, commit_coverage_data::CoverageIdentifier, create_db_infallible},
    errors::{RunTestsCommandErrors, RunTestsErrors, TestFailure},
    platform::{
        ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform,
        dotnet::DotnetTestPlatform, golang::GolangTestPlatform, rust::RustTestPlatform,
    },
    scm::{Scm, ScmCommit, git::GitScm},
    timing_tracer::{PerformanceStorage, PerformanceStoringTracingSubscriber},
    util::duration_to_seconds,
};

use super::cli::{
    GetTestIdentifierMode, SourceMode, TestProjectType, autodetect_test_project_type,
};

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub async fn cli(test_project_type: TestProjectType, num_commits: u16, jobs: u16) -> ExitCode {
    let test_project_type = if test_project_type == TestProjectType::AutoDetect {
        autodetect_test_project_type()
    } else {
        test_project_type
    };
    match test_project_type {
        TestProjectType::AutoDetect => panic!("autodetect failed"),
        TestProjectType::Rust => {
            specific_cli::<_, _, _, _, RustTestPlatform>(num_commits, jobs).await
        }
        TestProjectType::Dotnet => {
            specific_cli::<_, _, _, _, DotnetTestPlatform>(num_commits, jobs).await
        }
        TestProjectType::Golang => {
            specific_cli::<_, _, _, _, GolangTestPlatform>(num_commits, jobs).await
        }
    }
}

async fn specific_cli<TI, CI, TD, CTI, TP>(num_commits: u16, jobs: u16) -> ExitCode
where
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    match simulate_history::<_, _, _, _, _, _, TP>(
        &GitScm {},
        num_commits,
        jobs,
        &create_db_infallible(),
    )
    .await
    {
        Ok(out) => {
            let mut wtr = csv::Writer::from_writer(io::stdout());
            for rec in out.commits_simulated {
                wtr.serialize(rec)
                    .expect("serialize SimulateCommitOutput and write to stdout");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!("error occurred in simulate_history: {err:?}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Serialize)]
pub enum SimulationResult {
    /// Success, including all tests.
    Success,
    /// testtrim's simulation attempt occurred, but tests failed.
    TestExecutionFailure,
    /// simulation attempt failed; could be a compile failure, could be an internal error; more clarity might be useful
    /// in the future.
    Error,
}

#[derive(Serialize)]
pub struct SimulateCommitOutput<Commit: ScmCommit> {
    #[serde(skip_serializing)]
    pub commit: Commit,
    pub commit_identifier: String,

    pub success: SimulationResult,
    pub test_failure_count: Option<usize>, // if success == TestExecutionFailure

    #[serde(skip_serializing)]
    pub ancestor_commit: Option<Commit>,
    pub ancestor_commit_identifier: Option<String>,
    pub total_test_count: Option<usize>,
    pub targeted_test_count: Option<usize>,

    pub file_changed_count: Option<usize>,
    pub external_dependencies_changed_count: Option<usize>,

    /// Total wall-clock time taken to execute the commit's simulation.
    #[serde(serialize_with = "duration_to_seconds")]
    pub total_time: Duration,

    // FIXME: cannot serialize RunTestTiming container inside struct when writing headers from structs
    // As a hack around this, just copying the values into this struct.
    // pub profiling: RunTestTiming,
    #[serde(serialize_with = "duration_to_seconds")]
    pub discover_tests: Duration,
    #[serde(serialize_with = "duration_to_seconds")]
    pub read_historical_coverage_data: Duration,
    #[serde(serialize_with = "duration_to_seconds")]
    pub test_determination: Duration,
    #[serde(serialize_with = "duration_to_seconds")]
    pub addt_platform_specific_test_determination: Duration,
    /// Total time spent running tests; note that this is cumulative time across concurrent test runners, not wall-clock time.
    #[serde(serialize_with = "duration_to_seconds")]
    pub run_tests: Duration,
    /// Total time spent reading test's coverage output; note that this is cumulative time across concurrent test runners, not wall-clock time.
    #[serde(serialize_with = "duration_to_seconds")]
    pub read_new_coverage_data: Duration,
    #[serde(serialize_with = "duration_to_seconds")]
    pub write_new_coverage_data: Duration,
    // FIXME: add testtrim database statistics -- eg. current size after this commit
}

#[derive(Serialize)]
pub struct SimulateHistoryOutput<Commit: ScmCommit> {
    pub commits_simulated: Vec<SimulateCommitOutput<Commit>>,
}

async fn simulate_history<Commit, MyScm, TI, CI, TD, CTI, TP>(
    scm: &MyScm,
    num_commits: u16,
    jobs: u16,
    coverage_db: &impl CoverageDatabase,
) -> Result<SimulateHistoryOutput<Commit>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    // Remove all contents from the testtrim database, to ensure a clean simulation.
    coverage_db
        .clear_project_data::<TP>(&TP::project_name()?)
        .await?;

    // Use git log -> get the target commits from earliest to latest.  When we hit a merge branch, we'll go up each
    // parent's path until we've found enough commits to meet the requested test count.  This might not reach a common
    // ancestor of all commits, leaving the potential for multiple test commits to have no ancestor coverage data at the
    // beginning of testing.
    info!("Searching for testing target commits...");
    let head = scm.get_head_commit()?;
    let mut commits = get_more_commits(scm, &head, num_commits - 1)?;
    commits.push(head);
    info!("Found {} commits to test.", commits.len());

    // Simulate each commit, and thenoutput results to stdout in a CSV format:
    //   - commit identifier
    //   - did the tests execute successfully
    //   - was an ancestor commit identified successfully w/ coverage data; ancestor commit identifier
    //   - how many tests were present
    //   - how many tests were targeted based upon coverage data
    //   - change stats; # of files changed, # of functions changed, # of external dependencies changed
    //   - time taken to discover tests / build, time taken to run tests, time "added by testtrim" for reading coverage
    //     data, analyzing coverage data, and writing coverage data
    let mut commits_simulated = Vec::<SimulateCommitOutput<Commit>>::with_capacity(commits.len());
    for commit in commits {
        info!("testing commit: {:?}", scm.get_commit_identifier(&commit));
        commits_simulated
            .push(simulate_commit::<_, _, _, _, _, _, TP>(scm, commit, jobs, coverage_db).await?);
    }

    Ok(SimulateHistoryOutput { commits_simulated })
}

fn get_more_commits<Commit, MyScm>(
    scm: &MyScm,
    head: &Commit,
    num_commits: u16,
) -> Result<Vec<Commit>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
{
    let mut result = vec![];
    let mut parents = scm.get_commit_parents(head)?;
    while result.len() < Into::<usize>::into(num_commits) {
        if let Some(cur_commit) = parents.pop() {
            let cur_parents = scm.get_commit_parents(&cur_commit)?;
            result.push(cur_commit);
            parents.extend(cur_parents);
        } else {
            break;
        }
    }
    // Reorganize the commits from oldest to newest (not based upon time; based upon ancestry).
    result.reverse();
    Ok(result)
}

async fn simulate_commit<Commit, MyScm, TI, CI, TD, CTI, TP>(
    scm: &MyScm,
    commit: Commit,
    jobs: u16,
    coverage_db: &impl CoverageDatabase,
) -> Result<SimulateCommitOutput<Commit>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    // For each commit:
    // - Checkout that branch
    // - Ensure working directory is clean, but try not to remove any incremental build files.  `git clean -f` (without
    //   -x, -d) should probably do this.
    // - Run `testtrim run-tests --source-mode=CleanCommit` (in-process), which should guarantee that the working
    //   directory is clean and that coverage map will be saved if generated.
    // - Return data for simulation output, if applicable

    trace!("checking out {:?}", scm.get_commit_identifier(&commit));
    scm.checkout(&commit)?;

    trace!("cleaning working directory");
    scm.clean_lightly()?;

    let perf_storage = Arc::new(PerformanceStorage::new());
    let my_subscriber = PerformanceStoringTracingSubscriber::new(perf_storage.clone());
    let start_instant = Instant::now();

    trace!("beginning run test subcommand");
    let run_tests_result = async {
        run_tests::<_, _, _, _, _, _, TP>(
            GetTestIdentifierMode::Relevant,
            scm,
            SourceMode::CleanCommit,
            jobs,
            &get_test_identifiers::tags::<TP>(&[], PlatformTaggingMode::Automatic), // default tags only
            coverage_db,
        )
        .await
    }
    .with_subscriber(my_subscriber)
    .await;

    let total_time = Instant::now().duration_since(start_instant);
    let run_test_timing = perf_storage.interpret_run_test_timing();

    let commit_identifier = scm.get_commit_identifier(&commit);
    match run_tests_result {
        Ok(run_result) => {
            let ancestor_commit_identifier = run_result
                .ancestor_commit
                .as_ref()
                .map(|c| scm.get_commit_identifier(c));
            Ok(SimulateCommitOutput {
                commit,
                commit_identifier,
                success: SimulationResult::Success,
                test_failure_count: None,
                ancestor_commit: run_result.ancestor_commit,
                ancestor_commit_identifier,
                total_test_count: Some(run_result.all_test_cases.len()),
                targeted_test_count: Some(run_result.target_test_cases.len()),
                file_changed_count: run_result.files_changed.map(|set| set.len()),
                external_dependencies_changed_count: run_result.external_dependencies_changed,
                total_time,
                discover_tests: run_test_timing.discover_tests,
                read_historical_coverage_data: run_test_timing.read_historical_coverage_data,
                test_determination: run_test_timing.test_determination,
                addt_platform_specific_test_determination: run_test_timing
                    .addt_platform_specific_test_determination,
                run_tests: run_test_timing.run_tests,
                read_new_coverage_data: run_test_timing.read_new_coverage_data,
                write_new_coverage_data: run_test_timing.write_new_coverage_data,
            })
        }
        Err(RunTestsCommandErrors::RunTestsErrors(RunTestsErrors::TestExecutionFailures(
            failures,
        ))) => {
            warn!(
                "commit {commit_identifier} failed to execute {} tests",
                failures.len()
            );
            for failure in &failures {
                match &failure.failure {
                    TestFailure::NonZeroExitCode {
                        exit_code,
                        stdout,
                        stderr,
                    } => {
                        info!(
                            "test {} exited with code {exit_code:?}\n\nstdout: {}\n\nstderr: {}",
                            failure.test_identifier,
                            // indent stdout & stderr for maybe more clarity:
                            stdout.replace('\n', "\n    "),
                            stderr.replace('\n', "\n    "),
                        );
                    }
                }
            }
            Ok(SimulateCommitOutput {
                commit,
                commit_identifier,
                success: SimulationResult::TestExecutionFailure,
                test_failure_count: Some(failures.len()),
                ancestor_commit: None,
                ancestor_commit_identifier: None,
                total_test_count: None,
                targeted_test_count: None,
                file_changed_count: None,
                external_dependencies_changed_count: None,
                total_time,
                discover_tests: run_test_timing.discover_tests,
                read_historical_coverage_data: run_test_timing.read_historical_coverage_data,
                test_determination: run_test_timing.test_determination,
                addt_platform_specific_test_determination: run_test_timing
                    .addt_platform_specific_test_determination,
                run_tests: run_test_timing.run_tests,
                read_new_coverage_data: run_test_timing.read_new_coverage_data,
                write_new_coverage_data: run_test_timing.write_new_coverage_data,
            })
        }
        Err(e) => {
            warn!("commit {commit_identifier} failed to run tests with error: {e}");
            Ok(SimulateCommitOutput {
                commit,
                commit_identifier,
                success: SimulationResult::Error,
                test_failure_count: None,
                ancestor_commit: None,
                ancestor_commit_identifier: None,
                total_test_count: None,
                targeted_test_count: None,
                file_changed_count: None,
                external_dependencies_changed_count: None,
                total_time,
                discover_tests: run_test_timing.discover_tests,
                read_historical_coverage_data: run_test_timing.read_historical_coverage_data,
                test_determination: run_test_timing.test_determination,
                addt_platform_specific_test_determination: run_test_timing
                    .addt_platform_specific_test_determination,
                run_tests: run_test_timing.run_tests,
                read_new_coverage_data: run_test_timing.read_new_coverage_data,
                write_new_coverage_data: run_test_timing.write_new_coverage_data,
            })
        }
    }
}
