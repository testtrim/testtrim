// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    io,
    path::Path,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use log::{Log, error, info, trace, warn};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{Instrument as _, info_span, instrument::WithSubscriber};
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{
    cmd::{cli::PlatformTaggingMode, get_test_identifiers, run_tests::run_tests, ui::UiStage},
    coverage::{CoverageDatabase, commit_coverage_data::CoverageIdentifier, create_db_infallible},
    errors::{RunTestsCommandErrors, RunTestsErrors, TestFailure},
    platform::{
        ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform,
        dotnet::DotnetTestPlatform, golang::GolangTestPlatform, rust::RustTestPlatform,
    },
    scm::{Scm, ScmCommit, git::GitScm},
    timing_tracer::{PerformanceStorage, PerformanceStoringLayer},
    util::duration_to_seconds,
};

use super::{
    cli::{
        CommonOptions, GetTestIdentifierMode, SimulateHistoryOptions, SourceMode, TestProjectType,
        autodetect_test_project_type,
    },
    simulate_history_ui::SimulateHistoryConsole,
};

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub async fn cli(
    logger: Box<dyn Log>,
    common_opts: &CommonOptions,
    run_opts: &SimulateHistoryOptions,
) -> ExitCode {
    let test_project_type = if run_opts.test_project_type == TestProjectType::AutoDetect {
        autodetect_test_project_type(&common_opts.project_dir)
    } else {
        run_opts.test_project_type
    };
    match test_project_type {
        TestProjectType::AutoDetect => panic!("autodetect failed"),
        TestProjectType::Rust => {
            specific_cli::<_, _, _, _, RustTestPlatform>(logger, common_opts, run_opts).await
        }
        TestProjectType::Dotnet => {
            specific_cli::<_, _, _, _, DotnetTestPlatform>(logger, common_opts, run_opts).await
        }
        TestProjectType::Golang => {
            specific_cli::<_, _, _, _, GolangTestPlatform>(logger, common_opts, run_opts).await
        }
    }
}

async fn specific_cli<TI, CI, TD, CTI, TP>(
    logger: Box<dyn Log>,
    common_opts: &CommonOptions,
    run_opts: &SimulateHistoryOptions,
) -> ExitCode
where
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    let perf_storage = Arc::new(PerformanceStorage::new());
    let perf_layer = PerformanceStoringLayer::new(perf_storage.clone());

    let terminal_output = SimulateHistoryConsole::new(common_opts.no_progress, logger);

    // At the core of our subscriber, use tracing-subscriber's Registry which does nothing but generate span IDs.
    let subscriber = tracing_subscriber::registry::Registry::default()
        .with(perf_layer)
        .with(terminal_output);

    match simulate_history::<_, _, _, _, _, _, TP>(
        &common_opts.project_dir,
        &GitScm::new(common_opts.project_dir.clone()),
        run_opts.num_commits,
        run_opts.execution_parameters.jobs,
        &create_db_infallible(),
        run_opts.override_config.as_ref(),
        perf_storage,
    )
    .with_subscriber(subscriber)
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
    project_dir: &Path,
    scm: &MyScm,
    num_commits: u16,
    jobs: u16,
    coverage_db: &impl CoverageDatabase,
    override_config: Option<&String>,
    perf_storage: Arc<PerformanceStorage>,
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
        .clear_project_data::<TP>(&TP::project_name(project_dir)?)
        .instrument(info_span!(
            "clear_project_data",
            ui_stage = Into::<u64>::into(UiStage::ClearProjectData),
        ))
        .await?;

    // Use git log -> get the target commits from earliest to latest.  When we hit a merge branch, we'll go up each
    // parent's path until we've found enough commits to meet the requested test count.  This might not reach a common
    // ancestor of all commits, leaving the potential for multiple test commits to have no ancestor coverage data at the
    // beginning of testing.
    info!("Searching for testing target commits...");
    let commits = info_span!(
        "identify_test_commits",
        ui_stage = Into::<u64>::into(UiStage::IdentifyTestCommits)
    )
    .in_scope(|| {
        let head = scm.get_head_commit()?;
        let mut commits = get_more_commits(scm, &head, num_commits - 1)?;
        commits.push(head);
        info!("Found {} commits to test.", commits.len());
        Ok::<_, anyhow::Error>(commits)
    })?;

    // Simulate each commit, and thenoutput results to stdout in a CSV format:
    //   - commit identifier
    //   - did the tests execute successfully
    //   - was an ancestor commit identified successfully w/ coverage data; ancestor commit identifier
    //   - how many tests were present
    //   - how many tests were targeted based upon coverage data
    //   - change stats; # of files changed, # of functions changed, # of external dependencies changed
    //   - time taken to discover tests / build, time taken to run tests, time "added by testtrim" for reading coverage
    //     data, analyzing coverage data, and writing coverage data
    let commit_count = commits.len();
    let mut commits_simulated = Vec::<SimulateCommitOutput<Commit>>::with_capacity(commit_count);
    async {
        for commit in commits {
            let commit_identifier = scm.get_commit_identifier(&commit);
            info!("testing commit: {:?}", commit_identifier);
            commits_simulated.push(
                simulate_commit::<_, _, _, _, _, _, TP>(
                    project_dir,
                    scm,
                    commit,
                    jobs,
                    coverage_db,
                    override_config,
                    perf_storage.clone(),
                )
                .instrument(info_span!(
                    "simulate_commit",
                    ui_stage = Into::<u64>::into(UiStage::SimulateSingleCommit),
                    commit_identifier = commit_identifier,
                ))
                .await?,
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .instrument(info_span!(
        "simulate_commits",
        ui_stage = Into::<u64>::into(UiStage::SimulateCommits),
        commit_count = commit_count,
    ))
    .await?;

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
    project_dir: &Path,
    scm: &MyScm,
    commit: Commit,
    jobs: u16,
    coverage_db: &impl CoverageDatabase,
    override_config: Option<&String>,
    perf_storage: Arc<PerformanceStorage>,
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

    perf_storage.clear();
    let start_instant = Instant::now();

    trace!("beginning run test subcommand");
    let run_tests_result = async {
        run_tests::<_, _, _, _, _, _, TP>(
            project_dir,
            GetTestIdentifierMode::Relevant,
            scm,
            SourceMode::CleanCommit,
            jobs,
            &get_test_identifiers::tags::<TP>(&[], PlatformTaggingMode::Automatic), // default tags only
            coverage_db,
            override_config,
        )
        .await
    }
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
