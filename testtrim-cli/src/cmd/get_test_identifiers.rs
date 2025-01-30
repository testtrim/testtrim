// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use current_platform::CURRENT_PLATFORM;
use log::{Log, debug, error, info, trace, warn};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::process::ExitCode;
use std::sync::Arc;
use std::{collections::HashSet, path::PathBuf};
use tracing::instrument::WithSubscriber;
use tracing::{Instrument as _, info_span, instrument};
use tracing_subscriber::layer::SubscriberExt as _;

use crate::cmd::ui::UiStage;
use crate::coverage::{Tag, create_db_infallible};
use crate::network::compute_tests_from_network_accesses;
use crate::repo_config::get_repo_config;
use crate::timing_tracer::{PerformanceStorage, PerformanceStoringLayer};
use crate::{
    coverage::{
        CoverageDatabase, commit_coverage_data::CoverageIdentifier,
        full_coverage_data::FullCoverageData,
    },
    platform::{
        ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform, TestReason,
        dotnet::DotnetTestPlatform, golang::GolangTestPlatform, rust::RustTestPlatform,
    },
    scm::{Scm, ScmCommit, git::GitScm},
};

use super::cli::{
    CommonOptions, GetTestIdentifierMode, PlatformTaggingMode, TestProjectType,
    TestTargetingParameters, autodetect_test_project_type,
};
use super::get_test_identifiers_ui::GetTestIdentifiersConsole;

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub async fn cli<Logger: Log + 'static>(
    logger: Logger,
    common_opts: &CommonOptions,
    target_parameters: &TestTargetingParameters,
) -> ExitCode {
    let test_project_type = if target_parameters.test_project_type == TestProjectType::AutoDetect {
        autodetect_test_project_type()
    } else {
        target_parameters.test_project_type
    };
    match test_project_type {
        TestProjectType::AutoDetect => panic!("autodetect failed"),
        TestProjectType::Rust => {
            specific_cli::<_, _, _, _, _, RustTestPlatform>(logger, common_opts, target_parameters)
                .await
        }
        TestProjectType::Dotnet => {
            specific_cli::<_, _, _, _, _, DotnetTestPlatform>(
                logger,
                common_opts,
                target_parameters,
            )
            .await
        }
        TestProjectType::Golang => {
            specific_cli::<_, _, _, _, _, GolangTestPlatform>(
                logger,
                common_opts,
                target_parameters,
            )
            .await
        }
    }
}

#[allow(clippy::print_stdout)]
async fn specific_cli<Logger, TI, CI, TD, CTI, TP>(
    logger: Logger,
    common_opts: &CommonOptions,
    target_parameters: &TestTargetingParameters,
) -> ExitCode
where
    Logger: Log + 'static,
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    let perf_storage = Arc::new(PerformanceStorage::new());
    let perf_layer = PerformanceStoringLayer::new(perf_storage.clone());

    let terminal_output = GetTestIdentifiersConsole::new(common_opts.no_progress, logger);

    // At the core of our subscriber, use tracing-subscriber's Registry which does nothing but generate span IDs.
    let subscriber = tracing_subscriber::registry::Registry::default()
        .with(perf_layer)
        .with(terminal_output);

    let tags = tags::<TP>(
        &target_parameters.tags,
        target_parameters.platform_tagging_mode,
    );

    let test_cases = get_target_test_cases::<_, _, _, _, _, _, TP>(
        target_parameters.test_selection_mode,
        &GitScm {},
        AncestorSearchMode::AllCommits,
        &tags,
        &create_db_infallible(),
        target_parameters.override_config.as_ref(),
    )
    .with_subscriber(subscriber)
    .await;

    // Note: println output needs to come after `subscriber` is dropped so that we don't fight the
    // `GetTestIdentifiersConsole` for control over the console.
    let test_cases = match test_cases {
        Ok(test_cases) => test_cases,
        Err(err) => {
            error!("error occurred in get_target_test_cases: {:?}", err);
            return ExitCode::FAILURE;
        }
    };
    for (cti, reasons) in test_cases.target_test_cases {
        println!("{:?}", cti.test_identifier());
        for reason in reasons {
            println!("\t{reason:?}");
        }
    }

    // FIXME: probably not the right choice to print this to stdout; ideally this cli command just prints the test
    // identifiers.
    println!("Performance stats:");
    perf_storage.print();

    ExitCode::SUCCESS
}

#[must_use]
pub fn tags<TP: TestPlatform>(
    user_tags: &[Tag],
    platform_tagging_mode: PlatformTaggingMode,
) -> Vec<Tag> {
    let mut retval = Vec::with_capacity(user_tags.len() + 1);
    if platform_tagging_mode == PlatformTaggingMode::Automatic {
        retval.push(Tag {
            key: String::from("platform"),
            value: String::from(CURRENT_PLATFORM),
        });
    }
    for t in user_tags {
        retval.push(t.clone());
    }
    for t in TP::platform_tags() {
        retval.push(t.clone());
    }
    retval
}

pub struct TargetTestCases<
    Commit: ScmCommit,
    TI: TestIdentifier,
    CTI: ConcreteTestIdentifier<TI>,
    CI: CoverageIdentifier,
> {
    // Test discovery and analysis results
    pub all_test_cases: HashSet<CTI>,
    pub target_test_cases: HashMap<CTI, HashSet<TestReason<CI>>>,
    pub ancestor_commit: Option<Commit>,

    // Change discovery results
    pub files_changed: Option<HashSet<PathBuf>>,
    pub external_dependencies_changed: Option<usize>,

    test_identifier_type: PhantomData<TI>,
}

#[derive(Debug)]
pub enum AncestorSearchMode {
    SkipHeadCommit,
    AllCommits,
}

pub async fn get_target_test_cases<Commit, MyScm, TI, CI, TD, CTI, TP>(
    mode: GetTestIdentifierMode,
    scm: &MyScm,
    ancestor_search_mode: AncestorSearchMode,
    tags: &[Tag],
    coverage_db: &impl CoverageDatabase,
    override_config: Option<&String>,
) -> Result<TargetTestCases<Commit, TI, CTI, CI>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI = TI, CI = CI, TD = TD, CTI = CTI>,
{
    let test_discovery = TP::discover_tests().await?;
    let all_test_cases = test_discovery.all_test_cases();

    if mode == GetTestIdentifierMode::All {
        return Ok(TargetTestCases {
            all_test_cases: all_test_cases.clone(),
            target_test_cases: all_test_cases
                .iter()
                .map(|tc| (tc.clone(), HashSet::from([TestReason::NoCoverageMap])))
                .collect(),
            ancestor_commit: None,
            files_changed: None,
            external_dependencies_changed: None,
            test_identifier_type: PhantomData,
        });
    }

    let (ancestor_commit, coverage_data) = if let Some(ancestor_retval) =
        find_ancestor_commit_with_coverage_data::<Commit, MyScm, TP>(
            &TP::project_name()?,
            scm,
            scm.get_head_commit()?,
            ancestor_search_mode,
            coverage_db,
            tags,
        )
        .instrument(info_span!(
            "find_ancestor_commit_with_coverage_data",
            ui_stage = Into::<u64>::into(UiStage::FindingAncestorCommit),
        ))
        .await?
    {
        info!(
            "relevant test cases will be computed base upon commit {:?}",
            scm.get_commit_identifier(&ancestor_retval.ancestor_commit)
        );
        (
            ancestor_retval.ancestor_commit,
            ancestor_retval.coverage_data,
        )
    } else {
        // FIXME: this is ugly -- but in order to prevent a "3/4" output being the last output if we didn't find an
        // ancestor commit, we pretend that we did a ComputeTestCases span here -- this can definitely be cleaned up at
        // some point once the console output stuff is a little more solid.
        info_span!(
            "find_ancestor_commit_with_coverage_data",
            ui_stage = Into::<u64>::into(UiStage::ComputeTestCases),
        )
        .in_scope(|| {});
        warn!("no base commit identified with coverage data to work from");
        return Ok(TargetTestCases {
            all_test_cases: all_test_cases.clone(),
            target_test_cases: all_test_cases
                .iter()
                .map(|tc| (tc.clone(), HashSet::from([TestReason::NoCoverageMap])))
                .collect(),
            ancestor_commit: None,
            files_changed: None,
            external_dependencies_changed: None,
            test_identifier_type: PhantomData,
        });
    };

    let (relevant_test_cases, changed_files, external_dependencies_changed) = info_span!(
        "find_ancestor_commit_with_coverage_data",
        ui_stage = Into::<u64>::into(UiStage::ComputeTestCases),
    )
    .in_scope(|| {
        let changed_files = scm.get_changed_files(&ancestor_commit)?;
        debug!("changed files: {:?}", changed_files);

        let all_test_identifiers = all_test_cases
            .iter()
            .map(|tc| tc.test_identifier().clone())
            .collect();
        let mut relevant_test_cases =
            compute_relevant_test_cases(&all_test_identifiers, &changed_files, &coverage_data)?;

        let platform_specific = TP::platform_specific_relevant_test_cases(
            &all_test_identifiers,
            &changed_files,
            scm,
            &ancestor_commit,
            &coverage_data,
        )?;
        for (ti, reasons) in platform_specific.additional_test_cases {
            relevant_test_cases.entry(ti).or_default().extend(reasons);
        }

        let repo_config = get_repo_config(override_config)?;

        for (ti, reasons) in compute_tests_from_network_accesses::<TP>(
            &coverage_data,
            repo_config.network_policy(),
            &changed_files,
        ) {
            if all_test_identifiers.contains(&ti) {
                // ignore deleted tests
                relevant_test_cases.entry(ti).or_default().extend(reasons);
            }
        }

        Ok::<_, anyhow::Error>((
            relevant_test_cases,
            changed_files,
            platform_specific.external_dependencies_changed,
        ))
    })?;

    debug!("relevant_test_cases: {:?}", relevant_test_cases);

    Ok(TargetTestCases {
        all_test_cases: all_test_cases.clone(),
        target_test_cases: relevant_test_cases
            .into_iter()
            .filter_map(|(ti, reasons)| test_discovery.map_ti_to_cti(ti).map(|cti| (cti, reasons)))
            .collect::<HashMap<_, _>>(),
        ancestor_commit: Some(ancestor_commit),
        files_changed: Some(changed_files),
        external_dependencies_changed,
        test_identifier_type: PhantomData,
    })
}

struct AncestorCommit<Commit: ScmCommit, TP: TestPlatform> {
    ancestor_commit: Commit,
    coverage_data: FullCoverageData<TP::TI, TP::CI>,
}

/// Identify a useable commit which has stored coverage data and can be used as a basis for determining which tests to
/// run in this project.
///
/// A useable commit is one that doesn't come from a branch, as coverage data could change during a merge making any
/// branch commits an incorrect source of data.  Commits are searched starting at HEAD and going towards their ancestors
/// checking for any coverage data.  If a merge commit is found, then the search skips to the best common ancestor to
/// both parents of the merge commit, and continues from there.
#[instrument(skip_all, fields(perftrace = "read-coverage-data"))]
async fn find_ancestor_commit_with_coverage_data<Commit, MyScm, TP>(
    project_name: &str,
    scm: &MyScm,
    head: Commit,
    ancestor_search_mode: AncestorSearchMode,
    coverage_db: &impl CoverageDatabase,
    tags: &[Tag],
) -> Result<Option<AncestorCommit<Commit, TP>>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TP: TestPlatform,
    TP::TI: TestIdentifier + DeserializeOwned,
    TP::CI: CoverageIdentifier,
{
    if !coverage_db
        .has_any_coverage_data::<TP>(project_name)
        .await?
    {
        return Ok(None);
    }

    let mut commit = head;
    let commit_identifier = scm.get_commit_identifier(&commit);
    let mut coverage_data = match ancestor_search_mode {
        AncestorSearchMode::AllCommits => {
            let coverage_data = coverage_db
                .read_coverage_data::<TP>(project_name, &commit_identifier, tags)
                .await?;
            trace!(
                "commit (HEAD) id {} had coverage data? {:}",
                commit_identifier,
                coverage_data.is_some()
            );
            coverage_data
        }
        AncestorSearchMode::SkipHeadCommit => None,
    };

    while coverage_data.is_none() {
        let mut parents = scm.get_commit_parents(&commit)?;
        trace!("checking parents; {} parents found", parents.len());

        if parents.is_empty() {
            warn!(
                "Commit {} had no parents; unable to identify a base set of test cases that has already been run.  All test cases will be run.",
                scm.get_commit_identifier(&commit)
            );
            return Ok(None);
        } else if parents.len() > 1 {
            // If the commit had multiple parents, try to find their common ancestor and continue looking for coverage
            // data at that point.
            if let Ok(Some(common_ancestor)) = scm.get_best_common_ancestor(&parents) {
                commit = common_ancestor;
            } else {
                warn!(
                    "unable to identify common ancestor for parent commits of {}",
                    scm.get_commit_identifier(&commit)
                );
                return Ok(None);
            }
        } else {
            commit = parents.remove(0);
        }
        let commit_identifier = scm.get_commit_identifier(&commit);
        coverage_data = coverage_db
            .read_coverage_data::<TP>(project_name, &commit_identifier, tags)
            .await?;
        trace!(
            "commit id {} had coverage data? {:}",
            commit_identifier,
            coverage_data.is_some()
        );
    }

    Ok(Some(AncestorCommit {
        ancestor_commit: commit,
        coverage_data: coverage_data.unwrap(),
    }))
}

/// Compute which test cases need to be run based upon what changes are being made, and stored coverage data from
/// previous test runs.  A coverage database from `find_ancestor_commit_with_coverage_data` is typically used.
///
/// Concept for relevant test cases:
///
/// - All test cases that have never been seen before are relevant to be run.  As we store in the coverage data a
///   complete record of test cases, whether they were run or not, we can determine what test cases haven't been seen
///   before by finding the most recent commit with coverage data.
///
/// - For changed files -- because the coverage data is a complete denormalization of all coverage data, even if the
///   previous commit only ran a subset of tests, it is easy to just look up all touched points in the coverage data and
///   coalesce them.
#[instrument(skip_all, fields(perftrace = "analyze-tests-to-run"))]
fn compute_relevant_test_cases<TI: TestIdentifier, CI: CoverageIdentifier>(
    eval_target_test_cases: &HashSet<TI>,
    eval_target_changed_files: &HashSet<PathBuf>,
    coverage_data: &FullCoverageData<TI, CI>,
) -> Result<HashMap<TI, HashSet<TestReason<CI>>>> {
    let mut retval = HashMap::new();

    compute_all_new_test_cases(eval_target_test_cases, coverage_data, &mut retval);
    debug!(
        "relevant test cases after searching for new tests: {:?}",
        retval
    );

    // If retval already contains all the test cases, then we're done -- we don't need to start digging into the
    // modified files because we're already running all tests.
    if retval.len() == eval_target_test_cases.len() {
        return Ok(retval);
    }

    for changed_file in eval_target_changed_files {
        compute_changed_file_test_cases(
            eval_target_test_cases,
            changed_file,
            coverage_data,
            &mut retval,
            &mut HashSet::with_capacity(eval_target_changed_files.len()),
            None,
        )?;
    }
    debug!(
        "relevant test cases after searching for file changes: {:?}",
        retval
    );

    Ok(retval)
}

fn compute_all_new_test_cases<TI: TestIdentifier, CI: CoverageIdentifier>(
    eval_target_test_cases: &HashSet<TI>,
    coverage_data: &FullCoverageData<TI, CI>,
    retval: &mut HashMap<TI, HashSet<TestReason<CI>>>,
) {
    for tc in eval_target_test_cases {
        if !coverage_data.all_tests().contains(tc) {
            trace!(
                "test case {:?} was not found in parent coverage data and so will be run as a new test",
                tc
            );
            retval
                .entry(tc.clone())
                .or_default()
                .insert(TestReason::NewTest);
        }
    }
}

fn compute_changed_file_test_cases<TI: TestIdentifier, CI: CoverageIdentifier>(
    eval_target_test_cases: &HashSet<TI>,
    changed_file: &PathBuf,
    coverage_data: &FullCoverageData<TI, CI>,
    retval: &mut HashMap<TI, HashSet<TestReason<CI>>>,
    recurse_ignore_files: &mut HashSet<PathBuf>,
    override_reason: Option<&TestReason<CI>>,
) -> Result<()> {
    if !recurse_ignore_files.insert(changed_file.clone()) {
        return Ok(());
    }

    let default_reason = TestReason::FileChanged(changed_file.clone());
    let reason = override_reason.unwrap_or(&default_reason);
    if let Some(tests) = coverage_data.file_to_test_map().get(changed_file) {
        for test in tests {
            debug!("need to run test {test:?}");
            // Even if this test covered this file in the past, if the test doesn't exist in the current eval target
            // then we can't run it anymore; typically happens when a test case is removed.
            if eval_target_test_cases.contains(test) {
                retval
                    .entry(test.clone())
                    .or_default()
                    .insert(reason.clone());
            }
        }
    }

    if let Some(referencing_files) = coverage_data
        .file_referenced_by_files_map()
        .get(changed_file)
    {
        if !referencing_files.is_empty() {
            // Treat all the "referencing files", which are files that had some reference to the changed file, as-if
            // they were changed because this file was changed.
            for referencing_file in referencing_files {
                compute_changed_file_test_cases(
                    eval_target_test_cases,
                    referencing_file,
                    coverage_data,
                    retval,
                    recurse_ignore_files,
                    Some(&TestReason::SideEffect(
                        // Because this occurred (probably a FileChanged)
                        Box::new(reason.clone()),
                        // We treated it like this file changed:
                        Box::new(TestReason::FileChanged(referencing_file.clone())),
                    )),
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        cmd::get_test_identifiers::{
            AncestorSearchMode, compute_relevant_test_cases,
            find_ancestor_commit_with_coverage_data,
        },
        coverage::{
            CoverageDatabase, CoverageDatabaseDetailedError, Tag,
            commit_coverage_data::{CommitCoverageData, CoverageIdentifier, FileCoverage},
            full_coverage_data::FullCoverageData,
        },
        platform::{
            TestIdentifier, TestPlatform,
            rust::{
                RustConcreteTestIdentifier, RustCoverageIdentifier, RustTestBinary,
                RustTestIdentifier, RustTestPlatform,
            },
        },
        scm::Scm,
    };
    use lazy_static::lazy_static;
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::Value;
    use std::{
        collections::{HashMap, HashSet},
        path::PathBuf,
        time::Duration,
    };

    lazy_static! {
        static ref test1: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
        static ref test2: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test2".to_string(),
            }
        };
        static ref test3: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("sub_module/src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
        static ref sample_test_case_1: RustConcreteTestIdentifier = {
            RustConcreteTestIdentifier {
                test_binary: RustTestBinary {
                    rel_src_path: PathBuf::from("src/lib.rs"),
                    executable_path: PathBuf::from("target/crate/debug/crate-test"),
                    manifest_path: PathBuf::from("Cargo.toml"),
                },
                test_identifier: test1.clone(),
            }
        };
        static ref sample_test_case_2: RustConcreteTestIdentifier = {
            RustConcreteTestIdentifier {
                test_binary: RustTestBinary {
                    rel_src_path: PathBuf::from("src/lib.rs"),
                    executable_path: PathBuf::from("target/crate/debug/crate-test"),
                    manifest_path: PathBuf::from("Cargo.toml"),
                },
                test_identifier: test2.clone(),
            }
        };
    }

    #[derive(Clone, Default)]
    struct MockScmCommit {
        id: String,
        parents: Vec<String>,
        best_common_ancestor: Option<String>,
    }

    impl crate::scm::ScmCommit for MockScmCommit {}

    struct MockScm {
        head_commit: String,
        commits: Vec<MockScmCommit>,
    }

    impl MockScm {
        fn get_commit(&self, commit_id: &String) -> Option<MockScmCommit> {
            for commit in &self.commits {
                if self.get_commit_identifier(commit) == *commit_id {
                    return Some(commit.clone());
                }
            }
            None
        }
    }

    impl crate::scm::Scm<MockScmCommit> for MockScm {
        fn get_changed_files(
            &self,
            _commit: &MockScmCommit,
        ) -> anyhow::Result<std::collections::HashSet<std::path::PathBuf>> {
            unreachable!() // not required for these tests
        }

        fn get_head_commit(&self) -> anyhow::Result<MockScmCommit> {
            match self.get_commit(&self.head_commit) {
                Some(commit) => Ok(commit),
                None => Err(anyhow::anyhow!("test error: no head commit found")),
            }
        }

        fn get_commit_identifier(&self, commit: &MockScmCommit) -> String {
            commit.id.clone()
        }

        fn get_commit_parents(&self, commit: &MockScmCommit) -> anyhow::Result<Vec<MockScmCommit>> {
            let mut retval = vec![];
            for parent in &commit.parents {
                match self.get_commit(parent) {
                    Some(commit) => retval.push(commit),
                    None => return Err(anyhow::anyhow!("test error: no parent commit found")),
                }
            }
            Ok(retval)
        }

        fn get_best_common_ancestor(
            &self,
            commits: &[MockScmCommit],
        ) -> anyhow::Result<Option<MockScmCommit>> {
            // best common ancestor will just be stored on the commits for mock testing; we'll just sanity check that the mock data isn't broken
            let bce: Option<String> = commits[0].best_common_ancestor.clone();
            for commit in &commits[1..] {
                if commit.best_common_ancestor != bce {
                    return Err(anyhow::anyhow!("test error: best common ancestor mismatch"));
                }
            }
            Ok(bce.map(|bce| self.get_commit(&bce).unwrap()))
        }

        fn is_working_dir_clean(&self) -> anyhow::Result<bool> {
            unreachable!()
        }

        fn fetch_file_content(
            &self,
            _commit: &MockScmCommit,
            _path: &std::path::Path,
        ) -> anyhow::Result<Vec<u8>> {
            unreachable!()
        }

        fn checkout(&self, _commit: &MockScmCommit) -> anyhow::Result<()> {
            unreachable!()
        }

        fn clean_lightly(&self) -> anyhow::Result<()> {
            unreachable!()
        }

        fn get_all_repo_files(&self) -> anyhow::Result<HashSet<PathBuf>> {
            unreachable!()
        }
    }

    struct MockCoverageDatabase {
        commit_data: HashMap<String, Value>,
    }

    impl CoverageDatabase for MockCoverageDatabase {
        async fn save_coverage_data<TP>(
            &self,
            _project_name: &str,
            _coverage_data: &CommitCoverageData<TP::TI, TP::CI>,
            _commit_identifier: &str,
            _ancestor_commit_identifier: Option<&str>,
            _tags: &[Tag],
        ) -> Result<(), CoverageDatabaseDetailedError>
        where
            TP: TestPlatform,
            TP::TI: TestIdentifier + Serialize + DeserializeOwned,
            TP::CI: CoverageIdentifier + Serialize + DeserializeOwned,
        {
            // save_coverage_data should never be used on this mock
            unreachable!()
        }

        async fn read_coverage_data<TP>(
            &self,
            _project_name: &str,
            commit_identifier: &str,
            _tags: &[Tag],
        ) -> Result<Option<FullCoverageData<TP::TI, TP::CI>>, CoverageDatabaseDetailedError>
        where
            TP: TestPlatform,
            TP::TI: TestIdentifier + Serialize + DeserializeOwned,
            TP::CI: CoverageIdentifier + Serialize + DeserializeOwned,
        {
            match self.commit_data.get(commit_identifier) {
                Some(data) => Ok(Some(serde_json::from_value(data.clone())?)),
                None => Ok(None),
            }
        }

        async fn has_any_coverage_data<TP: TestPlatform>(
            &self,
            _project_name: &str,
        ) -> Result<bool, CoverageDatabaseDetailedError> {
            // has_any_coverage_data not currently used
            Ok(!self.commit_data.is_empty())
        }

        async fn clear_project_data<TP: TestPlatform>(
            &self,
            _project_name: &str,
        ) -> Result<(), CoverageDatabaseDetailedError> {
            // Not used in testing
            unreachable!()
        }

        async fn intermittent_clean(
            &self,
            _older_than: &Duration,
        ) -> Result<(), CoverageDatabaseDetailedError> {
            // Not used in testing
            unreachable!()
        }
    }

    #[tokio::test]
    async fn find_ancestor_no_coverage() {
        let scm = MockScm {
            head_commit: String::from("abc"),
            commits: vec![MockScmCommit {
                id: String::from("abc"),
                parents: vec![],
                ..Default::default()
            }],
        };
        let result = find_ancestor_commit_with_coverage_data::<_, _, RustTestPlatform>(
            "testtrim-tests",
            &scm,
            scm.get_head_commit().unwrap(),
            AncestorSearchMode::AllCommits,
            &MockCoverageDatabase {
                commit_data: HashMap::new(),
            },
            &[],
        )
        .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn find_ancestor_direct_coverage() {
        let scm = MockScm {
            head_commit: String::from("c2"),
            commits: vec![
                MockScmCommit {
                    id: String::from("c2"),
                    parents: vec![String::from("c1")],
                    ..Default::default()
                },
                MockScmCommit {
                    id: String::from("c1"),
                    parents: vec![],
                    ..Default::default()
                },
            ],
        };
        let mut previous_coverage_data = FullCoverageData::<_, RustCoverageIdentifier>::new();
        previous_coverage_data.add_existing_test(test1.clone());
        let result = find_ancestor_commit_with_coverage_data::<_, _, RustTestPlatform>(
            "testtrim-tests",
            &scm,
            scm.get_head_commit().unwrap(),
            AncestorSearchMode::AllCommits,
            &MockCoverageDatabase {
                commit_data: HashMap::from([(
                    String::from("c2"),
                    serde_json::to_value(previous_coverage_data).unwrap(),
                )]),
            },
            &[],
        )
        .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let ancestor = result.unwrap();
        assert_eq!(scm.get_commit_identifier(&ancestor.ancestor_commit), "c2");
        assert_eq!(ancestor.coverage_data.all_tests().len(), 1);
    }

    #[tokio::test]
    async fn find_ancestor_skip_branch_coverage() {
        let scm = MockScm {
            head_commit: String::from("fake-head"),
            commits: vec![
                MockScmCommit {
                    id: String::from("fake-head"),
                    parents: vec![String::from("merge")],
                    ..Default::default()
                },
                MockScmCommit {
                    id: String::from("merge"),
                    parents: vec![String::from("branch-a"), String::from("branch-b")],
                    ..Default::default()
                },
                MockScmCommit {
                    id: String::from("branch-a"),
                    parents: vec![String::from("ancestor")],
                    best_common_ancestor: Some(String::from("ancestor")),
                },
                MockScmCommit {
                    id: String::from("branch-b"),
                    parents: vec![String::from("ancestor")],
                    best_common_ancestor: Some(String::from("ancestor")),
                },
                MockScmCommit {
                    id: String::from("ancestor"),
                    parents: vec![],
                    ..Default::default()
                },
            ],
        };

        let mut branch_coverage_data = FullCoverageData::<_, RustCoverageIdentifier>::new();
        branch_coverage_data.add_existing_test(test1.clone());
        branch_coverage_data.add_existing_test(test2.clone());
        branch_coverage_data.add_existing_test(test3.clone());

        let mut ancestor_coverage_data = FullCoverageData::<_, RustCoverageIdentifier>::new();
        ancestor_coverage_data.add_existing_test(test1.clone());
        ancestor_coverage_data.add_existing_test(test3.clone());

        let result = find_ancestor_commit_with_coverage_data::<_, _, RustTestPlatform>(
            "testtrim-tests",
            &scm,
            scm.get_head_commit().unwrap(),
            AncestorSearchMode::AllCommits,
            &MockCoverageDatabase {
                commit_data: HashMap::from([
                    (
                        String::from("branch-a"),
                        serde_json::to_value(branch_coverage_data).unwrap(),
                    ),
                    (
                        String::from("ancestor"),
                        serde_json::to_value(ancestor_coverage_data).unwrap(),
                    ),
                ]),
            },
            &[],
        )
        .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(
            scm.get_commit_identifier(&result.ancestor_commit),
            "ancestor"
        );
        assert_eq!(result.coverage_data.all_tests().len(), 2); // ancestor is the only one missing test2
    }

    #[test]
    fn compute_empty_case() {
        let result = compute_relevant_test_cases::<RustTestIdentifier, RustCoverageIdentifier>(
            &HashSet::new(),
            &HashSet::new(),
            &FullCoverageData::new(),
        );
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn compute_all_new_cases_empty_dbs() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new(),
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&test1));
    }

    #[test]
    fn compute_all_new_cases_are_in_previous_commit() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());

        let mut previous_coverage_data =
            FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &previous_coverage_data,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn compute_some_new_cases_are_in_previous_commit() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());
        eval_target_test_cases.insert(test2.clone());

        let mut previous_coverage_data =
            FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &previous_coverage_data,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&test2));
    }

    #[test]
    fn compute_no_new_cases_one_file_changed() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());

        let mut eval_target_changed_files: HashSet<PathBuf> = HashSet::new();
        eval_target_changed_files.insert(PathBuf::from("src/lib.rs"));

        let mut previous_coverage_data =
            FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        previous_coverage_data.add_existing_test(test1.clone());
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test1.clone(),
        });

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &eval_target_changed_files,
            &previous_coverage_data,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&test1));
    }

    #[test]
    fn compute_no_new_cases_one_file_changed_w_outdated_test() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());

        let mut eval_target_changed_files: HashSet<PathBuf> = HashSet::new();
        eval_target_changed_files.insert(PathBuf::from("src/lib.rs"));

        let mut previous_coverage_data =
            FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        previous_coverage_data.add_existing_test(test1.clone());
        previous_coverage_data.add_existing_test(test2.clone()); // test2 doesn't exist in current set, but does exist in historical data
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test1.clone(),
        });
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test2.clone(),
        });

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &eval_target_changed_files,
            &previous_coverage_data,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&test1));
    }

    #[test]
    fn compute_no_new_cases_one_file_changed_another_not() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());
        eval_target_test_cases.insert(test2.clone());

        let mut eval_target_changed_files: HashSet<PathBuf> = HashSet::new();
        eval_target_changed_files.insert(PathBuf::from("src/file2.rs"));

        let mut previous_coverage_data =
            FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        previous_coverage_data.add_existing_test(test1.clone());
        previous_coverage_data.add_existing_test(test2.clone());
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/file1.rs"),
            test_identifier: test1.clone(),
        });
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/file2.rs"),
            test_identifier: test2.clone(),
        });

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &eval_target_changed_files,
            &previous_coverage_data,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&test2));
    }
}
