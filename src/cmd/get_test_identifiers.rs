// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use log::{error, info, trace, warn};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::{collections::HashSet, path::PathBuf};
use tracing::instrument;

use crate::timing_tracer::{PerformanceStorage, PerformanceStoringTracingSubscriber};
use crate::{
    commit_coverage_data::CoverageIdentifier,
    db::{CoverageDatabase, DieselCoverageDatabase},
    full_coverage_data::FullCoverageData,
    platform::{
        rust::RustTestPlatform, ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform,
    },
    scm::{git::GitScm, Scm, ScmCommit},
};

use super::cli::GetTestIdentifierMode;

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub fn cli(test_selection_mode: &GetTestIdentifierMode) {
    let perf_storage = Arc::new(PerformanceStorage::new());
    let my_subscriber = PerformanceStoringTracingSubscriber::new(perf_storage.clone());

    tracing::subscriber::with_default(my_subscriber, || {
        let test_cases = match get_target_test_cases::<_, _, _, _, _, _, RustTestPlatform>(
            test_selection_mode,
            &GitScm {},
            AncestorSearchMode::AllCommits,
        ) {
            Ok(test_cases) => test_cases,
            Err(err) => {
                error!("error occurred in get_target_test_cases: {:?}", err);
                return;
            }
        };
        for test_case in test_cases.target_test_cases {
            println!("{:?}", test_case.test_identifier);
        }
    });

    // FIXME: probably not the right choice to print this to stdout; ideally this cli command just prints the test
    // identifiers.
    println!("Performance stats:");
    perf_storage.print();
}

pub struct TargetTestCases<Commit: ScmCommit, TI: TestIdentifier, CTI: ConcreteTestIdentifier<TI>> {
    // Test discovery and analysis results
    pub all_test_cases: HashSet<CTI>,
    pub target_test_cases: HashSet<CTI>,
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

pub fn get_target_test_cases<Commit, MyScm, TI, CI, TD, CTI, TP>(
    mode: &GetTestIdentifierMode,
    scm: &MyScm,
    ancestor_search_mode: AncestorSearchMode,
) -> Result<TargetTestCases<Commit, TI, CTI>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI, CI, TD, CTI>,
{
    let test_discovery = TP::discover_tests()?;
    let all_test_cases = test_discovery.all_test_cases();

    if *mode == GetTestIdentifierMode::All {
        return Ok(TargetTestCases {
            all_test_cases: all_test_cases.clone(),
            target_test_cases: all_test_cases.clone(),
            ancestor_commit: None,
            files_changed: None,
            external_dependencies_changed: None,
            test_identifier_type: PhantomData,
        });
    }

    let (ancestor_commit, coverage_data) = if let Some((ancestor_commit, coverage_data)) =
        find_ancestor_commit_with_coverage_data::<Commit, MyScm, TI, CI>(
            scm,
            scm.get_head_commit()?,
            ancestor_search_mode,
            &mut (DieselCoverageDatabase::<TI, CI>::new_sqlite_from_default_path()),
        )? {
        info!(
            "relevant test cases will be computed base upon commit {:?}",
            scm.get_commit_identifier(&ancestor_commit)
        );
        (ancestor_commit, coverage_data)
    } else {
        warn!("no base commit identified with coverage data to work from");
        return Ok(TargetTestCases {
            all_test_cases: all_test_cases.clone(),
            target_test_cases: all_test_cases.clone(),
            ancestor_commit: None,
            files_changed: None,
            external_dependencies_changed: None,
            test_identifier_type: PhantomData,
        });
    };

    let changed_files = scm.get_changed_files(&ancestor_commit)?;
    trace!("changed files: {:?}", changed_files);

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
    relevant_test_cases.extend(platform_specific.additional_test_cases);

    trace!("relevant_test_cases: {:?}", relevant_test_cases);

    Ok(TargetTestCases {
        all_test_cases: all_test_cases.clone(),
        target_test_cases: relevant_test_cases
            .into_iter()
            .filter_map(|ti| test_discovery.map_ti_to_cti(ti))
            .collect::<HashSet<_>>(),
        ancestor_commit: Some(ancestor_commit),
        files_changed: Some(changed_files),
        external_dependencies_changed: platform_specific.external_dependencies_changed,
        test_identifier_type: PhantomData,
    })
}

/// Identify a useable commit which has stored coverage data and can be used as a basis for determining which tests to
/// run in this project.
///
/// A useable commit is one that doesn't come from a branch, as coverage data could change during a merge making any
/// branch commits an incorrect source of data.  Commits are searched starting at HEAD and going towards their ancestors
/// checking for any coverage data.  If a merge commit is found, then the search skips to the best common ancestor to
/// both parents of the merge commit, and continues from there.
#[instrument(skip_all, fields(perftrace = "read-coverage-data"))]
fn find_ancestor_commit_with_coverage_data<Commit, MyScm, TI, CI>(
    scm: &MyScm,
    head: Commit,
    ancestor_search_mode: AncestorSearchMode,
    coverage_db: &mut impl CoverageDatabase<TI, CI>,
) -> Result<Option<(Commit, FullCoverageData<TI, CI>)>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier,
    CI: CoverageIdentifier,
{
    if !coverage_db.has_any_coverage_data()? {
        return Ok(None);
    }

    let mut commit = head;
    let commit_identifier = scm.get_commit_identifier(&commit);
    let mut coverage_data = match ancestor_search_mode {
        AncestorSearchMode::AllCommits => {
            let coverage_data = coverage_db.read_coverage_data(&commit_identifier)?;
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
            warn!("Commit {} had no parents; unable to identify a base set of test cases that has already been run.  All test cases will be run.", scm.get_commit_identifier(&commit));
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
        coverage_data = coverage_db.read_coverage_data(&commit_identifier)?;
        trace!(
            "commit id {} had coverage data? {:}",
            commit_identifier,
            coverage_data.is_some()
        );
    }

    Ok(Some((commit, coverage_data.unwrap())))
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
) -> Result<HashSet<TI>> {
    let mut retval = HashSet::new();

    compute_all_new_test_cases(eval_target_test_cases, coverage_data, &mut retval);
    trace!(
        "relevant test cases after searching for new tests: {:?}",
        retval
    );

    // If retval already contains all the test cases, then we're done -- we don't need to start digging into the
    // modified files because we're already running all tests.
    if retval.len() == eval_target_test_cases.len() {
        return Ok(retval);
    }

    compute_changed_file_test_cases(
        eval_target_test_cases,
        eval_target_changed_files,
        coverage_data,
        &mut retval,
        &mut HashSet::with_capacity(eval_target_changed_files.len()),
    )?;
    trace!(
        "relevant test cases after searching for file changes: {:?}",
        retval
    );

    Ok(retval)
}

fn compute_all_new_test_cases<TI: TestIdentifier, CI: CoverageIdentifier>(
    eval_target_test_cases: &HashSet<TI>,
    coverage_data: &FullCoverageData<TI, CI>,
    retval: &mut HashSet<TI>,
) {
    for tc in eval_target_test_cases {
        if !coverage_data.all_tests().contains(tc) {
            trace!("test case {:?} was not found in parent coverage data and so will be run as a new test", tc);
            retval.insert(tc.clone());
        }
    }
}

fn compute_changed_file_test_cases<TI: TestIdentifier, CI: CoverageIdentifier>(
    eval_target_test_cases: &HashSet<TI>,
    eval_target_changed_files: &HashSet<PathBuf>,
    coverage_data: &FullCoverageData<TI, CI>,
    retval: &mut HashSet<TI>,
    recurse_ignore_files: &mut HashSet<PathBuf>,
) -> Result<()> {
    for changed_file in eval_target_changed_files {
        // As this function recurses (by referenced files), avoid processing the same file twice.
        if !recurse_ignore_files.insert(changed_file.clone()) {
            continue;
        }

        if let Some(tests) = coverage_data.file_to_test_map().get(changed_file) {
            for test in tests {
                // Even if this test covered this file in the past, if the test doesn't exist in the current eval target
                // then we can't run it anymore; typically happens when a test case is removed.
                if eval_target_test_cases.contains(test) {
                    retval.insert(test.clone());
                }
            }
        }

        if let Some(referencing_files) = coverage_data
            .file_referenced_by_files_map()
            .get(changed_file)
            && !referencing_files.is_empty()
        {
            // Treat all the "referencing files", which are files that had some reference to the changed file, as-if
            // they were changed because this file was changed.
            compute_changed_file_test_cases(
                eval_target_test_cases,
                referencing_files,
                coverage_data,
                retval,
                recurse_ignore_files,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        cmd::get_test_identifiers::{
            compute_relevant_test_cases, find_ancestor_commit_with_coverage_data,
            AncestorSearchMode,
        },
        commit_coverage_data::{CommitCoverageData, FileCoverage},
        db::CoverageDatabase,
        full_coverage_data::FullCoverageData,
        platform::rust::{
            RustConcreteTestIdentifier, RustCoverageIdentifier, RustTestBinary, RustTestIdentifier,
        },
        scm::Scm,
    };
    use lazy_static::lazy_static;
    use std::{
        collections::{HashMap, HashSet},
        path::PathBuf,
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
            for commit in self.commits.iter() {
                if self.get_commit_identifier(&commit) == *commit_id {
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
            for parent in commit.parents.iter() {
                match self.get_commit(&parent) {
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
            for commit in commits[1..].iter() {
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
        commit_data: HashMap<String, FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>>,
    }

    impl CoverageDatabase<RustTestIdentifier, RustCoverageIdentifier> for MockCoverageDatabase {
        fn save_coverage_data(
            &mut self,
            _coverage_data: &CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
            _commit_sha: &str,
            _ancestor_commit_sha: Option<&str>,
        ) -> anyhow::Result<()> {
            // save_coverage_data should never be used on this mock
            unreachable!()
        }

        fn read_coverage_data(
            &mut self,
            commit_sha: &str,
        ) -> anyhow::Result<Option<FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>>>
        {
            match self.commit_data.get(commit_sha) {
                Some(data) => Ok(Some(data.clone())),
                None => Ok(None),
            }
            // Ok(self.commit_data.get(commit_sha).cloned())
            // todo!()
        }

        fn has_any_coverage_data(&mut self) -> anyhow::Result<bool> {
            // has_any_coverage_data not currently used
            Ok(!self.commit_data.is_empty())
        }

        fn clear_project_data(&mut self) -> anyhow::Result<()> {
            // Not used in testing
            unreachable!()
        }
    }

    #[test]
    fn find_ancestor_no_coverage() {
        let scm = MockScm {
            head_commit: String::from("abc"),
            commits: vec![MockScmCommit {
                id: String::from("abc"),
                parents: vec![],
                ..Default::default()
            }],
        };
        let result = find_ancestor_commit_with_coverage_data(
            &scm,
            scm.get_head_commit().unwrap(),
            AncestorSearchMode::AllCommits,
            &mut MockCoverageDatabase {
                commit_data: HashMap::new(),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn find_ancestor_direct_coverage() {
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
        let mut previous_coverage_data = FullCoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());
        let result = find_ancestor_commit_with_coverage_data(
            &scm,
            scm.get_head_commit().unwrap(),
            AncestorSearchMode::AllCommits,
            &mut MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("c2"), previous_coverage_data)]),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let (result_commit, result_coverage_data) = result.unwrap();
        assert_eq!(scm.get_commit_identifier(&result_commit), "c2");
        assert_eq!(result_coverage_data.all_tests().len(), 1);
    }

    #[test]
    fn find_ancestor_skip_branch_coverage() {
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

        let mut branch_coverage_data = FullCoverageData::new();
        branch_coverage_data.add_existing_test(test1.clone());
        branch_coverage_data.add_existing_test(test2.clone());
        branch_coverage_data.add_existing_test(test3.clone());

        let mut ancestor_coverage_data = FullCoverageData::new();
        ancestor_coverage_data.add_existing_test(test1.clone());
        ancestor_coverage_data.add_existing_test(test3.clone());

        let result = find_ancestor_commit_with_coverage_data(
            &scm,
            scm.get_head_commit().unwrap(),
            AncestorSearchMode::AllCommits,
            &mut MockCoverageDatabase {
                commit_data: HashMap::from([
                    (String::from("branch-a"), branch_coverage_data),
                    (String::from("ancestor"), ancestor_coverage_data),
                ]),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let (result_commit, result_coverage_data) = result.unwrap();
        assert_eq!(scm.get_commit_identifier(&result_commit), "ancestor");
        assert_eq!(result_coverage_data.all_tests().len(), 2); // ancestor is the only one missing test2
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
        assert!(result.contains(&test1));
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
        assert!(result.contains(&test2));
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
        assert!(result.contains(&test1));
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
        assert!(result.contains(&test1));
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
        assert!(result.contains(&test2));
    }
}
