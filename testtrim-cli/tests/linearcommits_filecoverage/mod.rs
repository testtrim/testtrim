// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Result, anyhow};
use log::info;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use testtrim::cmd::cli::{GetTestIdentifierMode, PlatformTaggingMode, SourceMode};
use testtrim::cmd::get_test_identifiers::{self, AncestorSearchMode, get_target_test_cases};
use testtrim::cmd::run_tests::run_tests;
use testtrim::coverage::{CoverageDatabase, create_test_db};
use testtrim::errors::{RunTestsCommandErrors, RunTestsErrors};
use testtrim::platform::{ConcreteTestIdentifier as _, TestIdentifierCore as _, TestPlatform};
use testtrim::scm::git::GitScm;
use tokio::sync::MutexGuard;

use crate::util::ChangeWorkingDirectory;
use crate::{CWD_MUTEX, git_checkout, git_clone};

mod dotnet_test;
mod golang_test;
mod rust_test;

struct CommitTestData<'a> {
    test_commit: &'a str,
    all_test_cases: Vec<&'a str>,
    relevant_test_cases: Vec<&'a str>,
    expected_failing_test_cases: Vec<&'a str>,
}

async fn setup_test<TP: TestPlatform>(
    test_project: &str,
) -> Result<(
    TempDir,
    ChangeWorkingDirectory,
    MutexGuard<i32>,
    impl CoverageDatabase,
)> {
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())?;

    let _cwd_mutex = CWD_MUTEX.lock().await;

    let tmp_dir = tempfile::Builder::new().prefix("testtrim-test").tempdir()?;
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(tmp_dir.path());
    git_clone(test_project)?;
    drop(_tmp_dir_cwd);

    // FIXME: remove the CWD here so that we can test the new project_dir capabilities
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(&tmp_dir.path().join(test_project)); // FIXME: hack assumes folder name

    let coverage_db = create_test_db()?;
    coverage_db.clear_project_data::<TP>(test_project).await?;

    // FIXME: This will run with the env of the testtrim project, which is OK for the short-term -- but it would make
    // sense that we pick up the right dotnet tooling from the checked out repo.  Probably from here we need to start a
    // shell and read .envrc, for any future commands?

    Ok((tmp_dir, _tmp_dir_cwd, _cwd_mutex, coverage_db))
}

async fn execute_test<TP: TestPlatform>(
    commit_test_data: &CommitTestData<'_>,
    coverage_db: &impl CoverageDatabase,
) -> Result<()> {
    let project_dir = fs::canonicalize(PathBuf::from("."))?;
    let scm = GitScm::new(project_dir.clone());
    let tags = &get_test_identifiers::tags::<TP>(&Vec::new(), PlatformTaggingMode::Automatic);

    info!("checking out {}", commit_test_data.test_commit);
    git_checkout(commit_test_data.test_commit)?;

    let all_test_cases = get_target_test_cases::<_, _, _, _, _, _, TP>(
        &project_dir,
        GetTestIdentifierMode::All,
        &scm,
        AncestorSearchMode::AllCommits,
        tags,
        coverage_db,
        None,
    )
    .await?
    .target_test_cases;
    assert_eq!(
        all_test_cases.len(),
        commit_test_data.all_test_cases.len(),
        "unexpected count of all tests in {} commit",
        commit_test_data.test_commit,
    );
    for expected_test_name in commit_test_data.all_test_cases.iter() {
        assert_eq!(
            all_test_cases
                .keys()
                .filter(|tc| tc.test_identifier().lightly_unique_name() == *expected_test_name)
                .count(),
            1,
            "couldn't find test named {expected_test_name}"
        );
    }

    let relevant_test_cases = get_target_test_cases::<_, _, _, _, _, _, TP>(
        &project_dir,
        GetTestIdentifierMode::Relevant,
        &scm,
        AncestorSearchMode::AllCommits,
        tags,
        coverage_db,
        None,
    )
    .await?
    .target_test_cases;
    assert_eq!(
        relevant_test_cases.len(),
        commit_test_data.relevant_test_cases.len(),
        "unexpected count of tests-to-run in {} commit",
        commit_test_data.test_commit,
    );
    for expected_test_name in commit_test_data.relevant_test_cases.iter() {
        assert_eq!(
            relevant_test_cases
                .keys()
                .filter(|tc| tc.test_identifier().lightly_unique_name() == *expected_test_name)
                .count(),
            1
        );
    }

    println!(
        "starting cmd::run_tests for commit {}",
        commit_test_data.test_commit
    );
    match run_tests::<_, _, _, _, _, _, TP>(
        &project_dir,
        GetTestIdentifierMode::Relevant,
        &scm,
        SourceMode::Automatic,
        0,
        tags,
        coverage_db,
        None,
    )
    .await
    {
        Ok(_) if commit_test_data.expected_failing_test_cases.is_empty() => Ok(()),
        Ok(_) => Err(anyhow!(
            "expected {} failed tests in {} commit, but had zero",
            commit_test_data.expected_failing_test_cases.len(),
            commit_test_data.test_commit
        )),
        Err(RunTestsCommandErrors::RunTestsErrors(RunTestsErrors::TestExecutionFailures(
            failures,
        ))) => {
            let mut expected = commit_test_data
                .expected_failing_test_cases
                .iter()
                .map(|s| String::from(*s))
                .collect::<HashSet<_>>();
            for failure in failures {
                // lightly_unique_name is a dumb hack, but just makes it so that our test cases in this test don't
                // have to be DotnetTestIdentifier instances and can be &str.  It makes these tests slightly easier
                // to write & maintain.
                let test_name = failure.test_identifier.lightly_unique_name();
                if !expected.remove(&test_name) {
                    return Err(anyhow!(
                        "test {test_name} failed in commit {}, but wasn't expected to fail: {failure:?}",
                        commit_test_data.test_commit
                    ));
                }
            }
            if !expected.is_empty() {
                Err(anyhow!(
                    "tests were expected to fail in commit {} but did not fail: {expected:?}",
                    commit_test_data.test_commit
                ))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(e.into()),
    }
}
