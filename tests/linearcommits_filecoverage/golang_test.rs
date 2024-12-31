// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use log::info;
use std::collections::HashSet;
use std::sync::Arc;
use tempdir::TempDir;
use testtrim::cmd::cli::{GetTestIdentifierMode, PlatformTaggingMode, SourceMode};
use testtrim::cmd::get_test_identifiers::{self, get_target_test_cases, AncestorSearchMode};
use testtrim::cmd::run_tests::run_tests;
use testtrim::coverage::{create_test_db, CoverageDatabase};
use testtrim::errors::{RunTestsCommandErrors, RunTestsErrors};
use testtrim::platform::golang::{
    GolangCoverageIdentifier, GolangTestIdentifier, GolangTestPlatform,
};
use testtrim::platform::ConcreteTestIdentifier as _;
use testtrim::scm::git::GitScm;
use testtrim::timing_tracer::{PerformanceStorage, PerformanceStoringTracingSubscriber};
use tracing::instrument::WithSubscriber as _;

use crate::util::ChangeWorkingDirectory;
use crate::{assert_performance_tracing, git_checkout, git_clone, CWD_MUTEX};

#[tokio::test]
async fn golang_linearcommits_filecoverage() -> Result<()> {
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())?;

    let _cwd_mutex = CWD_MUTEX.lock();

    let tmp_dir = TempDir::new("testtrim-test")?;
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(tmp_dir.path());

    git_clone("go-coverage-specimen")?;
    let _tmp_dir_cwd2 = ChangeWorkingDirectory::new(&tmp_dir.path().join("go-coverage-specimen")); // FIXME: hack assumes folder name

    let coverage_db = create_test_db::<GolangTestPlatform>()?;
    coverage_db
        .clear_project_data("go-coverage-specimen")
        .await?;

    // FIXME: This will run with the env of the testtrim project, which is OK for the short-term -- but it would make
    // sense that we pick up the right rust tooling from the checked out repo.  Probably from here we need to start a
    // shell and read .envrc, for any future commands?

    struct CommitTestData<'a> {
        test_commit: &'a str,
        all_test_cases: Vec<&'a str>,
        relevant_test_cases: Vec<&'a str>,
        expected_failing_test_cases: Vec<&'a str>,
    }
    let test_commits = vec![
        CommitTestData {
            test_commit: "base",
            all_test_cases: vec!["TestAdd", "TestSub"],
            relevant_test_cases: vec!["TestAdd", "TestSub"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec!["TestAdd", "TestSub", "TestFibonacci"],
            relevant_test_cases: vec!["TestFibonacci"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-2",
            all_test_cases: vec!["TestAdd", "TestSub", "TestMul", "TestDiv", "TestFibonacci"],
            relevant_test_cases: vec!["TestAdd", "TestSub", "TestMul", "TestDiv", "TestFibonacci"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-3",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-4",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial", "TestFibonacciMemo"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-5",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial", "TestFibonacciMemo"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-7",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-8",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-9",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestAddDecimal"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-10",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFibonacciSequence", "TestFactorial"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-11",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacciSequence"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-12",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            relevant_test_cases: vec![
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-13",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            relevant_test_cases: vec![
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-14",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            relevant_test_cases: vec![
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-15",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            relevant_test_cases: vec![
                // FIXME: none of the const modifications are detected properly; this makes some sense as consts would
                // be initialized on every test causing their coverage to be present always, and we eliminate that with
                // the test baselining to avoid false positives.  This will be documented as a known limitation for now.
                //
                // "TestUsingConst", "TestUsingFunctionInit", "TestUsingModuleInit",
            ],
            expected_failing_test_cases: vec![
                // FIXME: see above
                //
                // "TestUsingConst", "TestUsingFunctionInit", "TestUsingModuleInit",
            ],
        },
        CommitTestData {
            test_commit: "check-16",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            relevant_test_cases: vec![],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-17",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
                "TestTCPConnectionToGoogle",
            ],
            relevant_test_cases: vec!["TestTCPConnectionToGoogle"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-18",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
                "TestTCPConnectionToGoogle",
            ],
            relevant_test_cases: vec!["TestTCPConnectionToGoogle"],
            expected_failing_test_cases: vec![],
        },
    ];

    async fn execute_test(
        commit_test_data: &CommitTestData<'_>,
        coverage_db: &impl CoverageDatabase<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<()> {
        let scm = GitScm {};
        let tags = &get_test_identifiers::tags::<GolangTestPlatform>(
            &Vec::new(),
            PlatformTaggingMode::Automatic,
        );

        info!("checking out {}", commit_test_data.test_commit);
        git_checkout(commit_test_data.test_commit)?;

        let all_test_cases = get_target_test_cases::<_, _, _, _, _, _, GolangTestPlatform>(
            GetTestIdentifierMode::All,
            &scm,
            AncestorSearchMode::AllCommits,
            tags,
            coverage_db,
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
                    .filter(|tc| tc.test_identifier().test_name == *expected_test_name)
                    .count(),
                1
            );
        }

        let relevant_test_cases = get_target_test_cases::<_, _, _, _, _, _, GolangTestPlatform>(
            GetTestIdentifierMode::Relevant,
            &scm,
            AncestorSearchMode::AllCommits,
            tags,
            coverage_db,
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
                    .filter(|tc| tc.test_identifier().test_name == *expected_test_name)
                    .count(),
                1
            );
        }

        match run_tests::<_, _, _, _, _, _, GolangTestPlatform>(
            GetTestIdentifierMode::Relevant,
            &scm,
            SourceMode::Automatic,
            0,
            tags,
            coverage_db,
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
                    // have to be RustTestIdentifier instances and can be &str.  It makes these tests slightly easier to
                    // write & maintain.
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

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test(&commit_test_data, &coverage_db)
            .with_subscriber(PerformanceStoringTracingSubscriber::new(
                perf_storage.clone(),
            ))
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}
