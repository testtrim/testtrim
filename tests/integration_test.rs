// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::util::ChangeWorkingDirectory;
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::info;
use std::collections::HashSet;
use std::process::Command;
use std::{env, sync::Mutex};
use tempdir::TempDir;
use testtrim::cmd::cli::{GetTestIdentifierMode, PlatformTaggingMode, SourceMode};
use testtrim::cmd::get_test_identifiers::{self, get_target_test_cases, AncestorSearchMode};
use testtrim::cmd::run_tests::run_tests;
use testtrim::coverage::create_db;
use testtrim::errors::{RunTestsCommandErrors, RunTestsErrors};
use testtrim::platform::dotnet::DotnetTestPlatform;
use testtrim::platform::rust::RustTestPlatform;
use testtrim::scm::git::GitScm;
use thiserror::Error;

mod util;

lazy_static! {
    // Avoid running multiple concurrent tests that modify the CWD by having a mutex that each needs to acquire.
    // There's only one of these tests right now but while doing some dev work I had duplicated it and found this
    // problems, so kept this around as a reminder.
    static ref CWD_MUTEX: Mutex<i32> = Mutex::new(0);
}

#[derive(Error, Debug)]
pub enum TestError {
    #[error(
        "test sub-command '{command:?}' failed with exit code {status:?} and stderr {stderr:?})"
    )]
    SubcommandFailed {
        command: String,
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("test sub-command '{command:?}' had unparseable output; error: {error:?} output: {output:?})")]
    SubcommandOutputParseFailed {
        command: String,
        error: String,
        output: String,
    },
}

fn git_clone(repo: &str) -> Result<()> {
    // If the environment variable RUST_COVERAGE_SPECIMEN_PAT is set, then we'll compose the repo URL with that token as
    // a PAT for authentication.  Otherwise we'll use the ssh URL and assume that the user's environment will provide
    // the required auth.
    let auth_token = env::var("RUST_COVERAGE_SPECIMEN_PAT").ok();
    let repo_url = match auth_token {
        Some(token) => format!("https://:{}@codeberg.org/testtrim/{}.git", token, repo,),
        None => format!("git@codeberg.org:testtrim/{}.git", repo),
    };

    let output = Command::new("git")
        .args(["clone", &repo_url])
        .output()
        .expect("Failed to execute cargo test command");

    // Check for non-zero exit status
    if !output.status.success() {
        return Err(TestError::SubcommandFailed {
            command: "git clone".to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    Ok(())
}

fn git_checkout(commit: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["checkout", commit])
        .output()
        .expect("Failed to execute cargo test command");

    // Check for non-zero exit status
    if !output.status.success() {
        return Err(TestError::SubcommandFailed {
            command: "git checkout".to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    Ok(())
}

#[test]
fn rust_linearcommits_filecoverage() -> Result<()> {
    // simplelog::SimpleLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default())?;

    let _cwd_mutex = CWD_MUTEX.lock();

    let tmp_dir = TempDir::new("testtrim-test")?;
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(tmp_dir.path());

    git_clone("rust-coverage-specimen")?;
    let _tmp_dir_cwd2 = ChangeWorkingDirectory::new(&tmp_dir.path().join("rust-coverage-specimen")); // FIXME: hack assumes folder name

    create_db::<RustTestPlatform>(String::from("rust-coverage-specimen"))?.clear_project_data()?;

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
            all_test_cases: vec!["basic_ops::tests::test_add", "basic_ops::tests::test_sub"],
            relevant_test_cases: vec!["basic_ops::tests::test_add", "basic_ops::tests::test_sub"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "sequences::tests::test_fibonacci",
            ],
            relevant_test_cases: vec!["sequences::tests::test_fibonacci"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-2",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-3",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-4",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-5",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-7",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-8",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-9",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec!["basic_ops::tests::test_add_decimal"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-10",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-11",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec!["sequences::tests::test_fibonacci_sequence"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-12",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-13",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-14",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            relevant_test_cases: vec![
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-15",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            relevant_test_cases: vec![
                // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            expected_failing_test_cases: vec![
                // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
        },
        CommitTestData {
            test_commit: "check-16",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            relevant_test_cases: vec![],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-17",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
                "network::tests::test_tcp_connection_to_google",
            ],
            relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-18",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
                "network::tests::test_tcp_connection_to_google",
            ],
            relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
            expected_failing_test_cases: vec![],
        },
    ];

    fn execute_test(commit_test_data: &CommitTestData) -> Result<()> {
        let scm = GitScm {};
        let tags = &get_test_identifiers::tags(&Vec::new(), PlatformTaggingMode::Automatic);

        info!("checking out {}", commit_test_data.test_commit);
        git_checkout(commit_test_data.test_commit)?;

        let all_test_cases = get_target_test_cases::<_, _, _, _, _, _, RustTestPlatform>(
            GetTestIdentifierMode::All,
            &scm,
            AncestorSearchMode::AllCommits,
            tags,
        )?
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
                    .filter(|tc| tc.test_identifier.test_name == *expected_test_name)
                    .count(),
                1
            );
        }

        let relevant_test_cases = get_target_test_cases::<_, _, _, _, _, _, RustTestPlatform>(
            GetTestIdentifierMode::Relevant,
            &scm,
            AncestorSearchMode::AllCommits,
            tags,
        )?
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
                    .filter(|tc| tc.test_identifier.test_name == *expected_test_name)
                    .count(),
                1
            );
        }

        match run_tests::<_, _, _, _, _, _, RustTestPlatform>(
            GetTestIdentifierMode::Relevant,
            &scm,
            SourceMode::Automatic,
            0,
            tags,
        ) {
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

    for commit_test_data in test_commits {
        execute_test(&commit_test_data)?;
    }

    Ok(())
}

#[test]
fn dotnet_linearcommits_filecoverage() -> Result<()> {
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())?;

    let _cwd_mutex = CWD_MUTEX.lock();

    let tmp_dir = TempDir::new("testtrim-test")?;
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(tmp_dir.path());

    git_clone("dotnet-coverage-specimen")?;
    let _tmp_dir_cwd2 =
        ChangeWorkingDirectory::new(&tmp_dir.path().join("dotnet-coverage-specimen")); // FIXME: hack assumes folder name

    create_db::<DotnetTestPlatform>(String::from("dotnet-coverage-specimen"))?
        .clear_project_data()?;

    // FIXME: This will run with the env of the testtrim project, which is OK for the short-term -- but it would make
    // sense that we pick up the right dotnet tooling from the checked out repo.  Probably from here we need to start a
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
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
            ],
            relevant_test_cases: vec!["MathFunctions.Tests.SequenceTests.TestFibonacci"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-2",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-3",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-4",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-5",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-7",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-8",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
        // TODO: external dependency tracking
        // FIXME: still need preemptive read of packages.lock.json changes at the beginning of a test, and lookup of
        // external dependencies, I think... maybe also the coverage DB storage?  not sure where I'm left at.
        // CommitTestData {
        //     test_commit: "check-9",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //     ],
        //     relevant_test_cases: vec!["MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt"],
        //     expected_failing_test_cases: vec![],
        // },

        // CommitTestData {
        //     test_commit: "check-10",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //     ],
        //     relevant_test_cases: vec![
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //     ],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-11",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //     ],
        //     relevant_test_cases: vec!["MathFunctions.Tests.SequenceTests.TestFibonacci_sequence"],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-12",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //     ],
        //     relevant_test_cases: vec![
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //     ],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-13",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //     ],
        //     relevant_test_cases: vec![
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //     ],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-14",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //         "constant_using_tests::tests::test_using_const",
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //     ],
        //     relevant_test_cases: vec![
        //         "constant_using_tests::tests::test_using_const",
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //     ],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-15",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //         "constant_using_tests::tests::test_using_const",
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //     ],
        //     relevant_test_cases: vec![
        //         // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //     ],
        //     expected_failing_test_cases: vec![
        //         // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //     ],
        // },
        // CommitTestData {
        //     test_commit: "check-16",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //         "constant_using_tests::tests::test_using_const",
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //     ],
        //     relevant_test_cases: vec![],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-17",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
        //         "constant_using_tests::tests::test_using_const",
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //         "network::tests::test_tcp_connection_to_google",
        //     ],
        //     relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
        //     expected_failing_test_cases: vec![],
        // },
        // CommitTestData {
        //     test_commit: "check-18",
        //     all_test_cases: vec![
        //         "MathFunctions.Tests.BasicOpsTests.TestAdd",
        //         "MathFunctions.Tests.BasicOpsTests.TestSub",
        //         "MathFunctions.Tests.BasicOpsTests.TestMul",
        //         "MathFunctions.Tests.BasicOpsTests.TestDiv",
        //         "MathFunctions.Tests.BasicOpsTests.TestPower",
        //         "basic_ops::tests::test_add_decimal",
        //         "MathFunctions.Tests.SequenceTests.TestFibonacci",
        //         "sequences::tests::test_fibonacci_sequence",
        //         "MathFunctions.Tests.SequenceTests.TestFactorial",
        //         "sequences::tests::test_factorial_include",
        //         "constant_using_tests::tests::test_using_const",
        //         "constant_using_tests::tests::test_using_const_fn",
        //         "constant_using_tests::tests::test_using_inline",
        //         "constant_using_tests::tests::test_using_lazy_static",
        //         "network::tests::test_tcp_connection_to_google",
        //     ],
        //     relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
        //     expected_failing_test_cases: vec![],
        // },
    ];

    fn execute_test(commit_test_data: &CommitTestData) -> Result<()> {
        let scm = GitScm {};
        let tags = &get_test_identifiers::tags(&Vec::new(), PlatformTaggingMode::Automatic);

        info!("checking out {}", commit_test_data.test_commit);
        git_checkout(commit_test_data.test_commit)?;

        let all_test_cases = get_target_test_cases::<_, _, _, _, _, _, DotnetTestPlatform>(
            GetTestIdentifierMode::All,
            &scm,
            AncestorSearchMode::AllCommits,
            tags,
        )?
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
                    .filter(|tc| tc.test_identifier.fully_qualified_name == *expected_test_name)
                    .count(),
                1,
                "couldn't find test named {expected_test_name}"
            );
        }

        let relevant_test_cases = get_target_test_cases::<_, _, _, _, _, _, DotnetTestPlatform>(
            GetTestIdentifierMode::Relevant,
            &scm,
            AncestorSearchMode::AllCommits,
            tags,
        )?
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
                    .filter(|tc| tc.test_identifier.fully_qualified_name == *expected_test_name)
                    .count(),
                1
            );
        }

        println!(
            "starting cmd::run_tests for commit {}",
            commit_test_data.test_commit
        );
        match run_tests::<_, _, _, _, _, _, DotnetTestPlatform>(
            GetTestIdentifierMode::Relevant,
            &scm,
            SourceMode::Automatic,
            0,
            tags,
        ) {
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

    for commit_test_data in test_commits {
        execute_test(&commit_test_data)?;
    }

    Ok(())
}
