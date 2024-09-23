use crate::util::ChangeWorkingDirectory;
use anyhow::Result;
use lazy_static::lazy_static;
use std::process::Command;
use std::{env, sync::Mutex};
use tempdir::TempDir;
use testtrim::scm_git::GitScm;
use testtrim::{get_target_test_cases, run_tests_subcommand, GetTestIdentifierMode};
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

fn git_clone() -> Result<()> {
    // If the environment variable RUST_COVERAGE_SPECIMEN_PAT is set, then we'll compose the repo URL with that token as
    // a PAT for authentication.  Otherwise we'll use the ssh URL and assume that the user's environment will provide
    // the required auth.
    let auth_token = env::var("RUST_COVERAGE_SPECIMEN_PAT").ok();
    let repo_url = match auth_token {
        Some(token) => format!(
            "https://:{}@forgejo.kainnef.com/mfenniak/rust-coverage-specimen.git",
            token
        ),
        None => "forgejo@ssh.forgejo.kainnef.com:mfenniak/rust-coverage-specimen.git".to_string(),
    };

    let output = Command::new("git")
        .args(&["clone", &repo_url])
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
        .args(&["checkout", commit])
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
    let _cwd_mutex = CWD_MUTEX.lock();

    let tmp_dir = TempDir::new("testtrim-test")?;
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(tmp_dir.path());

    git_clone()?;
    let _tmp_dir_cwd2 = ChangeWorkingDirectory::new(&tmp_dir.path().join("rust-coverage-specimen")); // FIXME: hack assumes folder name

    // FIXME: This will run with the env of the testtrim project, which is OK for the short-term -- but it would make
    // sense that we pick up the right rust tooling from the checked out repo.  Probably from here we need to start a
    // shell and read .envrc, for any future commands?

    struct CommitTestData<'a> {
        test_commit: &'a str,
        all_test_cases: Vec<&'a str>,
        relevant_test_cases: Vec<&'a str>,
    }
    let test_commits = vec![
        CommitTestData {
            test_commit: "base",
            all_test_cases: vec!["basic_ops::tests::test_add", "basic_ops::tests::test_sub"],
            relevant_test_cases: vec!["basic_ops::tests::test_add", "basic_ops::tests::test_sub"],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "sequences::tests::test_fibonacci",
            ],
            relevant_test_cases: vec!["sequences::tests::test_fibonacci"],
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
        },
    ];

    fn execute_test(commit_test_data: &CommitTestData) -> Result<()> {
        git_checkout(commit_test_data.test_commit)?;

        let all_test_cases = get_target_test_cases(&GetTestIdentifierMode::All, GitScm {})?;
        assert_eq!(
            all_test_cases.iter().count(),
            commit_test_data.all_test_cases.len(),
            "unexpected count of all tests in {} commit",
            commit_test_data.test_commit,
        );
        for expected_test_name in commit_test_data.all_test_cases.iter() {
            assert_eq!(
                all_test_cases
                    .iter()
                    .filter(|tc| tc.test_identifier.test_name == *expected_test_name)
                    .count(),
                1
            );
        }

        let relevant_test_cases =
            get_target_test_cases(&GetTestIdentifierMode::Relevant, GitScm {})?;
        assert_eq!(
            relevant_test_cases.iter().count(),
            commit_test_data.relevant_test_cases.len(),
            "unexpected count of tests-to-run in {} commit",
            commit_test_data.test_commit,
        );
        for expected_test_name in commit_test_data.relevant_test_cases.iter() {
            assert_eq!(
                relevant_test_cases
                    .iter()
                    .filter(|tc| tc.test_identifier.test_name == *expected_test_name)
                    .count(),
                1
            );
        }

        run_tests_subcommand(&GetTestIdentifierMode::Relevant)?;

        Ok(())
    }

    for commit_test_data in test_commits {
        execute_test(&commit_test_data)?;
    }

    Ok(())
}
