use crate::util::ChangeWorkingDirectory;
use anyhow::Result;
use std::env;
use std::process::Command;
use tempdir::TempDir;
use testtrim::{
    compute_relevant_test_cases, find_test_binaries, get_all_test_cases, get_changed_files,
    process_command, run_tests, Cli, Commands,
};
use thiserror::Error;

mod util;

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
fn analyze_base() {
    // FIXME: this is a stub for testing the CLI command later, when these tests aren't just hacked together with half
    // the logic and half the tests in this test file.
    process_command(Cli {
        command: Commands::Noop,
        verbose: clap_verbosity_flag::Verbosity::new(0, 0),
    });
}

// fn write_coverage_data(coverage_data: &CoverageData) -> Result<()> {
//     let output_file = "coverage.json";
//     let mut file = File::create(output_file).context("Failed to create output file")?;
//     serde_json::to_writer_pretty(&mut file, coverage_data).context("Failed to write output file")?;

//     let mut str = String::new();
//     File::open(output_file)?.read_to_string(&mut str)?;
//     trace!("coverage_data: {}", str);

//     Ok(())
// }

// // filter_to_relevant_test_cases takes an iterator of test cases, and for the moment just returns back the same
// // iterator... but in the future we'll remove some test cases that aren't relevant based upon the current patch
// fn filter_to_relevant_test_cases<'a, I>(test_cases: &I) -> I
//     where I: IntoIterator<Item = &'a TestCase>
// {
//     test_cases.collect().iter()
// }

#[test]
fn rust_linearcommits_filecoverage() -> Result<()> {
    let tmp_dir = TempDir::new("testtrim-test")?;
    let _tmp_dir_cwd = ChangeWorkingDirectory::new(tmp_dir.path());

    git_clone()?;
    let _tmp_dir_cwd2 = ChangeWorkingDirectory::new(&tmp_dir.path().join("rust-coverage-specimen")); // FIXME: hack assumes folder name

    // FIXME: This will run with the env of the testtrim project, which is OK for the short-term -- but it would make
    // sense that we pick up the right rust tooling from the checked out repo.  Probably from here we need to start a
    // shell and read .envrc, for any future commands?

    let base_coverage_data = {
        git_checkout("base")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            2,
            "unexpected count of all tests in base commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("base")?,
            vec![],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            2,
            "unexpected count of tests-to-run in base commit"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );

        run_tests(&relevant_test_cases)?
    };

    let check1_coverage_data = {
        git_checkout("check-1")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            3,
            "unexpected count of all tests in check-1 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-1")?,
            vec![&base_coverage_data],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            1,
            "unexpected count of tests-to-run in check-1 commit"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );

        run_tests(&relevant_test_cases)?
    };

    let check2_coverage_data = {
        git_checkout("check-2")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            5,
            "unexpected count of all tests in check-2 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-2")?,
            vec![&check1_coverage_data, &base_coverage_data],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            5,
            "unexpected count of tests-to-run in check-2 commit; {relevant_test_cases:?}"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        ); // changed basic_ops.rs
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        ); // changed basic_ops.rs
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        ); // new
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        ); // new
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        ); // because sequence->basic_ops.rs

        run_tests(&relevant_test_cases)?
    };

    let check3_coverage_data = {
        git_checkout("check-3")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            6,
            "unexpected count of all tests in check-3 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-3")?,
            vec![
                &check2_coverage_data,
                &check1_coverage_data,
                &base_coverage_data,
            ],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            2,
            "unexpected count of tests-to-run in check-3 commit; {relevant_test_cases:?}"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );

        run_tests(&relevant_test_cases)?
    };

    let check4_coverage_data = {
        git_checkout("check-4")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            7,
            "unexpected count of all tests in check-4 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );
        assert_eq!(all_test_cases.iter().filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci_memo").count(), 1);

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-4")?,
            vec![
                &check3_coverage_data,
                &check2_coverage_data,
                &check1_coverage_data,
                &base_coverage_data,
            ],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            3,
            "unexpected count of tests-to-run in check-4 commit; {relevant_test_cases:?}"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );
        assert_eq!(relevant_test_cases.iter().filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci_memo").count(), 1);

        run_tests(&relevant_test_cases)?
    };

    let check5_coverage_data = {
        git_checkout("check-5")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            8,
            "unexpected count of all tests in check-5 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_power")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );
        assert_eq!(all_test_cases.iter().filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci_memo").count(), 1);

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-5")?,
            vec![
                &check4_coverage_data,
                &check3_coverage_data,
                &check2_coverage_data,
                &check1_coverage_data,
                &base_coverage_data,
            ],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            8,
            "unexpected count of tests-to-run in check-5 commit; {relevant_test_cases:?}"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_power")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );
        assert_eq!(relevant_test_cases.iter().filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci_memo").count(), 1);

        run_tests(&relevant_test_cases)?
    };

    let check6_coverage_data = {
        git_checkout("check-6")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            8,
            "unexpected count of all tests in check-6 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_power")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );
        assert_eq!(all_test_cases.iter().filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci_memo").count(), 1);

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-6")?,
            vec![
                &check5_coverage_data,
                &check4_coverage_data,
                &check3_coverage_data,
                &check2_coverage_data,
                &check1_coverage_data,
                &base_coverage_data,
            ],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            3,
            "unexpected count of tests-to-run in check-6 commit; {relevant_test_cases:?}"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );
        assert_eq!(relevant_test_cases.iter().filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci_memo").count(), 1);

        run_tests(&relevant_test_cases)?
    };

    {
        git_checkout("check-7")?;

        let test_binaries = find_test_binaries()?;

        let all_test_cases = get_all_test_cases(&test_binaries)?;
        assert_eq!(
            all_test_cases.iter().count(),
            7,
            "unexpected count of all tests in check-7 commit"
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_add")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_sub")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_mul")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_div")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "basic_ops::tests::test_power")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            all_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );

        let relevant_test_cases = compute_relevant_test_cases(
            &all_test_cases,
            &get_changed_files("check-7")?,
            vec![
                &check6_coverage_data,
                &check5_coverage_data,
                &check4_coverage_data,
                &check3_coverage_data,
                &check2_coverage_data,
                &check1_coverage_data,
                &base_coverage_data,
            ],
            &test_binaries,
        );
        assert_eq!(
            relevant_test_cases.iter().count(),
            2,
            "unexpected count of tests-to-run in check-7 commit; {relevant_test_cases:?}"
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_fibonacci")
                .count(),
            1
        );
        assert_eq!(
            relevant_test_cases
                .iter()
                .filter(|tc| tc.test_identifier.test_name == "sequences::tests::test_factorial")
                .count(),
            1
        );

        run_tests(&relevant_test_cases)?
    };
    Ok(())
}
