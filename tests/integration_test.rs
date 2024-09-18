use crate::util::ChangeWorkingDirectory;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashSet;
use std::env::current_dir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, io};
use tempdir::TempDir;
use testtrim::coverage_map::{CoverageData, FileCoverage, FunctionCoverage, RustTestIdentifier};
use testtrim::rust_llvm::{CoverageLibrary, ProfilingData};
use testtrim::{process_command, Cli, Commands};
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

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct TestBinary {
    rel_src_path: PathBuf,
    executable_path: PathBuf,
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
struct TestCase {
    test_binary: TestBinary,
    test_identifier: RustTestIdentifier,
}

fn find_test_binaries() -> Result<HashSet<TestBinary>> {
    let repo_root = current_dir()?;

    let output = Command::new("cargo")
        .args(&[
            "test",
            "--workspace",
            "--tests",
            "--no-run",
            "--message-format=json",
        ])
        .env("RUSTFLAGS", "-C instrument-coverage")
        .output()
        .expect("Failed to execute cargo test command");

    // Check for non-zero exit status
    if !output.status.success() {
        return Err(TestError::SubcommandFailed {
            command: "cargo test --no-run".to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    let stdout = String::from_utf8(output.stdout)?;

    let mut test_binaries: HashSet<TestBinary> = HashSet::new();
    for line in stdout.lines() {
        let json_value: Result<Value, _> = serde_json::from_str(line);
        match json_value {
            Ok(json_value) => {
                // FIXME: Cleanup unwraps and any other non-error-checking items here... maybe best to use a struct rather than a serde_json Value
                if json_value["reason"] == "compiler-artifact"
                    && json_value["target"]["test"] == true
                {
                    // src_path will be the source file for the binary that contains this test, but will be an absolute
                    // path, eg. "/home/user/Dev/rust-coverage-specimen/src/lib.rs".  We want to translate that into a
                    // relative path from the root of the repo, eg. "src/lib.rs", which will be stable from coverage run
                    // to run.
                    let abs_src_path = json_value["target"]["src_path"].as_str().unwrap();
                    let rel_src_path = Path::new(abs_src_path).strip_prefix(&repo_root)?;

                    test_binaries.insert(TestBinary {
                        rel_src_path: rel_src_path.to_path_buf(),
                        executable_path: PathBuf::from(json_value["executable"].as_str().unwrap()),
                    });
                }
            }
            Err(err) => {
                return Err(TestError::SubcommandOutputParseFailed {
                    command: "cargo test --no-run".to_string(),
                    error: err.to_string(),
                    output: stdout.clone(),
                }
                .into());
            }
        }
    }

    Ok(test_binaries)
}

fn get_all_test_cases(test_binaries: &HashSet<TestBinary>) -> Result<HashSet<TestCase>> {
    let mut result: HashSet<TestCase> = HashSet::new();

    for binary in test_binaries {
        let output = Command::new(&binary.executable_path)
            .arg("--list")
            .output()
            .expect("Failed to execute binary --list command");

        if !output.status.success() {
            return Err(TestError::SubcommandFailed {
                command: format!("{:?} --list", binary).to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
        for test_name in stdout
            .lines()
            .filter(|line| line.ends_with(": test"))
            .map(|line| line.trim_end_matches(": test"))
        {
            result.insert(TestCase {
                test_binary: binary.clone(),
                // test_name: test_name.to_string(),
                test_identifier: RustTestIdentifier {
                    test_src_path: binary.rel_src_path.clone(),
                    test_name: test_name.to_string(),
                },
            });
        }
    }

    Ok(result)
}

#[test]
fn analyze_base() {
    // FIXME: this is a stub for testing the CLI command later, when these tests aren't just hacked together with half
    // the logic and half the tests in this test file.
    process_command(Cli {
        command: Commands::Noop,
    });
}

fn run_tests<'a, I>(test_cases: I) -> Result<CoverageData>
where
    I: IntoIterator<Item = &'a TestCase>,
{
    let mut coverage_library = CoverageLibrary::new();
    let mut coverage_data = CoverageData::new();

    let mut binaries = HashSet::new();
    for test_case in test_cases {
        coverage_data.add_test(test_case.test_identifier.clone());

        if binaries.insert(&test_case.test_binary.executable_path) {
            println!(
                "New binary {:?}; loading instrumentation data...",
                test_case.test_binary
            );
            coverage_library.load_binary(&test_case.test_binary.executable_path)?;
        }

        // println!("Execute test case {:?}...", test_case);

        let coverage_dir = Path::new("coverage-output").join(
            &test_case
                .test_binary
                .executable_path
                .file_name()
                .expect("file_name must be present"),
        );
        // Create coverage_dir but ignore if its error is 17 (file exists)
        fs::create_dir_all(&coverage_dir)
            .or_else(|e| {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    Err(e)
                } else {
                    Ok(())
                }
            })
            .context("Failed to create coverage directory")?;

        let profile_file = coverage_dir
            .join(&test_case.test_identifier.test_name)
            .with_extension("profraw"); // ")format!("{}/{}.profraw", coverage_dir, test);

        let output = Command::new(&test_case.test_binary.executable_path)
            .arg("--exact")
            .arg(&test_case.test_identifier.test_name)
            .env("LLVM_PROFILE_FILE", &profile_file)
            .env("RUSTFLAGS", "-C instrument-coverage")
            .output()
            .expect("Failed to execute test");

        if !output.status.success() {
            return Err(TestError::SubcommandFailed {
                command: format!(
                    "{:?} --exact {:?}",
                    test_case.test_binary, test_case.test_identifier.test_name
                )
                .to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }
        // FIXME: do something with test failure?

        println!("Successfully ran test {:?}!", test_case.test_identifier);
        // println!("Profile file: {:?}", profile_file);

        let reader = fs::File::open(&profile_file).context("Failed to open profile file")?;
        let profiling_data =
            ProfilingData::new_from_profraw_reader(reader).expect("new_from_profraw_reader");

        for point in profiling_data.get_hit_instrumentation_points() {
            println!("found point... {point:?}");

            // FIXME: not sure what the right thing to do here is, if we've hit a point in the instrumentation, but the
            // coverage library can't fetch data about it... for the moment we'll just ignore it until we come up with a
            // test that hits this case and breaks
            if let Ok(Some(metadata)) = coverage_library.search_metadata(&point) {
                // println!("metadata: {:?}", metadata);

                for file in metadata.file_paths {
                    coverage_data.add_file_to_test(FileCoverage {
                        file_name: file,
                        test_identifier: test_case.test_identifier.clone(),
                    });
                }
                coverage_data.add_function_to_test(FunctionCoverage {
                    function_name: metadata.function_name,
                    test_identifier: test_case.test_identifier.clone(),
                });
            }
        }

        println!("");
    }

    Ok(coverage_data)
}

// fn write_coverage_data(coverage_data: &CoverageData) -> Result<()> {
//     let output_file = "coverage.json";
//     let mut file = File::create(output_file).context("Failed to create output file")?;
//     serde_json::to_writer_pretty(&mut file, coverage_data).context("Failed to write output file")?;

//     let mut str = String::new();
//     File::open(output_file)?.read_to_string(&mut str)?;
//     println!("coverage_data: {}", str);

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

// run `git diff` to fetch all the file names changed in a specific commit; eg. git diff --name-only some-commit^ some-commit
fn get_changed_files(commit: &str) -> Result<HashSet<PathBuf>> {
    let mut output = Command::new("git")
        .args(&["diff", "--name-only", &format!("{commit}^"), commit])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("^': unknown revision or path not in the working tree") {
            // Couldn't find the parent commit ({str}^) for the commit ({str}).  That's a valid case if it's the first
            // commit in the repository.  In that case, replace the base commit with the well-known sha1 of the root git
            // commit, giving us all the changes in the original commit.
            let repo_root = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
            output = Command::new("git")
                .args(&["diff", "--name-only", repo_root, commit])
                .output()?;
        }
    }

    if !output.status.success() {
        return Err(TestError::SubcommandFailed {
            command: format!("git diff --name-only {commit}^ {commit}").to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    // FIXME: this doesn't seem like it will handle platform-specific file name encodings correctly
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().map(|s| PathBuf::from(s)).collect())
}

fn compute_relevant_test_cases(
    new_commit_test_cases: &HashSet<TestCase>,
    files_changed: &HashSet<PathBuf>,
    base_coverage_data: Vec<&CoverageData>,
    all_test_binaries: &HashSet<TestBinary>,
) -> HashSet<TestCase> {
    let mut retval = HashSet::new();

    // Find all the new tests in new_commit_test_cases that aren't in base_coverage_data...
    for new_test_case in new_commit_test_cases {
        // FIXME: If a test existed at some point, and then was deleted, and then was readded, then this logic would not
        // find it as a test that needs to be run unless the coverage data was hit from the previous time the test
        // existed by this name.  That kinda sucks...

        let mut found_test_case = false;
        for base in base_coverage_data.iter() {
            if base.test_set().contains(&new_test_case.test_identifier) {
                found_test_case = true;
                break;
            }
        }
        if !found_test_case {
            retval.insert((*new_test_case).clone());
        }
    }

    // Then find all the tests that should be re-run based upon the files changed in the commit...
    for file_changed in files_changed {
        for base in base_coverage_data.iter() {
            if let Some(tests) = base.file_to_test_map().get(file_changed) {
                for test in tests {
                    // Lookup test binary from all_test_binaries based upon the test_src_path of the test...
                    // FIXME: At larger scale this should be done with a better data structure.
                    let mut found_test_binary = false;
                    for test_binary in all_test_binaries {
                        if test_binary.rel_src_path == test.test_src_path {
                            let new_test_case = TestCase {
                                test_identifier: test.clone(),
                                test_binary: test_binary.clone(),
                            };

                            // If the test case we've found isn't part of the commit's test cases, then ignore it --
                            // this would happen if a test case is removed, for example.  It would still show up in the
                            // last coverage map but it isn't relevant to try to run anymore.
                            if new_commit_test_cases.contains(&new_test_case) {
                                retval.insert(new_test_case);
                            }

                            found_test_binary = true;
                        }
                    }

                    if !found_test_binary {
                        // Hm... we changed a file in this commit.  Previously that file was covered by a test, `test`,
                        // but now we can't find the test project which included that test.  This could be a result of a
                        // code change where that sub-project was removed or renamed, in which case this is fine.  But
                        // it seems worth raising a warning or something?
                        // FIXME: What to do here?
                        println!("Unable to find test binary for test: {test:?}");
                    }
                }
            } else {
                println!("found no tests in that file");
            }
        }
    }

    retval
}
