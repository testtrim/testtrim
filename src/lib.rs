use crate::git::get_revision_sha;
use crate::subcommand::SubcommandErrors;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use coverage_map::{CoverageData, FileCoverage, FunctionCoverage, RustTestIdentifier};
use db::{read_coverage_data, save_coverage_data};
use git::{get_changed_files, get_previous_commits};
use log::{debug, error, info, trace, warn};
use rust_llvm::{CoverageLibrary, ProfilingData};
use serde_json::Value;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::HashSet;
use std::env::current_dir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, io};

// FIXME: these modules probably shouldn't be private, but it's convenient as I'm writing code in the integration tests
// that probably later needs to be moved into this library/binary
pub mod coverage_map;
mod db;
pub mod git;
mod models;
pub mod rust_llvm;
mod schema;
mod subcommand;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)] // FIXME: are there things that should be customized here?
pub struct Cli {
    #[command(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Temporary no-operation command
    Noop,

    /// List test identifiers in the target project
    GetTestIdentifiers {
        #[arg(value_enum, long, default_value_t = GetTestIdentifierMode::Relevant)]
        mode: GetTestIdentifierMode,
    },

    /// Execute tests in the target project, recording per-test coverage data
    RunTests {
        // FIXME: there's probably some kind of sub-structure that could be used to make a common set of arguments
        // between GetTestIdentifiers & RunTests -- which will likely include test targeting, database access, target
        // project, etc.
        #[arg(value_enum, long, default_value_t = GetTestIdentifierMode::Relevant)]
        mode: GetTestIdentifierMode,
    },
    // /// Print stats on the coverage
    // PrintStats(CoverageSource),

    // /// Analyze and output the tests to execute
    // AnalyzeTests {
    //     #[clap(flatten)]
    //     coverage_source: CoverageSource,
    //     /// The file containing the diff
    //     #[clap(short, long, value_parser)]
    //     diff_file: String,
    //     /// Root directory of the repository; used to normalize file names between the coverage data and the diff file.
    //     #[clap(short, long, value_parser)]
    //     repository_root: String,
    // },

    // /// Print stats on coverage data; this command uses profraw data instead of lcov data
    // PrintStats2 {
    //     #[clap(flatten)]
    //     coverage_source: CoverageSource,

    //     /// Path of one or more binaries to read LLVM instrumentation data from
    //     #[clap(short, long, value_parser)]
    //     binaries: Vec<String>,
    // },

    // /// Analyze and output the tests to execute; this command uses profraw data instead of lcov data
    // AnalyzeTests2 {
    //     #[clap(flatten)]
    //     coverage_source: CoverageSource,
    //     /// The file containing the diff
    //     #[clap(short, long, value_parser)]
    //     diff_file: String,
    //     /// Root directory of the repository; used to normalize file names between the coverage data and the diff file.
    //     #[clap(short, long, value_parser)]
    //     repository_root: String,
    //     /// Path of one or more binaries to read LLVM instrumentation data from
    //     #[clap(short, long, value_parser)]
    //     binaries: Vec<String>,
    // },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum GetTestIdentifierMode {
    All,
    Relevant,
}

#[derive(Args)]
#[clap(group = clap::ArgGroup::new("coverage_source").required(true).multiple(false))]
pub struct CoverageSource {
    /// The directory containing coverage files
    #[clap(short = 'd', long, value_parser, group = "coverage_source")]
    pub coverage_dir: Option<String>,
    /// The archive containing coverage files
    #[clap(short = 'a', long, value_parser, group = "coverage_source")]
    pub coverage_archive: Option<String>,
}

pub fn process_command(cli: Cli) {
    TermLogger::init(
        cli.verbose.log_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .expect("termlogger init failed");

    match &cli.command {
        Commands::Noop => {}
        Commands::GetTestIdentifiers { mode } => {
            let test_cases = match get_target_test_cases(mode) {
                Ok(test_cases) => test_cases,
                Err(err) => {
                    error!("error occurred in get_target_test_cases: {:?}", err);
                    return;
                }
            };
            for test_case in test_cases {
                info!("{:?}", test_case.test_identifier);
            }
        }
        Commands::RunTests { mode } => match run_tests_subcommand(mode) {
            Ok(_) => {}
            Err(err) => {
                error!("error occurred in run_tests_subcommand: {:?}", err)
            }
        },
    }

    /*
    Commands::PrintStats(coverage_source) => {
        let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
            let coverage_dir = Path::new(dir);
            process_coverage_files(coverage_dir)
        } else if let Some(archive) = &coverage_source.coverage_archive {
            let archive_path = Path::new(archive);
            process_coverage_archive(archive_path)
        } else {
            unreachable!("Either coverage_dir or coverage_archive must be provided")
        };

        print_analysis_results(&coverage_data);
    },
    Commands::AnalyzeTests { coverage_source, diff_file, repository_root } => {
        let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
            let coverage_dir = Path::new(dir);
            process_coverage_files(coverage_dir)
        } else if let Some(archive) = &coverage_source.coverage_archive {
            let archive_path = Path::new(archive);
            process_coverage_archive(archive_path)
        } else {
            unreachable!("Either coverage_dir or coverage_archive must be provided")
        };

        process_diff_file(&coverage_data, diff_file, repository_root);
    },
    Commands::PrintStats2 { coverage_source, binaries } => {
        let mut coverage_library = CoverageLibrary::new();
        for binary in binaries {
            trace!("Loading binary ...");
            let binary_path = Path::new(binary);
            coverage_library.load_binary(binary_path).expect("load_binary");
        }
        let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
            let coverage_dir = Path::new(dir);
            process_profraw_coverage_files(&coverage_library, coverage_dir)
        } else if let Some(archive) = &coverage_source.coverage_archive {
            let archive_path = Path::new(archive);
            process_profraw_coverage_archive(&coverage_library, archive_path)
        } else {
            unreachable!("Either coverage_dir or coverage_archive must be provided")
        };

        print_analysis_results(&coverage_data);
    },
    Commands::AnalyzeTests2 { coverage_source, diff_file, repository_root, binaries } => {
        let mut coverage_library = CoverageLibrary::new();
        for binary in binaries {
            trace!("Loading binary ...");
            let binary_path = Path::new(binary);
            coverage_library.load_binary(binary_path).expect("load_binary");
        }
        let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
            let coverage_dir = Path::new(dir);
            process_profraw_coverage_files(&coverage_library, coverage_dir)
        } else if let Some(archive) = &coverage_source.coverage_archive {
            let archive_path = Path::new(archive);
            process_profraw_coverage_archive(&coverage_library, archive_path)
        } else {
            unreachable!("Either coverage_dir or coverage_archive must be provided")
        };

        process_diff_file(&coverage_data, diff_file, repository_root);
    },
    */
}

fn get_target_test_cases(mode: &GetTestIdentifierMode) -> Result<HashSet<TestCase>> {
    let test_binaries = find_test_binaries()?;
    trace!("test_binaries: {:?}", test_binaries);

    let all_test_cases = get_all_test_cases(&test_binaries)?;
    trace!("all_test_cases: {:?}", test_binaries);

    if *mode == GetTestIdentifierMode::All {
        return Ok(all_test_cases);
    }

    // FIXME: it's likely that different options will be required here, like using diff from index->HEAD, or some base branch
    let changed_files = get_changed_files("HEAD")?;
    trace!("changed files: {:?}", changed_files);

    let mut previous_coverage_data = vec![];
    for previous_commit in get_previous_commits()? {
        if let Some(coverage_data) = read_coverage_data(&previous_commit)? {
            previous_coverage_data.push(coverage_data);
        }
    }
    trace!(
        "found {} previous commits coverage data to analyze...",
        previous_coverage_data.len()
    );

    let relevant_test_cases = compute_relevant_test_cases(
        &all_test_cases,
        &changed_files,
        previous_coverage_data.iter().collect(),
        &test_binaries,
    );
    trace!("relevant_test_cases: {:?}", relevant_test_cases);

    Ok(relevant_test_cases)
}

fn run_tests_subcommand(mode: &GetTestIdentifierMode) -> Result<()> {
    let test_cases = get_target_test_cases(mode)?;
    let coverage_data = run_tests(&test_cases)?;
    info!("successfully ran tests");

    // FIXME: "HEAD" is obviously wrong when the local directory is dirty... just ignoring this for the moment.
    let commit_sha = get_revision_sha("HEAD")?;
    save_coverage_data(&coverage_data, &commit_sha)?;

    Ok(())
}

// FIXME: remove 'pub' after integration test is changed to use CLI
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TestBinary {
    // FIXME: remove 'pub' after integration test is changed to use CLI
    pub rel_src_path: PathBuf,
    // FIXME: remove 'pub' after integration test is changed to use CLI
    pub executable_path: PathBuf,
}

// FIXME: remove 'pub' after integration test is changed to use CLI
pub fn find_test_binaries() -> Result<HashSet<TestBinary>> {
    let repo_root = current_dir()?;

    let output = Command::new("cargo")
        .args([
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
        return Err(SubcommandErrors::SubcommandFailed {
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
                    && json_value["profile"]["test"] == true
                    && !json_value["executable"].is_null()
                {
                    // src_path will be the source file for the binary that contains this test, but will be an absolute
                    // path, eg. "/home/user/Dev/rust-coverage-specimen/src/lib.rs".  We want to translate that into a
                    // relative path from the root of the repo, eg. "src/lib.rs", which will be stable from coverage run
                    // to run.
                    // trace!("json_value: {:?}", json_value);
                    let abs_src_path = json_value["target"]["src_path"].as_str().unwrap();
                    // trace!("abs_src_path: {:?}", abs_src_path);
                    // trace!("repo_root: {:?}", repo_root);
                    let rel_src_path = Path::new(abs_src_path).strip_prefix(&repo_root)?;

                    test_binaries.insert(TestBinary {
                        rel_src_path: rel_src_path.to_path_buf(),
                        executable_path: PathBuf::from(json_value["executable"].as_str().unwrap()),
                    });
                }
            }
            Err(err) => {
                return Err(SubcommandErrors::SubcommandOutputParseFailed {
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

// FIXME: remove 'pub' after integration test is changed to use CLI
// FIXME: name is horrible... this is more like a "concrete" version of a RustTestIdentifier, w/ specific knowledge required to execute this test, rather than the abstract system-to-system reusable test identifier that RustTestIdentifier is
#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct TestCase {
    // FIXME: remove 'pub' after integration test is changed to use CLI
    pub test_binary: TestBinary,
    // FIXME: remove 'pub' after integration test is changed to use CLI
    pub test_identifier: RustTestIdentifier,
}

// FIXME: remove 'pub' after integration test is changed to use CLI
pub fn get_all_test_cases(test_binaries: &HashSet<TestBinary>) -> Result<HashSet<TestCase>> {
    let mut result: HashSet<TestCase> = HashSet::new();

    for binary in test_binaries {
        let output = Command::new(&binary.executable_path)
            .arg("--list")
            .output()
            .expect("Failed to execute binary --list command");

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
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
                test_identifier: RustTestIdentifier {
                    test_src_path: binary.rel_src_path.clone(),
                    test_name: test_name.to_string(),
                },
            });
        }
    }

    Ok(result)
}

// FIXME: remove 'pub' after integration test is changed to use CLI
pub fn compute_relevant_test_cases(
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
            trace!(
                "test case {:?} is considered relevant because it's new",
                new_test_case
            );
            retval.insert((*new_test_case).clone());
        }
    }

    // Then find all the tests that should be re-run based upon the files changed in the commit...
    for file_changed in files_changed {
        trace!(
            "digging up test cases affected by the file {:?}",
            file_changed
        );

        for base in base_coverage_data.iter() {
            if let Some(tests) = base.file_to_test_map().get(file_changed) {
                trace!(
                    "found possible relevant tests affected by that file: {:?}",
                    tests
                );

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
                                trace!("marking test case {:?} as relevant", new_test_case);
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
                        warn!("Unable to find test binary for test; skipped: {test:?}");
                    }
                }
            } else {
                // FIXME: change to verbose output
                trace!("found no tests in that file");
            }
        }
    }

    retval
}

// FIXME: remove 'pub' after integration test is changed to use CLI
pub fn run_tests<'a, I>(test_cases: I) -> Result<CoverageData>
where
    I: IntoIterator<Item = &'a TestCase>,
{
    let mut coverage_library = CoverageLibrary::new();
    let mut coverage_data = CoverageData::new();

    let mut binaries = HashSet::new();
    for test_case in test_cases {
        trace!("preparing for test case {:?}", test_case);

        coverage_data.add_test(test_case.test_identifier.clone());

        if binaries.insert(&test_case.test_binary.executable_path) {
            trace!(
                "binary {:?}; loading instrumentation data...",
                test_case.test_binary
            );
            coverage_library.load_binary(&test_case.test_binary.executable_path)?;
        }

        let coverage_dir = Path::new("coverage-output").join(
            test_case
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

        debug!(
            "Execute test case {:?} into {:?}...",
            test_case, profile_file
        );
        let output = Command::new(&test_case.test_binary.executable_path)
            .arg("--exact")
            .arg(&test_case.test_identifier.test_name)
            .env("LLVM_PROFILE_FILE", &profile_file)
            .env("RUSTFLAGS", "-C instrument-coverage")
            .output()
            .expect("Failed to execute test");

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
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

        trace!("Successfully ran test {:?}!", test_case.test_identifier);

        let reader = fs::File::open(&profile_file).context("Failed to open profile file")?;
        let profiling_data =
            ProfilingData::new_from_profraw_reader(reader).expect("new_from_profraw_reader");

        for point in profiling_data.get_hit_instrumentation_points() {
            // FIXME: not sure what the right thing to do here is, if we've hit a point in the instrumentation, but the
            // coverage library can't fetch data about it... for the moment we'll just ignore it until we come up with a
            // test that hits this case and breaks
            if let Ok(Some(metadata)) = coverage_library.search_metadata(&point) {
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
    }

    Ok(coverage_data)
}

// fn process_diff_file(coverage_data: &CoverageData, diff_file: &str, repository_root: &str) {
//     // FIXME: diff_file is not truly a diff (right now), but just a EOL terminated list of files that are modified for
//     // simplicity.  Make it a diff later.
//     //
//     // For now, read that list of files:
//     let diff_content = fs::read_to_string(diff_file).expect("Failed to read diff file");
//     let files_changed: Vec<&str> = diff_content.lines().collect();
//     trace!("files_changed: {:?}", files_changed);

//     // Get the absolute path of repository root.
//     let repository_root_abs = fs::canonicalize(repository_root).expect("Failed to canonicalize repository root");
//     trace!("repository_root_abs: {:?}", repository_root_abs);

//     // Now search coverage data for all the tests that we need to run.
//     let mut tests_to_run = HashSet::new();
//     for file in files_changed {
//         // Treat the file name as relative to the repository_root_abs; don't canonicalize it because it might not exist
//         // and apparently that's a requirement for that func.
//         let file_abs = repository_root_abs.join(file);
//         trace!("changed file, abs: {:?}", file_abs);

//         if let Some(tests) = coverage_data.file_to_test_map().get(&file_abs) {
//             trace!("\tFound {} tests", tests.len());
//             tests_to_run.extend(tests.iter().cloned());
//         }
//     }

//     trace!("{} tests to execute", tests_to_run.len());
//     for test in &tests_to_run {
//         trace!("\t{:?}", test);
//     }
//     if coverage_data.test_set().is_empty() {
//         trace!("can't compute %age");
//     } else {
//         trace!(
//             "Analysis shows there were {} tests, so this is {}%",
//             coverage_data.test_set().len(),
//             100 * tests_to_run.len() / coverage_data.test_set().len()
//         );
//     }
// }

// fn process_coverage_files(coverage_dir: &Path) -> CoverageData {
//     let mut coverage_data = CoverageData::new();
//     // let mut test_set: HashSet<String> = HashSet::new();
//     // let mut file_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();
//     // let mut function_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();

//     for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
//         let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
//         trace!("Test executor binary: {}", test_executor_path.display());

//         process_test_executor_directory(&test_executor_path, &mut coverage_data);
//     }

//     // CoverageData {
//     //     test_set,
//     //     file_to_test_map,
//     //     function_to_test_map,
//     // }

//     coverage_data
// }

// fn process_test_executor_directory(
//     test_executor_path: &Path,
//     coverage_data: &mut CoverageData,
// ) {
//     for test_output_entry in fs::read_dir(test_executor_path).expect("Failed to read test executor directory") {
//         let test_output_path = test_output_entry.expect("Failed to read directory entry").path();

//         if let Some("lcov") = test_output_path.extension().and_then(|ext| ext.to_str()) {
//             trace!("\tTest case: {}", test_output_path.display());

//             let test_name = test_output_path.file_stem()
//                 .and_then(|stem| stem.to_str())
//                 .expect("Failed to extract test name")
//                 .to_string();

//             coverage_data.add_test(&test_name);
//             // test_set.insert(test_output_path.to_str().unwrap().to_string());

//             let file = fs::File::open(&test_output_path).expect("Failed to open LCOV file");
//             process_lcov(file, &test_name, coverage_data);
//         }
//     }
// }

// fn process_profraw_coverage_files(coverage_library: &CoverageLibrary, coverage_dir: &Path) -> CoverageData {
//     let mut coverage_data = CoverageData::new();

//     for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
//         let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
//         trace!("Test executor binary: {}", test_executor_path.display());

//         process_profraw_test_executor_directory(&test_executor_path, coverage_library, &mut coverage_data);
//     }

//     coverage_data
// }

// fn process_profraw_test_executor_directory(
//     test_executor_path: &Path,
//     coverage_library: &CoverageLibrary,
//     coverage_data: &mut CoverageData,
// ) {
//     for test_output_entry in fs::read_dir(test_executor_path).expect("Failed to read test executor directory") {
//         let test_output_path = test_output_entry.expect("Failed to read directory entry").path();

//         if let Some("profraw") = test_output_path.extension().and_then(|ext| ext.to_str()) {
//             trace!("\tTest case: {}", test_output_path.display());

//             let test_name = test_output_path.file_stem()
//                 .and_then(|stem| stem.to_str())
//                 .expect("Failed to extract test name")
//                 .to_string();

//             coverage_data.add_test(&test_name);

//             let file = fs::File::open(&test_output_path).expect("Failed to open LCOV file");
//             process_profraw(file, &test_name, coverage_library, coverage_data);
//         }
//     }
// }

// fn process_coverage_archive(archive_path: &Path) -> CoverageData {
//     let mut coverage_data = CoverageData::new();

//     let extension = archive_path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

//     match extension {
//         "bz2" => process_tar_bz2(archive_path, &mut coverage_data),
//         "7z" => process_7z(archive_path, &mut coverage_data),
//         _ => panic!("Unsupported archive format"),
//     }

//     coverage_data
// }

// fn process_profraw_coverage_archive(coverage_library: &CoverageLibrary, archive_path: &Path) -> CoverageData {
//     let mut coverage_data = CoverageData::new();

//     let extension = archive_path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

//     match extension {
//         "bz2" => process_profraw_tar_bz2(coverage_library, archive_path, &mut coverage_data),
//         "7z" => process_profraw_7z(coverage_library, archive_path, &mut coverage_data),
//         _ => panic!("Unsupported archive format"),
//     }

//     coverage_data
// }

// fn process_tar_bz2(
//     archive_path: &Path,
//     coverage_data: &mut CoverageData,
// ) {
//     let file = fs::File::open(archive_path).expect("Failed to open archive file");
//     let bz2 = BzDecoder::new(file);
//     let mut archive = Archive::new(bz2);

//     for entry in archive.entries().expect("Failed to read archive entries") {
//         let mut entry = entry.expect("Failed to read archive entry");
//         let path = entry.path().unwrap().to_str().unwrap().to_string();
//         trace!("bz2: {}", path);
//         process_archive_entry(&path, &mut entry, coverage_data);
//     }
// }

// fn process_profraw_tar_bz2(
//     coverage_library: &CoverageLibrary,
//     archive_path: &Path,
//     coverage_data: &mut CoverageData,
// ) {
//     let file = fs::File::open(archive_path).expect("Failed to open archive file");
//     let bz2 = BzDecoder::new(file);
//     let mut archive = Archive::new(bz2);

//     for entry in archive.entries().expect("Failed to read archive entries") {
//         let mut entry = entry.expect("Failed to read archive entry");
//         let path = entry.path().unwrap().to_str().unwrap().to_string();
//         trace!("bz2: {}", path);
//         process_profraw_archive_entry(coverage_library, &path, &mut entry, coverage_data);
//     }
// }

// fn process_7z(
//     archive_path: &Path,
//     coverage_data: &mut CoverageData,
// ) {
//     // let file = fs::File::open(archive_path).expect("Failed to open archive file");
//     let mut sz = SevenZReader::open(archive_path, Password::empty()).expect("Failed to create 7z reader");

//     sz.for_each_entries(|entry, reader| {
//         trace!("7z: {}", entry.name());
//         process_archive_entry(entry.name(), reader, coverage_data);
//         Ok(true) // FIXME: not sure if true or false is needed here
//     }).expect("for_each_entries");
// }

// fn process_profraw_7z(
//     coverage_library: &CoverageLibrary,
//     archive_path: &Path,
//     coverage_data: &mut CoverageData,
// ) {
//     // let file = fs::File::open(archive_path).expect("Failed to open archive file");
//     let mut sz = SevenZReader::open(archive_path, Password::empty()).expect("Failed to create 7z reader");

//     sz.for_each_entries(|entry, reader| {
//         trace!("7z: {}", entry.name());
//         process_profraw_archive_entry(coverage_library, entry.name(), reader, coverage_data);
//         Ok(true) // FIXME: not sure if true or false is needed here
//     }).expect("for_each_entries");
// }

// fn process_archive_entry<R: Read + ?Sized>(
//     entry_name: &str,
//     entry: &mut R,
//     coverage_data: &mut CoverageData,
// ) {
//     // check if lcov, and if so, extract the test name...
//     if entry_name.ends_with(".lcov") {
//         let test_name = Path::new(entry_name)
//             .file_stem()
//             .and_then(|stem| stem.to_str())
//             .expect("Failed to extract test name")
//             .to_string();
//         coverage_data.add_test(&test_name);
//         process_lcov(entry, &test_name, coverage_data);
//     }
// }

// fn process_profraw_archive_entry<R: Read + ?Sized>(
//     coverage_library: &CoverageLibrary,
//     entry_name: &str,
//     entry: &mut R,
//     coverage_data: &mut CoverageData,
// ) {
//     if entry_name.ends_with(".profraw") {
//         let test_name = Path::new(entry_name)
//             .file_stem()
//             .and_then(|stem| stem.to_str())
//             .expect("Failed to extract test name")
//             .to_string();
//         coverage_data.add_test(&test_name);
//         process_profraw(entry, &test_name, coverage_library, coverage_data);
//     }
// }

// fn process_lcov<T: Read>(
//     reader: T,
//     test_name: &str,
//     coverage_data: &mut CoverageData,
// ) {
//     let buf_reader = BufReader::new(reader);
//     let reader = Reader::new(buf_reader);
//     let mut current_source_file: Option<PathBuf> = None;
//     let mut current_source_file_is_hit = false;

//     for record in reader {
//         match record {
//             Ok(Record::SourceFile { path }) => {
//                 match current_source_file {
//                     Some(ref current_source_file) if current_source_file_is_hit => {
//                         coverage_data.add_file_to_test(
//                             FileCoverage {
//                                 test_name: test_name.to_string(),
//                                 file_name: current_source_file.clone(),
//                             }
//                         );
//                     }
//                     _ => {}
//                 }
//                 // update_file_to_test_map(file_to_test_map, &current_source_file, test_name, current_source_file_is_hit);
//                 current_source_file = Some(path);
//                 current_source_file_is_hit = false;
//             }
//             Ok(Record::LineData { count, .. }) if count > 0 => {
//                 current_source_file_is_hit = true;
//             }
//             Ok(Record::EndOfRecord) => {
//                 match current_source_file {
//                     Some(ref current_source_file) if current_source_file_is_hit => {
//                         coverage_data.add_file_to_test(
//                             FileCoverage {
//                                 test_name: test_name.to_string(),
//                                 file_name: current_source_file.clone(),
//                             }
//                         );
//                     }
//                     _ => {}
//                 }
//             }
//             Ok(Record::FunctionData { name: function_name, count }) if count > 0 => {
//                 coverage_data.add_function_to_test(
//                     FunctionCoverage {
//                         test_name: test_name.to_string(),
//                         function_name,
//                     }
//                 );
//             }
//             _ => {}
//         }
//     }
// }

// fn process_profraw<T: Read>(
//     reader: T,
//     test_name: &str,
//     coverage_library: &CoverageLibrary,
//     coverage_data: &mut CoverageData,
// ) {
//     let profiling_data = ProfilingData::new_from_profraw_reader(reader).expect("new_from_profraw_reader");

//     for point in profiling_data.get_hit_instrumentation_points() {
//         // trace!("found point...");

//         let metadata = coverage_library.search_metadata(&point)
//             .expect("search_metadata success")
//             .expect("search_metadata returned value");
//         // trace!("metadata: {:?}", metadata);

//         for file in metadata.file_paths {
//             coverage_data.add_file_to_test(
//                 FileCoverage {
//                     file_name: file,
//                     test_name: test_name.to_string(),
//                 }
//             );
//         }
//         coverage_data.add_function_to_test(
//             FunctionCoverage {
//                 function_name: metadata.function_name,
//                 test_name: test_name.to_string(),
//             }
//         );
//     }
// }

// fn print_analysis_results(coverage_data: &CoverageData) {
//     let total_tests = coverage_data.test_set().len();
//     // let total_tests = file_to_test_map.values().map(|tests| tests.len()).sum::<usize>();

//     // Example analysis (unchanged)
//     if let Some(tests_affected) = coverage_data.file_to_test_map().get(&PathBuf::from("/home/mfenniak/Dev/testtrim/src/main.rs")) {
//         trace!(
//             "If src/main.rs is changed, {} tests need to be rerun ({:?})",
//             tests_affected.len(),
//             tests_affected,
//         );
//     } else if let Some(tests_affected) = coverage_data.file_to_test_map().get(&PathBuf::from("src/main.rs")) {
//         trace!(
//             "If src/main.rs is changed, {} tests need to be rerun ({:?})",
//             tests_affected.len(),
//             tests_affected,
//         );
//     } else {
//         trace!("can't find src/main.rs");
//     }

//     if let Some(tests_affected) = coverage_data.file_to_test_map().get(&PathBuf::from("/home/mfenniak/Dev/testtrim/src/rust_llvm.rs")) {
//         trace!(
//             "If src/rust_llvm.rs is changed, {} tests need to be rerun ({:?})",
//             tests_affected.len(),
//             tests_affected,
//         );
//     } else if let Some(tests_affected) = coverage_data.file_to_test_map().get(&PathBuf::from("src/rust_llvm.rs")) {
//         trace!(
//             "If src/rust_llvm.rs is changed, {} tests need to be rerun ({:?})",
//             tests_affected.len(),
//             tests_affected,
//         );
//     } else {
//         trace!("can't find src/rust_llvm.rs");
//     }

//     let stats = coverage_data.calculate_statistics();

//     if stats.input_file_count == 0 || total_tests == 0 {
//         // Avoid division by zero
//         trace!("No input source files ({}) or tests ({}) found.", stats.input_file_count, total_tests);
//     } else {
//         trace!(
//             "On average, for each source file, we'd have to rerun {} tests ({}%)",
//             stats.input_file_total_tests_affected / stats.input_file_count,
//             100 * stats.input_file_total_tests_affected / stats.input_file_count / total_tests
//         );
//         trace!("By file: Minimum tests affected count = {:?}", stats.by_file_min_tests_affected_by_change);
//         trace!("By file: Median tests affected count = {:?}", stats.by_file_median_tests_affected_by_change);
//         trace!("By file: Maximum tests affected count = {:?}", stats.by_file_max_tests_affected_by_change);
//     }

//     // Display every input file, and the number of tests that would need to be re-executed:
//     trace!("file\ttests-to-rerun\ttotal-tests");
//     for (file, tests_affected) in coverage_data.file_to_test_map() {
//         trace!(
//             "{:?}\t{}\t{}",
//             file,
//             tests_affected.len(),
//             total_tests,
//         );
//     }

//     if stats.input_function_count == 0 || total_tests == 0 {
//         trace!("No input source functions ({}) or tests ({}) found.", stats.input_function_count, total_tests);
//     } else {
//         trace!(
//             "On average, for each source function, we'd have to rerun {} tests ({}%)",
//             stats.input_function_total_tests_affected / stats.input_function_count,
//             100 * stats.input_function_total_tests_affected / stats.input_function_count / total_tests
//         );
//     }
//     trace!("By function: Minimum tests affected count = {:?}", stats.by_function_min_tests_affected_by_change);
//     trace!("By function: Median tests affected count = {:?}", stats.by_function_median_tests_affected_by_change);
//     trace!("By function: Maximum tests affected count = {:?}", stats.by_function_max_tests_affected_by_change);

//     // Display every input function, and the number of tests that would need to be re-executed:
//     trace!("function\ttests-to-rerun\ttotal-tests");
//     for (function, tests_affected) in coverage_data.function_to_test_map() {
//         trace!(
//             "{}\t{}\t{}",
//             function,
//             tests_affected.len(),
//             total_tests,
//         );
//     }
// }

#[cfg(test)]
mod tests {
    use crate::rust_llvm::sentinel_function;

    /// This is a sentinel test that doesn't reach outside of this project, but does go from main.rs -> rust_llvm.rs.
    /// As a result, this test should be considered for re-run if rust_llvm.rs changes or main.rs changes, but nothing
    /// else.
    #[test]
    fn sentinel_internal_file() {
        let x = sentinel_function();
        assert_eq!(x, 2);
    }
}
