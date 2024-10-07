use crate::scm::Scm;
use crate::scm_git::GitScm;
use crate::subcommand::SubcommandErrors;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use coverage_map::{CoverageData, FileCoverage, FunctionCoverage, RustTestIdentifier};
use db::{CoverageDatabase, DieselCoverageDatabase};
use log::{debug, error, info, trace, warn};
use rust_llvm::{CoverageLibrary, ProfilingData};
use scm::ScmCommit;
use serde_json::Value;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::HashSet;
use std::env::current_dir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, io};

mod coverage_map;
mod db;
mod models;
mod rust_llvm;
mod schema;
mod scm;
pub mod scm_git;
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
            let test_cases = match get_target_test_cases(mode, GitScm {}) {
                Ok(test_cases) => test_cases,
                Err(err) => {
                    error!("error occurred in get_target_test_cases: {:?}", err);
                    return;
                }
            };
            for test_case in test_cases.target_test_cases {
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

pub struct TargetTestCases {
    pub all_test_cases: HashSet<TestCase>,
    pub target_test_cases: HashSet<TestCase>,
}

pub fn get_target_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
    mode: &GetTestIdentifierMode,
    scm: MyScm,
) -> Result<TargetTestCases> {
    let test_binaries = find_test_binaries()?;
    trace!("test_binaries: {:?}", test_binaries);

    let all_test_cases = get_all_test_cases(&test_binaries)?;
    trace!("all_test_cases: {:?}", all_test_cases);

    if *mode == GetTestIdentifierMode::All {
        return Ok(TargetTestCases {
            all_test_cases: all_test_cases.clone(),
            target_test_cases: all_test_cases,
        });
    }

    // FIXME: it's likely that different options will be required here, like using diff from index->HEAD, or some base branch
    let changed_files = scm.get_changed_files("HEAD")?;
    trace!("changed files: {:?}", changed_files);

    let total_test_case_count = all_test_cases.len();
    let relevant_test_cases = compute_relevant_test_cases(
        &all_test_cases
            .iter()
            .map(|tc| tc.test_identifier.clone())
            .collect(),
        &changed_files,
        &scm,
        &(DieselCoverageDatabase {}),
    )?;

    trace!("relevant_test_cases: {:?}", relevant_test_cases);
    println!(
        "relevant test cases are {} of {}, {}%",
        relevant_test_cases.len(),
        total_test_case_count,
        100 * relevant_test_cases.len() / total_test_case_count,
    );

    Ok(TargetTestCases {
        all_test_cases,
        target_test_cases: HashSet::from_iter(
            relevant_test_cases
                .into_iter()
                .filter_map(|ti| map_rust_test_identifier_to_test_case(ti, &test_binaries)),
        ),
    })
}

pub fn run_tests_subcommand(mode: &GetTestIdentifierMode) -> Result<()> {
    let test_cases = get_target_test_cases(mode, GitScm {})?;

    let mut coverage_data = run_tests(&test_cases.target_test_cases)?;
    for tc in test_cases.all_test_cases {
        coverage_data.add_existing_test(tc.test_identifier);
    }

    info!("successfully ran tests");

    // FIXME: "HEAD" is obviously wrong when the local directory is dirty... just ignoring this for the moment.
    let commit_sha = (GitScm {}).get_revision_sha("HEAD")?;
    (DieselCoverageDatabase {}).save_coverage_data(&coverage_data, &commit_sha)?;

    Ok(())
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TestBinary {
    pub rel_src_path: PathBuf,
    pub executable_path: PathBuf,
}

fn find_test_binaries() -> Result<HashSet<TestBinary>> {
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

// FIXME: name is horrible... this is more like a "concrete" version of a RustTestIdentifier, w/ specific knowledge
// required to execute this test, rather than the abstract system-to-system reusable test identifier that
// RustTestIdentifier is
#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct TestCase {
    pub test_binary: TestBinary,
    pub test_identifier: RustTestIdentifier,
}

fn get_all_test_cases(test_binaries: &HashSet<TestBinary>) -> Result<HashSet<TestCase>> {
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

/// Compute which test cases need to be run based upon what changes are being made, and stored coverage data from
/// previous test runs.  The SCM (eg. git) is used to identify what coverage data is relevant.
///
/// Concept for relevant test cases:
///
/// - All test cases that have never been seen before are relevant to be run.  As we store in the coverage data a
///   complete record of test cases, whether they were run or not, we can determine what test cases haven't been seen
///   before by finding the most recent commit with coverage data.
///
///   Note that as we search for "most recent commit", we will skip over any branching sections of the history.  If a
///   commit is a merge commit (has multiple parents), then after checking if the merge commit has coverage data, we
///   will proceed to the most recent common ancestor of the N parents of that merge. Basically we'll skip the
///   non-linear history because any test runs on those may have been invalidated by the merge commit.  If no commits
///   can be found that have coverage data, then we will have to default to running all tests and abort any further
///   computation.
///
/// - It's much more difficult to figure out what tests are impacted by the changed files.  Because each commit could
///   run just a subset of the tests (that's kinda the point), the coverage data for any given commit will be
///   incomplete, preventing us from looking inside of it to determine what tests to run based upon what changes are
///   made.  The solution I have in mind for this is to constantly merge coverage data output from different test runs
///   -- after the base run (all tests), when we have a new commit that runs 1% of the tests, we'll actually merge the
///   full coverage data from the base run and the partial coverage from the second run so that we always have a
///   complete coverage map.
///
///   As a *temporary* implementation until that merged implementation is complete, we'll iterate through every prior
///   commit (that isn't on a branch -- skipping the multiple parents of a merge commit by going to the common
///   ancestor), and query for their coverage data.  This is terrible for large repositories with a long commit history
///   but it should work until the coverage data merging solution is implemented.
fn compute_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
    eval_target_test_cases: &HashSet<RustTestIdentifier>,
    eval_target_changed_files: &HashSet<PathBuf>,
    scm: &MyScm,
    coverage_db: &impl CoverageDatabase,
) -> Result<HashSet<RustTestIdentifier>> {
    let mut retval = HashSet::new();

    compute_all_new_test_cases(eval_target_test_cases, scm, coverage_db, &mut retval)?;
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
        scm,
        coverage_db,
        &mut retval,
    )?;
    trace!(
        "relevant test cases after searching for file changes: {:?}",
        retval
    );

    Ok(retval)
}

fn compute_all_new_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
    eval_target_test_cases: &HashSet<RustTestIdentifier>,
    scm: &MyScm,
    coverage_db: &impl CoverageDatabase,
    retval: &mut HashSet<RustTestIdentifier>,
) -> Result<()> {
    // Search for a commit with coverage data.  All coverage data includes a list of all the test cases that were
    // present for that commit, and we can use that to figure out any new test cases.
    let mut commit = scm.get_head_commit()?;
    let commit_identifier = scm.get_commit_identifier(&commit);
    let mut coverage_data = coverage_db.read_coverage_data(&commit_identifier)?;
    trace!(
        "commit id {} had coverage data? {:}",
        commit_identifier,
        coverage_data.is_some()
    );

    while coverage_data.is_none() {
        let mut parents = scm.get_commit_parents(&commit)?;
        trace!("checking parents; {} parents found", parents.len());

        if parents.is_empty() {
            warn!("Commit {} had no parents; unable to identify a base set of test cases that has already been run.  All test cases will be run.", scm.get_commit_identifier(&commit));
            break;
        } else if parents.len() > 1 {
            // If the commit had multiple parents, try to find their common ancestor and continue looking for coverage
            // data at that point.
            match scm.get_best_common_ancestor(&parents)? {
                Some(common_ancestor) => {
                    commit = common_ancestor;
                }
                None => {
                    warn!("Commit {} had multiple parents, and those parents didn't have a common ancestor; unable to identify a base set of test cases that has already been run.  All test cases will be run.", scm.get_commit_identifier(&commit));
                    break;
                }
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

    for tc in eval_target_test_cases {
        match coverage_data {
            Some(ref coverage_data) => {
                if !coverage_data.existing_test_set().contains(tc) {
                    trace!("test case {:?} was not found in parent coverage data and so will be run as a new test", tc);
                    retval.insert(tc.clone());
                }
            }
            None => {
                trace!("test case {:?} was not found in (ABSENT) parent coverage data and so will be run as a new test", tc);
                retval.insert(tc.clone());
            }
        }
    }

    Ok(())
}

fn compute_changed_file_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
    eval_target_test_cases: &HashSet<RustTestIdentifier>,
    eval_target_changed_files: &HashSet<PathBuf>,
    scm: &MyScm,
    coverage_db: &impl CoverageDatabase,
    retval: &mut HashSet<RustTestIdentifier>,
) -> Result<()> {
    let mut commit = scm.get_head_commit()?;

    loop {
        let coverage_data = coverage_db.read_coverage_data(&scm.get_commit_identifier(&commit))?;
        if let Some(coverage_data) = coverage_data {
            for changed_file in eval_target_changed_files {
                if let Some(tests) = coverage_data.file_to_test_map().get(changed_file) {
                    for test in tests {
                        // Even if this test covered this file in the past, if the test doesn't exist in the current eval
                        // target then we can't run it anymore; typically happens when a test case is removed.
                        if eval_target_test_cases.contains(test) {
                            retval.insert(test.clone());
                        }
                    }
                }
            }
        }

        let mut parents = scm.get_commit_parents(&commit)?;
        if parents.is_empty() {
            break;
        } else if parents.len() > 1 {
            // If the commit had multiple parents, try to find their common ancestor and continue looking for coverage
            // data at that point.
            match scm.get_best_common_ancestor(&parents)? {
                Some(common_ancestor) => {
                    commit = common_ancestor;
                }
                None => {
                    break;
                }
            }
        } else {
            commit = parents.remove(0);
        }
    }

    Ok(())
}

fn map_rust_test_identifier_to_test_case(
    test_identifier: RustTestIdentifier,
    all_test_binaries: &HashSet<TestBinary>,
) -> Option<TestCase> {
    for test_binary in all_test_binaries {
        if test_binary.rel_src_path == test_identifier.test_src_path {
            let new_test_case = TestCase {
                test_identifier: test_identifier.clone(),
                test_binary: test_binary.clone(),
            };
            return Some(new_test_case);
        }
    }

    warn!("Unable to find test binary for test: {test_identifier:?}");
    None
}

fn run_tests<'a, I>(test_cases: I) -> Result<CoverageData>
where
    I: IntoIterator<Item = &'a TestCase>,
{
    let mut coverage_library = CoverageLibrary::new();
    let mut coverage_data = CoverageData::new();

    let mut binaries = HashSet::new();
    for test_case in test_cases {
        trace!("preparing for test case {:?}", test_case);

        coverage_data.add_executed_test(test_case.test_identifier.clone());

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
    use crate::{
        compute_relevant_test_cases,
        coverage_map::{CoverageData, FileCoverage, RustTestIdentifier},
        db::CoverageDatabase,
        rust_llvm::sentinel_function,
        scm::Scm,
        TestBinary, TestCase,
    };
    use lazy_static::lazy_static;
    use std::{
        collections::{HashMap, HashSet},
        iter,
        path::PathBuf,
    };

    /// This is a sentinel test that doesn't reach outside of this project, but does go from main.rs -> rust_llvm.rs.
    /// As a result, this test should be considered for re-run if rust_llvm.rs changes or main.rs changes, but nothing
    /// else.
    #[test]
    fn sentinel_internal_file() {
        let x = sentinel_function();
        assert_eq!(x, 2);
    }

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
        static ref sample_test_case_1: TestCase = {
            TestCase {
                test_binary: TestBinary {
                    rel_src_path: PathBuf::from("src/lib.rs"),
                    executable_path: PathBuf::from("target/crate/debug/crate-test"),
                },
                test_identifier: test1.clone(),
            }
        };
        static ref sample_test_case_2: TestCase = {
            TestCase {
                test_binary: TestBinary {
                    rel_src_path: PathBuf::from("src/lib.rs"),
                    executable_path: PathBuf::from("target/crate/debug/crate-test"),
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
            _commit: &str,
        ) -> anyhow::Result<std::collections::HashSet<std::path::PathBuf>> {
            unreachable!() // not required for these tests
        }

        fn get_previous_commits(&self) -> impl Iterator<Item = anyhow::Result<String>> {
            // not required for these tests
            iter::from_fn(|| unreachable!())
        }

        fn get_revision_sha(&self, _commit: &str) -> anyhow::Result<String> {
            // not required for these tests
            unreachable!()
        }

        fn get_head_commit(&self) -> anyhow::Result<MockScmCommit> {
            match self.get_commit(&self.head_commit) {
                Some(commit) => Ok(commit),
                None => Err(anyhow::anyhow!("test error: no head commit found")),
            }
            // for commit in self.commits.iter() {
            //     if self.get_commit_identifier(&commit) == self.head_commit {
            //         return Ok(commit.clone());
            //     }
            // }
            // Err(anyhow::anyhow!("test error: no head commit found"))
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
    }

    struct MockCoverageDatabase {
        commit_data: HashMap<String, CoverageData>,
    }

    impl CoverageDatabase for MockCoverageDatabase {
        fn save_coverage_data(
            &self,
            _coverage_data: &CoverageData,
            _commit_sha: &str,
        ) -> anyhow::Result<()> {
            // save_coverage_data should never be used on this mock
            unreachable!()
        }

        fn read_coverage_data(&self, commit_sha: &str) -> anyhow::Result<Option<CoverageData>> {
            match self.commit_data.get(commit_sha) {
                Some(data) => Ok(Some(data.clone())),
                None => Ok(None),
            }
            // Ok(self.commit_data.get(commit_sha).cloned())
            // todo!()
        }
    }

    #[test]
    fn compute_empty_case() {
        let result = compute_relevant_test_cases(
            &HashSet::new(),
            &HashSet::new(),
            &MockScm {
                head_commit: String::from("abc"),
                commits: vec![MockScmCommit {
                    id: String::from("abc"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::new(),
            },
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
            &MockScm {
                head_commit: String::from("abc"),
                commits: vec![MockScmCommit {
                    id: String::from("abc"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::new(),
            },
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

        let mut previous_coverage_data = CoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &MockScm {
                head_commit: String::from("abc"),
                commits: vec![MockScmCommit {
                    id: String::from("abc"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("abc"), previous_coverage_data)]),
            },
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

        let mut previous_coverage_data = CoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &MockScm {
                head_commit: String::from("abc"),
                commits: vec![MockScmCommit {
                    id: String::from("abc"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("abc"), previous_coverage_data)]),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains(&test2));
    }

    #[test]
    fn compute_some_new_cases_are_in_parent_commit() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());
        eval_target_test_cases.insert(test2.clone());

        let mut previous_coverage_data = CoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &MockScm {
                head_commit: String::from("head"),
                commits: vec![
                    MockScmCommit {
                        id: String::from("head"),
                        parents: vec![String::from("parent")],
                        ..Default::default()
                    },
                    MockScmCommit {
                        id: String::from("parent"),
                        parents: vec![],
                        ..Default::default()
                    },
                ],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("parent"), previous_coverage_data)]),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains(&test2));
    }

    #[test]
    fn compute_all_new_cases_are_past_merge_commit() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());
        eval_target_test_cases.insert(test2.clone());

        let mut previous_coverage_data = CoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &MockScm {
                head_commit: String::from("head"),
                commits: vec![
                    MockScmCommit {
                        id: String::from("head"),
                        parents: vec![String::from("parent")],
                        ..Default::default()
                    },
                    MockScmCommit {
                        id: String::from("parent"),
                        parents: vec![String::from("branch-1"), String::from("branch-1")],
                        ..Default::default()
                    },
                    MockScmCommit {
                        id: String::from("branch-1"),
                        parents: vec![String::from("common-root")],
                        best_common_ancestor: Some(String::from("common-root")),
                    },
                    MockScmCommit {
                        id: String::from("branch-2"),
                        parents: vec![String::from("common-root")],
                        best_common_ancestor: Some(String::from("common-root")),
                    },
                    MockScmCommit {
                        id: String::from("common-root"),
                        parents: vec![],
                        ..Default::default()
                    },
                ],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("common-root"), previous_coverage_data)]),
            },
        );

        // Compute should go past the branch to the "common-root", which has coverage data that includes test1, leaving
        // just test2 as a new case.
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

        let mut previous_coverage_data = CoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test1.clone(),
        });

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &eval_target_changed_files,
            &MockScm {
                head_commit: String::from("fake-head"),
                commits: vec![MockScmCommit {
                    id: String::from("fake-head"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("fake-head"), previous_coverage_data)]),
            },
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

        let mut previous_coverage_data = CoverageData::new();
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
            &MockScm {
                head_commit: String::from("fake-head"),
                commits: vec![MockScmCommit {
                    id: String::from("fake-head"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("fake-head"), previous_coverage_data)]),
            },
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

        let mut previous_coverage_data = CoverageData::new();
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
            &MockScm {
                head_commit: String::from("fake-head"),
                commits: vec![MockScmCommit {
                    id: String::from("fake-head"),
                    parents: vec![],
                    ..Default::default()
                }],
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([(String::from("fake-head"), previous_coverage_data)]),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains(&test2));
    }

    #[test]
    fn compute_no_new_cases_one_file_changed_multiple_histories() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());
        eval_target_test_cases.insert(test2.clone());
        eval_target_test_cases.insert(test3.clone());

        let mut eval_target_changed_files: HashSet<PathBuf> = HashSet::new();
        eval_target_changed_files.insert(PathBuf::from("src/lib.rs"));

        let mut merge_coverage_data = CoverageData::new();
        merge_coverage_data.add_existing_test(test1.clone());
        merge_coverage_data.add_existing_test(test2.clone());
        merge_coverage_data.add_existing_test(test3.clone());
        merge_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test1.clone(),
        });

        let mut branch_coverage_data = CoverageData::new();
        branch_coverage_data.add_existing_test(test1.clone());
        branch_coverage_data.add_existing_test(test2.clone());
        branch_coverage_data.add_existing_test(test3.clone());
        branch_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test2.clone(),
        });

        let mut ancestor_coverage_data = CoverageData::new();
        ancestor_coverage_data.add_existing_test(test1.clone());
        ancestor_coverage_data.add_existing_test(test2.clone());
        ancestor_coverage_data.add_existing_test(test3.clone());
        ancestor_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test3.clone(),
        });

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &eval_target_changed_files,
            &MockScm {
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
            },
            &MockCoverageDatabase {
                commit_data: HashMap::from([
                    (String::from("merge"), merge_coverage_data),
                    (String::from("branch-a"), branch_coverage_data),
                    (String::from("ancestor"), ancestor_coverage_data),
                ]),
            },
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&test1)); // from 'merge' commit
                                          // not present, test2, from 'branch-a' commit's coverage data; omited because it was a branch
        assert!(result.contains(&test3)); // from 'ancestor' commit
    }
}
