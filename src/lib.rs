use crate::scm::Scm;
use crate::scm_git::GitScm;
use crate::subcommand::SubcommandErrors;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use commit_coverage_data::{
    CommitCoverageData, FileCoverage, FunctionCoverage, RustTestIdentifier,
};
use db::{CoverageDatabase, DieselCoverageDatabase};
use full_coverage_data::FullCoverageData;
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

mod commit_coverage_data;
mod db;
mod full_coverage_data;
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
}

pub struct TargetTestCases<Commit: ScmCommit> {
    pub all_test_cases: HashSet<TestCase>,
    pub target_test_cases: HashSet<TestCase>,
    pub ancestor_commit: Option<Commit>,
}

pub fn get_target_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
    mode: &GetTestIdentifierMode,
    scm: MyScm,
) -> Result<TargetTestCases<Commit>> {
    let test_binaries = find_test_binaries()?;
    trace!("test_binaries: {:?}", test_binaries);

    let all_test_cases = get_all_test_cases(&test_binaries)?;
    trace!("all_test_cases: {:?}", all_test_cases);

    if *mode == GetTestIdentifierMode::All {
        return Ok(TargetTestCases {
            all_test_cases: all_test_cases.clone(),
            target_test_cases: all_test_cases,
            ancestor_commit: None,
        });
    }

    // FIXME: it's likely that different options will be required here, like using diff from index->HEAD, or some base branch
    // FIXME: this should really figure out the ancestor branch first, and then diff from ancestor->HEAD (etc) since all those changes are are untested
    let changed_files = scm.get_changed_files("HEAD")?;
    trace!("changed files: {:?}", changed_files);

    let (ancestor_commit, coverage_data) = match find_ancestor_commit_with_coverage_data(
        &scm,
        scm.get_head_commit()?, // FIXME: same as above; need better handling of dirty workingdir and targets
        &mut (DieselCoverageDatabase::new_sqlite("test.db")), // FIXME: hard-coded
    )? {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    match ancestor_commit {
        Some(ref ancestor_commit) => info!(
            "relevant test cases will be computed base upon commit {:?}",
            scm.get_commit_identifier(ancestor_commit)
        ),
        None => warn!("no base commit identified with coverage data to work from"),
    }

    let total_test_case_count = all_test_cases.len();
    let relevant_test_cases = compute_relevant_test_cases(
        &all_test_cases
            .iter()
            .map(|tc| tc.test_identifier.clone())
            .collect(),
        &changed_files,
        &coverage_data,
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
        ancestor_commit,
    })
}

pub fn run_tests_subcommand(mode: &GetTestIdentifierMode) -> Result<()> {
    let test_cases = get_target_test_cases(mode, GitScm {})?;

    let mut coverage_data = run_tests(&test_cases.target_test_cases)?;
    for tc in test_cases.all_test_cases {
        coverage_data.add_existing_test(tc.test_identifier);
    }

    info!("successfully ran tests");

    let scm = GitScm {};

    // FIXME: "HEAD" is obviously wrong when the local directory is dirty... just ignoring this for the moment --
    // probably the right behavior in the future is to have two modes of operation -- if we're on a clean checkout (or
    // forced by a CLI option) then we are testing a commit (HEAD) and should be storing coverage data for that commit
    // (and we should diff between ancestor commit and HEAD).  If we're not on a clean checkout (or if asked not to),
    // we're testing a working directory, in which case we should (a) diff between ancestor commit -> working directory,
    // and (b) not save coverage data.
    let commit_sha = scm.get_revision_sha("HEAD")?;

    let ancestor_commit_sha = test_cases
        .ancestor_commit
        .map(|c| scm.get_commit_identifier(&c));

    (DieselCoverageDatabase::new_sqlite("test.db")) // FIXME: hard-coded
        .save_coverage_data(&coverage_data, &commit_sha, ancestor_commit_sha.as_deref())?;

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
                    let abs_src_path = json_value["target"]["src_path"].as_str().unwrap();
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

/// Identify a useable commit which has stored coverage data and can be used as a basis for determining which tests to
/// run in this project.
///
/// A useable commit is one that doesn't come from a branch, as coverage data could change during a merge making any
/// branch commits an incorrect source of data.  Commits are searched starting at HEAD and going towards their ancestors
/// checking for any coverage data.  If a merge commit is found, then the search skips to the best common ancestor to
/// both parents of the merge commit, and continues from there.
fn find_ancestor_commit_with_coverage_data<Commit: ScmCommit, MyScm: Scm<Commit>>(
    scm: &MyScm,
    head: Commit,
    coverage_db: &mut impl CoverageDatabase,
) -> Result<Option<(Commit, FullCoverageData)>> {
    if !coverage_db.has_any_coverage_data()? {
        return Ok(None);
    }

    let mut commit = head;
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
            return Ok(None);
        } else if parents.len() > 1 {
            // If the commit had multiple parents, try to find their common ancestor and continue looking for coverage
            // data at that point.
            match scm.get_best_common_ancestor(&parents) {
                Ok(Some(common_ancestor)) => {
                    commit = common_ancestor;
                }
                Err(_) | Ok(None) => {
                    warn!(
                        "unable to identify common ancestor for parent commits of {}",
                        scm.get_commit_identifier(&commit)
                    );
                    return Ok(None);
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
fn compute_relevant_test_cases(
    eval_target_test_cases: &HashSet<RustTestIdentifier>,
    eval_target_changed_files: &HashSet<PathBuf>,
    coverage_data: &Option<FullCoverageData>,
) -> Result<HashSet<RustTestIdentifier>> {
    let mut retval = HashSet::new();

    compute_all_new_test_cases(eval_target_test_cases, coverage_data, &mut retval)?;
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
    )?;
    trace!(
        "relevant test cases after searching for file changes: {:?}",
        retval
    );

    Ok(retval)
}

fn compute_all_new_test_cases(
    eval_target_test_cases: &HashSet<RustTestIdentifier>,
    coverage_data: &Option<FullCoverageData>,
    retval: &mut HashSet<RustTestIdentifier>,
) -> Result<()> {
    for tc in eval_target_test_cases {
        match coverage_data {
            Some(ref coverage_data) => {
                if !coverage_data.all_tests().contains(tc) {
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

fn compute_changed_file_test_cases(
    eval_target_test_cases: &HashSet<RustTestIdentifier>,
    eval_target_changed_files: &HashSet<PathBuf>,
    coverage_data: &Option<FullCoverageData>,
    retval: &mut HashSet<RustTestIdentifier>,
) -> Result<()> {
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

fn run_tests<'a, I>(test_cases: I) -> Result<CommitCoverageData>
where
    I: IntoIterator<Item = &'a TestCase>,
{
    let mut coverage_library = CoverageLibrary::new();
    let mut coverage_data = CommitCoverageData::new();

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
            .with_extension("profraw");

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

#[cfg(test)]
mod tests {
    use crate::{
        commit_coverage_data::{CommitCoverageData, FileCoverage, RustTestIdentifier},
        compute_relevant_test_cases,
        db::CoverageDatabase,
        find_ancestor_commit_with_coverage_data,
        full_coverage_data::FullCoverageData,
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
        commit_data: HashMap<String, FullCoverageData>,
    }

    impl CoverageDatabase for MockCoverageDatabase {
        fn save_coverage_data(
            &mut self,
            _coverage_data: &CommitCoverageData,
            _commit_sha: &str,
            _ancestor_commit_sha: Option<&str>,
        ) -> anyhow::Result<()> {
            // save_coverage_data should never be used on this mock
            unreachable!()
        }

        fn read_coverage_data(
            &mut self,
            commit_sha: &str,
        ) -> anyhow::Result<Option<FullCoverageData>> {
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
        let result = compute_relevant_test_cases(&HashSet::new(), &HashSet::new(), &None);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn compute_all_new_cases_empty_dbs() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());

        let result = compute_relevant_test_cases(&eval_target_test_cases, &HashSet::new(), &None);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains(&test1));
    }

    #[test]
    fn compute_all_new_cases_are_in_previous_commit() {
        let mut eval_target_test_cases: HashSet<RustTestIdentifier> = HashSet::new();
        eval_target_test_cases.insert(test1.clone());

        let mut previous_coverage_data = FullCoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &Some(previous_coverage_data),
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

        let mut previous_coverage_data = FullCoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &HashSet::new(),
            &Some(previous_coverage_data),
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

        let mut previous_coverage_data = FullCoverageData::new();
        previous_coverage_data.add_existing_test(test1.clone());
        previous_coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("src/lib.rs"),
            test_identifier: test1.clone(),
        });

        let result = compute_relevant_test_cases(
            &eval_target_test_cases,
            &eval_target_changed_files,
            &Some(previous_coverage_data),
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

        let mut previous_coverage_data = FullCoverageData::new();
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
            &Some(previous_coverage_data),
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

        let mut previous_coverage_data = FullCoverageData::new();
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
            &Some(previous_coverage_data),
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains(&test2));
    }
}
