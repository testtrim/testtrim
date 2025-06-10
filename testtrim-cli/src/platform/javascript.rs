// SPDX-FileCopyrightText: 2025 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context as _;
use anyhow::{Result, anyhow};
use log::warn;
use log::{debug, trace};
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::{fmt, fs};
use tokio::process::Command;
use tracing::Instrument as _;
use tracing::info_span;
use tracing::instrument;

use crate::coverage::Tag;
use crate::coverage::commit_coverage_data::{CommitCoverageData, CoverageIdentifier};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::RunTestsErrors;
use crate::errors::SubcommandErrors;
use crate::network::NetworkDependency;
use crate::scm::{Scm, ScmCommit};
use crate::sys_trace::trace::ResolvedSocketAddr;

use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestIdentifierCore, TestPlatform,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct JavascriptMochaTestIdentifier {
    /// Project-relative source path that defines the binary which contains the test.  For example,
    /// `src/basic_ops.js`
    pub test_src_path: PathBuf,
    /// Full title of the test, combined from all describe/it functions.  For example, `basic ops div should divide two
    /// numbers`.`
    pub full_title: String,
}

impl TestIdentifier for JavascriptMochaTestIdentifier {}
impl TestIdentifierCore for JavascriptMochaTestIdentifier {
    fn lightly_unique_name(&self) -> String {
        self.full_title.clone()
    }
}

impl fmt::Display for JavascriptMochaTestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} / {}",
            self.test_src_path.to_string_lossy(),
            self.full_title
        )
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum JavascriptCoverageIdentifier {
    // Possible future: node.js version, platform, etc. -- might be better as tags since they'd be pretty universal for the whole commit though?
    // PackageDependency(JavascriptPackageDependency),
    NetworkDependency(ResolvedSocketAddr),
}

impl CoverageIdentifier for JavascriptCoverageIdentifier {}

impl TryFrom<JavascriptCoverageIdentifier> for NetworkDependency {
    type Error = &'static str;

    #[allow(clippy::match_wildcard_for_single_variants)] // really unlikely that new variations will match
    fn try_from(value: JavascriptCoverageIdentifier) -> std::result::Result<Self, Self::Error> {
        match value {
            JavascriptCoverageIdentifier::NetworkDependency(socket) => Ok(Self { socket }),
            // _ => Err("not supported"),
        }
    }
}

// #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
// pub struct JavascriptPackageDependency {
//     pub package_name: String,
//     pub version: String,
// }

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct JavascriptMochaConcreteTestIdentifier {
    pub test_identifier: JavascriptMochaTestIdentifier,
    pub absolute_test_src_path: PathBuf,
}

impl ConcreteTestIdentifier<JavascriptMochaTestIdentifier>
    for JavascriptMochaConcreteTestIdentifier
{
    fn test_identifier(&self) -> &JavascriptMochaTestIdentifier {
        &self.test_identifier
    }
}

pub struct JavascriptMochaTestDiscovery {
    all_test_cases: HashSet<JavascriptMochaConcreteTestIdentifier>,
}

impl TestDiscovery<JavascriptMochaConcreteTestIdentifier, JavascriptMochaTestIdentifier>
    for JavascriptMochaTestDiscovery
{
    fn all_test_cases(&self) -> &HashSet<JavascriptMochaConcreteTestIdentifier> {
        &self.all_test_cases
    }

    fn map_ti_to_cti(
        &self,
        test_identifier: JavascriptMochaTestIdentifier,
    ) -> Option<JavascriptMochaConcreteTestIdentifier> {
        for test_case in &self.all_test_cases {
            if test_case.test_identifier == test_identifier {
                return Some(test_case.clone());
            }
        }
        warn!("Unable to find test file for test: {test_identifier:?}");
        None
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MochaTestOutput {
    pub stats: TestStats,
    pub tests: Vec<TestCase>,
    pub pending: Vec<TestCase>,
    pub failures: Vec<TestCase>,
    pub passes: Vec<TestCase>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestStats {
    pub suites: u32,
    pub tests: u32,
    pub passes: u32,
    pub pending: u32,
    pub failures: u32,
    pub start: String, // ISO 8601 timestamp
    pub end: String,   // ISO 8601 timestamp
    pub duration: u64, // milliseconds
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestCase {
    pub title: String,
    #[serde(rename = "fullTitle")]
    pub full_title: String,
    pub file: String,
    #[serde(rename = "currentRetry")]
    pub current_retry: u32,
    pub speed: String, // "fast", "medium", "slow"
    pub err: TestError,
    // Optional fields that might appear in some test cases
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestError {
    // For successful tests, this is typically an empty object
    // For failed tests, this would contain error details
    #[serde(flatten)]
    pub details: HashMap<String, serde_json::Value>,
}

impl Default for TestError {
    fn default() -> Self {
        Self {
            details: HashMap::new(),
        }
    }
}

// Alternative implementation if you want to handle the error field more specifically
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TestErrorAlt {
    Empty {},
    Error {
        message: String,
        stack: Option<String>,
        #[serde(flatten)]
        other: HashMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestCaseAlt {
    pub title: String,
    #[serde(rename = "fullTitle")]
    pub full_title: String,
    pub file: String,
    #[serde(rename = "currentRetry")]
    pub current_retry: u32,
    pub speed: String,
    pub err: TestErrorAlt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// Example usage and helper methods
impl MochaTestOutput {
    /// Get all test cases regardless of their status
    pub fn all_tests(&self) -> &Vec<TestCase> {
        &self.tests
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.stats.failures == 0 && self.stats.pending == 0
    }

    /// Get test success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.stats.tests == 0 {
            return 100.0;
        }
        (self.stats.passes as f64 / self.stats.tests as f64) * 100.0
    }
}

pub struct JavascriptMochaTestPlatform;

impl JavascriptMochaTestPlatform {
    #[must_use]
    pub fn autodetect(project_dir: &Path) -> bool {
        if fs::exists(project_dir.join("package.json"))
            .expect("autodetect test project type failed when checking package.json existence")
        {
            trace!("Detected package.json; auto-detect result: JavaScript mocha test project");
            true
        } else {
            false
        }
    }

    // async fn get_all_test_cases(
    //     project_dir: &Path,
    //     test_binaries: &HashSet<RustTestBinary>,
    // ) -> Result<HashSet<JavascriptMochaConcreteTestIdentifier>> {
    //     let tmp_dir = tempfile::Builder::new().prefix("testtrim").tempdir()?;
    //     let mut result: HashSet<JavascriptMochaConcreteTestIdentifier> = HashSet::new();

    //     for binary in test_binaries {
    //         let output = Command::new(&binary.executable_path)
    //             .arg("--list")
    //             .env(
    //                 "LLVM_PROFILE_FILE",
    //                 Path::join(tmp_dir.path(), "get_all_test_cases_%m_%p.profraw"),
    //             )
    //             .current_dir(project_dir)
    //             .output()
    //             .instrument(info_span!("list tests",
    //                 subcommand = true,
    //                 subcommand_binary = ?&binary.executable_path,
    //                 subcommand_args = ?["--list"],
    //             ))
    //             .await
    //             .map_err(|e| SubcommandErrors::UnableToStart {
    //                 command: format!("{binary:?} --list").to_string(),
    //                 error: e,
    //             })?;

    //         if !output.status.success() {
    //             return Err(SubcommandErrors::SubcommandFailed {
    //                 command: format!("{binary:?} --list").to_string(),
    //                 status: output.status,
    //                 stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    //             }
    //             .into());
    //         }

    //         let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    //         for test_name in stdout
    //             .lines()
    //             .filter(|line| line.ends_with(": test"))
    //             .map(|line| line.trim_end_matches(": test"))
    //         {
    //             result.insert(JavascriptMochaConcreteTestIdentifier {
    //                 test_binary: binary.clone(),
    //                 test_identifier: JavascriptMochaTestIdentifier {
    //                     test_src_path: binary.rel_src_path.clone(),
    //                     test_name: test_name.to_string(),
    //                 },
    //             });
    //         }
    //     }

    //     Ok(result)
    // }

    // #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    // fn parse_trace_data(
    //     project_dir: &Path,
    //     test_case: &JavascriptMochaConcreteTestIdentifier,
    //     trace: &Trace,
    //     current_dir: &Path,
    //     coverage_data: &mut CommitCoverageData<JavascriptMochaTestIdentifier, JavascriptCoverageIdentifier>,
    // ) -> Result<()> {
    //     for path in trace.get_open_paths() {
    //         if path.is_relative() || path.starts_with(project_dir) {
    //             debug!(
    //                 "found test {} accessed local file {}",
    //                 test_case.test_identifier,
    //                 path.display(),
    //             );

    //             let target_path = normalize_path(
    //                 path,
    //                 &current_dir.join("fake"), // normalize_path expects relative_to to be a file, not dir; so we add a fake child path
    //                 project_dir,
    //                 |warning| {
    //                     warn!(
    //                         "syscall trace accessed path {} but couldn't normalize to repo root: {warning}",
    //                         path.display()
    //                     );
    //                 },
    //             );
    //             if let Some(target_path) = target_path {
    //                 // It might make sense to filter out files that aren't part of the repo... both here and in
    //                 // parse_profiling_data?
    //                 coverage_data.add_file_to_test(FileCoverage {
    //                     file_name: target_path.clone(),
    //                     test_identifier: test_case.test_identifier.clone(),
    //                 });
    //             }
    //         }
    //         // FIXME: absolute path case -- check if it's part of the repo/cwd, and if so include it
    //     }

    //     for sockaddr in trace.get_connect_sockets() {
    //         coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
    //             test_identifier: test_case.test_identifier.clone(),
    //             coverage_identifier: JavascriptCoverageIdentifier::NetworkDependency(sockaddr.clone()),
    //         });
    //     }

    //     Ok(())
    // }

    // FIXME: npm run test -- --jobs=1 test/basic_ops.js --grep "^basic ops add should add two numbers$"

    // async fn run_test(
    //     project_dir: &Path,
    //     test_case: &JavascriptMochaConcreteTestIdentifier,
    //     tmp_path: &Path,
    //     binaries: &DashSet<PathBuf>,
    //     coverage_library: &Arc<RwLock<CoverageLibrary>>,
    // ) -> Result<CommitCoverageData<JavascriptMochaTestIdentifier, JavascriptCoverageIdentifier>, RunTestError> {
    //     let mut coverage_data = CommitCoverageData::new();

    //     trace!("preparing for test case {test_case:?}");

    //     coverage_data.add_executed_test(test_case.test_identifier.clone());

    //     if binaries.insert(test_case.test_binary.executable_path.clone()) {
    //         let mut lock = coverage_library.write().unwrap(); // FIXME: unwrap?
    //         trace!(
    //             "binary {:?}; loading instrumentation data...",
    //             test_case.test_binary
    //         );
    //         (*lock).load_binary(&test_case.test_binary.executable_path)?;
    //     }

    //     let coverage_dir = tmp_path.join(
    //         test_case
    //             .test_binary
    //             .executable_path
    //             .file_name()
    //             .expect("file_name must be present"),
    //     );
    //     // Create coverage_dir but ignore if its error is 17 (file exists)
    //     fs::create_dir_all(&coverage_dir)
    //         .or_else(|e| {
    //             if e.kind() == io::ErrorKind::AlreadyExists {
    //                 Ok(())
    //             } else {
    //                 Err(e)
    //             }
    //         })
    //         .context("Failed to create coverage directory")?;

    //     let profile_file = coverage_dir
    //         // FIXME: ':' -> '_' is because ':' isn't supported in Windows paths; this is an incomplete support of restricted filenames
    //         .join(test_case.test_identifier.test_name.replace(':', "_"))
    //         .with_extension("profraw");
    //     let strace_file = coverage_dir
    //         .join(&test_case.test_identifier.test_name)
    //         .with_extension("strace");

    //     // Match `cargo test` behavior by moving CWD into the root of the module
    //     let test_wd = test_case.test_binary.manifest_path.parent().unwrap();
    //     debug!(
    //         "Execute test case {test_case:?} into {} from working-dir {}...",
    //         profile_file.display(),
    //         test_wd.display()
    //     );

    //     let mut cmd = Command::new(&test_case.test_binary.executable_path);
    //     let args = ["--exact", &test_case.test_identifier.test_name];
    //     cmd.args(args)
    //         .env("LLVM_PROFILE_FILE", &profile_file)
    //         .env("RUSTFLAGS", "-C instrument-coverage")
    //         .current_dir(test_wd);

    //     let (output, trace) = SYS_TRACE_COMMAND
    //         .trace_command(cmd, &strace_file)
    //         .instrument(info_span!(
    //             "execute-test",
    //             perftrace = "run-test",
    //             parallel = true,
    //             subcommand = true,
    //             subcommand_binary = ?&test_case.test_binary.executable_path,
    //             subcommand_args = ?args,
    //         ))
    //         .await?;

    //     if !output.status.success() {
    //         return Err(RunTestError::TestExecutionFailure(FailedTestResult {
    //             test_identifier: Box::new(test_case.test_identifier.clone()),
    //             failure: TestFailure::NonZeroExitCode {
    //                 exit_code: output.status.code(),
    //                 stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    //                 stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    //             },
    //         }));
    //     }

    //     trace!("Successfully ran test {:?}!", test_case.test_identifier);

    //     let coverage_library_lock = coverage_library.read().unwrap();
    //     Self::parse_profiling_data(
    //         test_case,
    //         &profile_file,
    //         &coverage_library_lock,
    //         &mut coverage_data,
    //     )?;
    //     Self::parse_trace_data(project_dir, test_case, &trace, test_wd, &mut coverage_data)?;

    //     Ok(coverage_data)
    // }
}

impl TestPlatform for JavascriptMochaTestPlatform {
    type TI = JavascriptMochaTestIdentifier;
    type CI = JavascriptCoverageIdentifier;
    type TD = JavascriptMochaTestDiscovery;
    type CTI = JavascriptMochaConcreteTestIdentifier;

    fn platform_identifier() -> &'static str {
        "javascript-mocha"
    }

    fn platform_tags() -> Vec<Tag> {
        vec![Tag {
            key: String::from("__testtrim_javascript_mocha"),
            value: String::from("1"),
        }]
    }

    fn project_name(_project_dir: &Path) -> Result<String> {
        unimplemented!("project_name")

        // // It could make more sense to make this method infallible and return an "unknown" tag or something.  But I'm
        // // thinking to start restrictive and see if it ever becomes an issue.

        // // We avoid using `Manifest`'s advanced workspace features since we're just trying to read the project name; so
        // // read the Cargo.toml file ourselves and use `from_str` to parse it with the least fuss.
        // let toml_contents =
        //     fs::read_to_string(project_dir.join("Cargo.toml")).context("reading Cargo.toml")?;
        // let manifest = Manifest::from_str(&toml_contents).context("parsing Cargo.toml")?;

        // if let Some(package) = manifest.package {
        //     Ok(package.name)
        // } else {
        //     if let Some(workspace) = manifest.workspace {
        //         if !workspace.members.is_empty() {
        //             // This is a bit hacky... not sure what the right behavior is yet.
        //             return Ok(workspace.members[0].clone());
        //         }
        //     }
        //     Err(anyhow!("unable to access package metadata in Cargo.toml"))
        // }
    }

    #[instrument(skip_all, fields(perftrace = "discover-tests"))]
    async fn discover_tests(project_dir: &Path) -> Result<JavascriptMochaTestDiscovery> {
        // --reporter-option output=test-output.json
        let json_output = tempfile::Builder::new().prefix("testtrim").tempfile()?;

        let output = Command::new("npm")
            .args([
                "run",
                "test",
                "--",
                "--dry-run",
                "--reporter=json",
                &format!(
                    "--reporter-option=output={}",
                    json_output.path().to_string_lossy()
                ),
            ])
            .current_dir(project_dir)
            .output()
            .instrument(info_span!("npm run test -- --dry-run",
                subcommand = true,
                subcommand_binary = ?"npm",
                subcommand_args = ?["run", "test", "--", "--dry-run", "--reporter=json"],
            ))
            .await
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: format!("npm run test -- --dry-run").to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("npm run test -- --dry-run").to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        debug!(
            "npm dry run output: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        let mocha_output: MochaTestOutput = serde_json::from_reader(File::open(json_output)?)
            .context("while parsing npm run test output")?;
        let mut test_cases = HashSet::new();
        for mocha_test in mocha_output.tests {
            let success = test_cases.insert(JavascriptMochaConcreteTestIdentifier {
                test_identifier: JavascriptMochaTestIdentifier {
                    test_src_path: PathBuf::new(),
                    full_title: mocha_test.full_title.clone(),
                },
                absolute_test_src_path: PathBuf::new(),
            });
            if !success {
                return Err(anyhow!(
                    "failed to insert test case for {mocha_test:?}, indicating a duplicate test case"
                ));
            }
        }

        Ok(JavascriptMochaTestDiscovery {
            all_test_cases: test_cases,
        })
    }

    #[instrument(skip_all, fields(perftrace = "platform-specific-test-cases"))]
    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        _eval_target_test_cases: &HashSet<JavascriptMochaTestIdentifier>,
        _eval_target_changed_files: &HashSet<PathBuf>,
        _scm: &MyScm,
        _ancestor_commit: &Commit,
        _coverage_data: &FullCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
    ) -> Result<
        PlatformSpecificRelevantTestCaseData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
    > {
        unimplemented!("platform_specific_relevant_test_cases")

        // let mut test_cases: HashMap<
        //     JavascriptMochaTestIdentifier,
        //     HashSet<TestReason<JavascriptCoverageIdentifier>>,
        // > = HashMap::new();

        // let mut external_dependencies_changed = None;
        // // FIXME: I'm not confident that this check is right -- could there be multiple lock files in a realistic repo?
        // // But this is simple and seems pretty applicable for now.
        // if eval_target_changed_files.contains(Path::new("Cargo.lock")) {
        //     external_dependencies_changed = Some(JavascriptMochaTestPlatform::rust_cargo_deps_test_cases(
        //         eval_target_test_cases,
        //         scm,
        //         ancestor_commit,
        //         coverage_data,
        //         &mut test_cases,
        //     )?);
        // }

        // Ok(PlatformSpecificRelevantTestCaseData {
        //     additional_test_cases: test_cases,
        //     external_dependencies_changed,
        // })
    }

    #[instrument(skip_all)]
    async fn run_tests<'a, I>(
        _project_dir: &Path,
        _test_cases: I,
        _jobs: u16,
    ) -> Result<
        CommitCoverageData<JavascriptMochaTestIdentifier, JavascriptCoverageIdentifier>,
        RunTestsErrors,
    >
    where
        I: IntoIterator<Item = &'a JavascriptMochaConcreteTestIdentifier>,
        JavascriptMochaConcreteTestIdentifier: 'a,
    {
        unimplemented!("run_tests")

        // let tmp_dir = tempfile::Builder::new().prefix("testtrim").tempdir()?;

        // let coverage_library = Arc::new(RwLock::new(CoverageLibrary::new()));
        // let mut coverage_data = CommitCoverageData::new();
        // let binaries = Arc::new(DashSet::new());

        // let mut futures = vec![];
        // for test_case in test_cases {
        //     let tmp_path = PathBuf::from(tmp_dir.path());
        //     let b = binaries.clone();
        //     let cl = coverage_library.clone();
        //     let tc = test_case.clone();
        //     futures.push(async move {
        //         JavascriptMochaTestPlatform::run_test(project_dir, &tc, &tmp_path, &b, &cl)
        //             .instrument(info_span!("cargo test",
        //                 ui_stage = Into::<u64>::into(UiStage::RunSingleTest),
        //                 test_case = %tc.test_identifier(),
        //             ))
        //             .await
        //     });
        // }
        // let concurrency = if jobs == 0 {
        //     num_cpus::get()
        // } else {
        //     jobs.into()
        // };
        // tracing::info!(
        //     ui_info = "run-test-count",
        //     count = futures.len(),
        //     concurrency
        // );
        // let results = spawn_limited_concurrency(concurrency, futures).await;

        // let mut failed_test_results = vec![];
        // for result in results {
        //     match result {
        //         Ok(res) => coverage_data.merge_in(res),
        //         Err(RunTestError::TestExecutionFailure(failed_test_result)) => {
        //             failed_test_results.push(failed_test_result);
        //         }
        //         Err(e) => return Err(e.into()),
        //     }
        // }

        // if failed_test_results.is_empty() {
        //     Ok(coverage_data)
        // } else {
        //     Err(RunTestsErrors::TestExecutionFailures(failed_test_results))
        // }
    }

    fn analyze_changed_files(
        _project_dir: &Path,
        _changed_files: &HashSet<PathBuf>,
        _coverage_data: &mut CommitCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
    ) -> Result<()> {
        unimplemented!("analyze_changed_files")

        // for file in changed_files {
        //     if file.extension().is_some_and(|ext| ext == "rs") {
        //         let mut found_references = false;

        //         if !fs::exists(file)? {
        //             // A file was considered "changed" but doesn't exist -- indicating a deleted file.
        //             coverage_data.mark_file_makes_no_references(file.clone());
        //             continue;
        //         }

        //         for target_path in Self::find_compile_time_includes(file)? {
        //             // FIXME: It's not clear whether warnings are the right behavior for any of these problems.  Some of
        //             // them might be better elevated to errors?
        //             let target_path = normalize_path(&target_path, file, project_dir, |warning| {
        //                 warn!(
        //                     "file {} had an include/include_str/include_bytes macro, but reference could not be followed: {warning}",
        //                     file.display()
        //                 );
        //             });

        //             if let Some(target_path) = target_path {
        //                 coverage_data.add_file_reference(FileReference {
        //                     referencing_file: file.clone(),
        //                     target_file: target_path,
        //                 });
        //                 found_references = true;
        //             }
        //         }

        //         if !found_references {
        //             coverage_data.mark_file_makes_no_references(file.clone());
        //         }
        //     } else {
        //         // This probably isn't necessary since it would've never been marked as making references
        //         coverage_data.mark_file_makes_no_references(file.clone());
        //     }
        // }

        // Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_mocha_output() {
        let json_data = r#"
        {
          "stats": {
            "suites": 8,
            "tests": 6,
            "passes": 6,
            "pending": 0,
            "failures": 0,
            "start": "2025-06-10T19:16:56.428Z",
            "end": "2025-06-10T19:16:56.429Z",
            "duration": 1
          },
          "tests": [
            {
              "title": "should add two numbers",
              "fullTitle": "basic ops add should add two numbers",
              "file": "/home/test/basic_ops.js",
              "currentRetry": 0,
              "speed": "fast",
              "err": {}
            }
          ],
          "pending": [],
          "failures": [],
          "passes": [
            {
              "title": "should add two numbers",
              "fullTitle": "basic ops add should add two numbers",
              "file": "/home/test/basic_ops.js",
              "currentRetry": 0,
              "speed": "fast",
              "err": {}
            }
          ]
        }
        "#;

        let result: Result<MochaTestOutput, _> = serde_json::from_str(json_data);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.stats.tests, 6);
        assert_eq!(output.stats.passes, 6);
        assert!(output.all_passed());
        assert_eq!(output.success_rate(), 100.0);
    }
}
