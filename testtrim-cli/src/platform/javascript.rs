// SPDX-FileCopyrightText: 2025 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context as _;
use anyhow::{Result, anyhow};
use lcov::{Reader, Record};
use log::{debug, trace};
use log::{info, warn};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fmt, fs};
use tempfile::TempDir;
use tokio::process::Command;
use tracing::Instrument as _;
use tracing::info_span;
use tracing::instrument;

use crate::cmd::ui::UiStage;
use crate::coverage::Tag;
use crate::coverage::commit_coverage_data::{
    CommitCoverageData, CoverageIdentifier, FileCoverage, HeuristicCoverage,
};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::{FailedTestResult, SubcommandErrors, TestFailure};
use crate::errors::{RunTestError, RunTestsErrors};
use crate::network::NetworkDependency;
use crate::platform::TestReason;
use crate::platform::util::spawn_limited_concurrency;
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
    /// numbers`.
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
    // Possible future: node.js version, platform, etc. -- might be better as tags since they'd be pretty universal for
    // the whole commit though?
    PackageDependency(JavascriptPackageDependency),
    NetworkDependency(ResolvedSocketAddr),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct JavascriptPackageDependency {
    package_subpath: String, // eg. "node_modules/yargs-unparser/node_modules/camelcase"
    version: String,
    resolved: String,
    integrity: String,
}

impl CoverageIdentifier for JavascriptCoverageIdentifier {}

impl TryFrom<JavascriptCoverageIdentifier> for NetworkDependency {
    type Error = &'static str;

    #[allow(clippy::match_wildcard_for_single_variants)] // really unlikely that new variations will match
    fn try_from(value: JavascriptCoverageIdentifier) -> std::result::Result<Self, Self::Error> {
        match value {
            JavascriptCoverageIdentifier::NetworkDependency(socket) => Ok(Self { socket }),
            _ => Err("not supported"),
        }
    }
}

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
    coverage_data_baseline: HashMap<PathBuf, HashSet<FunctionName>>,
    _cache_tmp_dir: TempDir, // keep the TempDir alive to support cache_dir's storage
    cache_dir: PathBuf,
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
    // Example:
    // "stack": "AssertionError [ERR_ASSERTION]: 0 == 22\n    at Context.<anonymous> (test/basic_ops.js:8:14)\n    at process.processImmediate (node:internal/timers:505:21)",
    // "message": "0 == 22",
    // "generatedMessage": true,
    // "name": "AssertionError",
    // "code": "ERR_ASSERTION",
    // "actual": "0",
    // "expected": "22",
    // "operator": "=="
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageLock {
    // pub name: String,
    // pub lockfile_version: u32,
    // pub requires: bool,
    pub packages: HashMap<String, Package>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    pub version: Option<String>,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
struct FunctionName(String);

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

    async fn run_test(
        project_dir: &Path,
        test_case: &JavascriptMochaConcreteTestIdentifier,
        external_dependencies: &HashMap<String, Package>,
        coverage_data_baseline: &HashMap<PathBuf, HashSet<FunctionName>>,
        cache_dir: &PathBuf,
    ) -> Result<
        CommitCoverageData<JavascriptMochaTestIdentifier, JavascriptCoverageIdentifier>,
        RunTestError,
    > {
        trace!("preparing for test case {test_case:?}");

        let tmp_dir = tempfile::Builder::new().prefix("testtrim").tempdir()?;
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_executed_test(test_case.test_identifier.clone());

        let report_dir = tmp_dir.path().join("report");
        let nyc_temp_dir = tmp_dir.path().join("nyc_output");

        let mut cmd = Command::new("npm");
        let full_title_regex =
            format!("^{}$", regex::escape(&test_case.test_identifier.full_title));
        let args = [
            // FIXME: this is awkward... merging together &str and PathBuf... must be a better way

            // npm options:
            AsRef::<OsStr>::as_ref("test"),
            AsRef::<OsStr>::as_ref("--"),
            // nyc options:
            AsRef::<OsStr>::as_ref("--reporter=lcovonly"),
            // If we don't use separate `--temp-dir` for each test run, then coverage data bleeds between tests.
            AsRef::<OsStr>::as_ref("--temp-dir"),
            AsRef::<OsStr>::as_ref(&nyc_temp_dir),
            AsRef::<OsStr>::as_ref("--cache-dir"),
            AsRef::<OsStr>::as_ref(&cache_dir),
            AsRef::<OsStr>::as_ref("--report-dir"),
            AsRef::<OsStr>::as_ref(&report_dir),
            // Instrument node_modules files so that we can track dependency usage.
            AsRef::<OsStr>::as_ref("--exclude-node-modules=false"),
            // Override the default --exclude which would exclude test files.
            AsRef::<OsStr>::as_ref("--exclude=\"\""),
            // mocha options:
            AsRef::<OsStr>::as_ref("mocha"),
            AsRef::<OsStr>::as_ref("--jobs=1"), // probably not necessary since we're running one test?  But just in-case `--grep` matches more than one...
            AsRef::<OsStr>::as_ref("--grep"),
            AsRef::<OsStr>::as_ref(&full_title_regex),
            AsRef::<OsStr>::as_ref(&test_case.absolute_test_src_path),
        ];
        cmd.args(args);
        debug!("cmd.args: {cmd:?}");
        cmd.current_dir(project_dir);

        let output = cmd
            .output()
            .instrument(info_span!(
                "execute-test",
                perftrace = "run-test",
                parallel = true,
                subcommand = true,
                subcommand_binary = ?"npm",
                subcommand_args = ?args,
            ))
            .await?;

        if !output.status.success() {
            return Err(RunTestError::TestExecutionFailure(FailedTestResult {
                test_identifier: Box::new(test_case.test_identifier.clone()),
                failure: TestFailure::NonZeroExitCode {
                    exit_code: output.status.code(),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                },
            }));
        }

        trace!(
            "running {test_case:?} npm test stdout: {}",
            String::from_utf8_lossy(&output.stdout).into_owned()
        );
        trace!(
            "running {test_case:?} npm test stderr: {}",
            String::from_utf8_lossy(&output.stderr).into_owned()
        );

        // FIXME: make test output to json reporter, parse results, and verify that 1 and only 1 test was run -- I don't
        // fully trust `grep` since it's plausible that someone could create two tests with the same names, and I don't
        // want to let that be confusing and undetected

        trace!("Successfully ran test {:?}!", test_case.test_identifier);

        Self::parse_coverage_data(
            &report_dir.join("lcov.info"),
            &mut coverage_data,
            test_case,
            external_dependencies,
            coverage_data_baseline,
        )?;

        Ok(coverage_data)
    }

    // When a JavaScript test is run, imports of the test file are executed in order to provide their exports.  The
    // execution of that file is counted in the code coverage, even though the exports from that file may not be used.
    // The execution of the file can even run functions during it's own initialization to create its exports, making it
    // somewhat difficult to identify whether that file was truely touched by a test, or it was just exported and
    // imported and none of the exports were used.
    //
    // In order to address this, when we run the `dry-run` in order to identify what tests exist, we also run that under
    // the coverage tool.  Then we create a map of all the files->functions that are executed during the dry-run.  Those
    // functions are excluded from later code coverage analysis -- they're always run, so we can't distinguish from
    // whether a test is exercising that code, or just importing the file.
    //
    // This creates the possibility of test gaps, but it should be minimized to just "never ran an exported function
    // (that wasn't run during the import)", which *seems* on the surface like a pretty good solution.
    fn create_coverage_data_baseline(lcov_path: &Path) -> HashMap<PathBuf, HashSet<FunctionName>> {
        let reader = Reader::open_file(lcov_path).expect("Failed to open LCOV file");
        let mut current_source_file = None;
        let mut coverage_data_baseline: HashMap<PathBuf, HashSet<FunctionName>> = HashMap::new();

        for record in reader {
            match record {
                Ok(Record::SourceFile { path }) => {
                    current_source_file = Some(path.clone());
                }
                Ok(Record::FunctionData {
                    name: function_name,
                    count,
                    ..
                }) if count > 0 => {
                    if let Some(ref current_source_file) = current_source_file {
                        coverage_data_baseline
                            .entry(current_source_file.clone())
                            .or_default()
                            .insert(FunctionName(function_name));
                    }
                }
                _ => {}
            }
        }

        coverage_data_baseline
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_coverage_data(
        lcov_path: &Path,
        coverage_data: &mut CommitCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
        test_case: &JavascriptMochaConcreteTestIdentifier,
        external_dependencies: &HashMap<String, Package>,
        coverage_data_baseline: &HashMap<PathBuf, HashSet<FunctionName>>,
    ) -> Result<(), RunTestError> {
        let reader = Reader::open_file(lcov_path).expect("Failed to open LCOV file");
        let mut current_source_file = None;
        let mut current_source_file_is_hit = false;

        for record in reader {
            match record {
                Ok(Record::SourceFile { path }) => {
                    current_source_file = Some(path.clone());
                    current_source_file_is_hit = false;
                }
                // It's a bit debatable whether to trigger off `LineData` or `FunctionData` hits.  If a test file
                // includes a module (eg. `require()` or `import`), then `LineData` would show it as a dependency...
                // even if the import isn't used... because the file needs to be executed to create its exports.  With
                // `FunctionData`, the idea is that only *used* dependencies will be traced rather than just imports.
                // I'm not sure yet whether there are dependency cases this might miss... exporting constants is likely
                // one of those cases though.  At least for the moment `FunctionData` seems like a more effective way to
                // trace, until those other cases are explored.
                Ok(Record::FunctionData {
                    name: ref function_name,
                    count,
                    ..
                }) if count > 0 => {
                    if !current_source_file_is_hit {
                        if let Some(ref current_source_file) = current_source_file {
                            if let Some(function_map) =
                                coverage_data_baseline.get(current_source_file)
                            {
                                // FIXME: this is a dumb clone -- just occurring to create the wrapper FunctionName type
                                if function_map.contains(&FunctionName(function_name.clone())) {
                                    // This function was hit even in the baseline, so we can't count on it as a good
                                    // indicator of a test dependency.  Don't match current_source_file_is_hit because
                                    // there may be other functions in this file, but move on from this function without
                                    // processing it.
                                    trace!(
                                        "test {:?} ignoring coverage touch of {} {function_name:?} due to presence in baseline",
                                        test_case.test_identifier.full_title,
                                        current_source_file.display(),
                                    );
                                    continue;
                                }
                            }

                            if current_source_file.starts_with("node_modules") {
                                let package_dependency = Self::touched_external_dependency(
                                    test_case,
                                    coverage_data,
                                    current_source_file,
                                    external_dependencies,
                                );
                                if let Some(package_dependency) = package_dependency {
                                    trace!(
                                        "test {:?} hit external dependency {:?}",
                                        test_case.test_identifier.full_title,
                                        package_dependency.resolved,
                                    );
                                }
                            } else if current_source_file.is_absolute() {
                                // not sure what an absolute file is here, but it's not a project file
                            } else {
                                trace!(
                                    "test {:?} hit in-project file {}",
                                    test_case.test_identifier.full_title,
                                    current_source_file.display()
                                );
                                coverage_data.add_file_to_test(FileCoverage {
                                    file_name: current_source_file.clone(),
                                    test_identifier: test_case.test_identifier.clone(),
                                });
                            }
                        }
                        current_source_file_is_hit = true;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn touched_external_dependency(
        test_case: &JavascriptMochaConcreteTestIdentifier,
        coverage_data: &mut CommitCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
        current_source_file: &Path,
        external_dependencies: &HashMap<String, Package>,
    ) -> Option<JavascriptPackageDependency> {
        // example path: "node_modules/mocha/node_modules/glob/src/has-magic.ts". walk the path
        // backwards until we find a match in package-lock.json's `packages`, from which we can
        // extract the version and mark the dependency.
        let mut path = current_source_file.to_path_buf();
        let mut success = false;
        while let Some(parent) = path.parent() {
            // FIXME: might make more sense to have HashMap<PathBuf, Package> to avoid conversions here
            let package_subpath = parent.to_str().expect("referenced path in JS trace to str");
            if let Some(package) = external_dependencies.get(package_subpath) {
                match package {
                    Package {
                        version: Some(version),
                        resolved: Some(resolved),
                        integrity: Some(integrity),
                        ..
                    } => {
                        let package_dependency = JavascriptPackageDependency {
                            package_subpath: String::from(package_subpath),
                            version: version.clone(),
                            resolved: resolved.clone(),
                            integrity: integrity.clone(),
                        };
                        coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
                            test_identifier: test_case.test_identifier.clone(),
                            coverage_identifier: JavascriptCoverageIdentifier::PackageDependency(
                                package_dependency.clone(),
                            ),
                        });
                        return Some(package_dependency);
                    }
                    _ => {
                        // FIXME: not sure if this should be a warning or an error
                        warn!(
                            "missing version, resolved, or integrity field in dependency {package_subpath:}: {package:?}"
                        );
                    }
                }
                success = true;
                break;
            }
            path = parent.to_path_buf();
        }
        if !success {
            // FIXME: not sure if this should be a warning or an error
            warn!(
                "unable to trace external dependency of accessed source file {}",
                current_source_file.display(),
            );
        }
        None
    }

    fn parse_project_external_dependencies() -> Result<HashMap<String, Package>, RunTestsErrors> {
        let mut package_json: PackageLock =
            serde_json::from_reader(File::open("package-lock.json")?).map_err(|e| {
                RunTestsErrors::PlatformError(format!("unable to parse package-lock.json: {e:?}"))
            })?;
        // Remove the root package ("") because it's not an external dependency; could be confusing to access it.
        package_json.packages.remove("");
        Ok(package_json.packages)
    }

    fn diff_package_lock(
        ancestor_lock: &PackageLock,
        current_lock: &PackageLock,
    ) -> HashSet<JavascriptPackageDependency> {
        let mut relevant_changes = HashSet::new();

        // If the ancestor lock file has a package in it, and the new lock file doesn't, then trigger any tests that
        // referenced the ancestor's package.

        let mut current_lock_map: HashSet<(&String, &Package)> = HashSet::new();
        for (package_subpath, package) in &current_lock.packages {
            current_lock_map.insert((package_subpath, package));
        }

        for (package_subpath, package) in &ancestor_lock.packages {
            if !current_lock_map.contains(&(package_subpath, package)) {
                if let Package {
                    version: Some(version),
                    resolved: Some(resolved),
                    integrity: Some(integrity),
                    ..
                } = package
                {
                    relevant_changes.insert(JavascriptPackageDependency {
                        package_subpath: package_subpath.clone(),
                        version: version.clone(),
                        resolved: resolved.clone(),
                        integrity: integrity.clone(),
                    });
                }
            }
        }

        relevant_changes
    }

    fn package_lock_deps_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<JavascriptMochaTestIdentifier>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
        test_cases: &mut HashMap<
            JavascriptMochaTestIdentifier,
            HashSet<TestReason<JavascriptCoverageIdentifier>>,
        >,
    ) -> Result<usize> {
        // I think there might be plausible cases where Cargo.lock loading from the previous commit would fail, but we
        // wouldn't want to error out... for example, if Cargo.lock was added since the ancestor commit?.  But I'm not
        // confident what those cases would be where we would actually have ancestor coverage data yet be discovering
        // Cargo.lock wasn't present?  And what behavior we'd want.  So for now we'll treat that as an error and wait
        // for the situation to appear.
        let ancestor_lock =
            scm.fetch_file_content(ancestor_commit, Path::new("package-lock.json"))?;
        let ancestor_lock = String::from_utf8(ancestor_lock)?;
        let ancestor_lock: PackageLock = serde_json::from_str(&ancestor_lock)?;
        let current_lock: PackageLock = serde_json::from_reader(File::open("package-lock.json")?)?;

        let relevant_changes = Self::diff_package_lock(&ancestor_lock, &current_lock);

        let mut changed_external_dependencies = 0;
        for relevant_change in relevant_changes {
            info!(
                "Change to dependency {}; will run all tests that touched it",
                relevant_change.resolved
            );
            changed_external_dependencies += 1;
            let coverage_identifier =
                JavascriptCoverageIdentifier::PackageDependency(relevant_change);

            if let Some(tests) = coverage_data
                .coverage_identifier_to_test_map()
                .get(&coverage_identifier)
            {
                for test in tests {
                    if eval_target_test_cases.contains(test) {
                        debug!("test {test:?} needs rerun");
                        test_cases
                            .entry(test.clone())
                            .or_default()
                            .insert(TestReason::CoverageIdentifier(coverage_identifier.clone()));
                    }
                }
            }
        }

        Ok(changed_external_dependencies)
    }
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
        let package_json: Value = serde_json::from_reader(File::open("package.json")?)?;
        if let Value::Object(ref object) = package_json {
            if let Some(name) = object.get("name") {
                if let Value::String(name) = name {
                    Ok(name.clone())
                } else {
                    Err(anyhow!("package.json / name field is not a string"))
                }
            } else {
                Err(anyhow!("package.json / name field is missing"))
            }
        } else {
            Err(anyhow!("package.json is not a map"))
        }
    }

    #[instrument(skip_all, fields(perftrace = "discover-tests"))]
    async fn discover_tests(project_dir: &Path) -> Result<JavascriptMochaTestDiscovery> {
        let json_output = tempfile::Builder::new().prefix("testtrim").tempfile()?;

        let tmp_dir = tempfile::Builder::new().prefix("testtrim").tempdir()?;
        let cache_dir = tmp_dir.path().join("cache");
        let report_dir = tmp_dir.path().join("report");
        let nyc_temp_dir = tmp_dir.path().join("nyc_output");

        let output = Command::new("npm")
            .args([
                // npm options:
                AsRef::<OsStr>::as_ref("test"),
                AsRef::<OsStr>::as_ref("--"),

                // nyc options:
                AsRef::<OsStr>::as_ref("--reporter=lcovonly"),
                // If we don't use separate `--temp-dir` for each test run, then coverage data bleeds between tests.
                AsRef::<OsStr>::as_ref("--temp-dir"),
                AsRef::<OsStr>::as_ref(&nyc_temp_dir),
                // FIXME: it might be OK for `--cache-dir` to be shared and, for basic tests, reduces runtime by about 1/3rd...
                AsRef::<OsStr>::as_ref("--cache-dir"),
                AsRef::<OsStr>::as_ref(&cache_dir),
                AsRef::<OsStr>::as_ref("--report-dir"),
                AsRef::<OsStr>::as_ref(&report_dir),
                // Instrument node_modules files so that we can track dependency usage.
                AsRef::<OsStr>::as_ref("--exclude-node-modules=false"),
                // Override the default --exclude which would exclude test files.
                AsRef::<OsStr>::as_ref("--exclude=\"\""),

                // mocha options:
                AsRef::<OsStr>::as_ref("mocha"),
                AsRef::<OsStr>::as_ref("--dry-run"),
                AsRef::<OsStr>::as_ref("--reporter=json"),
                AsRef::<OsStr>::as_ref(&format!(
                    "--reporter-option=output={}",
                    json_output.path().to_string_lossy()
                )),
            ])
            .current_dir(project_dir)
            .output()
            .instrument(info_span!("npm run test -- mocha --dry-run --reporter=json",
                subcommand = true,
                subcommand_binary = ?"npm",
                subcommand_args = ?["run", "test", "--", "mocha", "--dry-run", "--reporter=json"],
            ))
            .await
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "npm run test -- mocha --dry-run --reporter=json".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: "npm run test -- mocha --dry-run --reporter=json".to_string(),
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
                    // FIXME:
                    test_src_path: PathBuf::new(),
                    full_title: mocha_test.full_title.clone(),
                },
                absolute_test_src_path: PathBuf::from(&mocha_test.file),
            });
            if !success {
                return Err(anyhow!(
                    "failed to insert test case for {mocha_test:?}, indicating a duplicate test case"
                ));
            }
        }

        let coverage_data_baseline =
            Self::create_coverage_data_baseline(&report_dir.join("lcov.info"));

        debug!("discovered tests: {test_cases:?}");
        Ok(JavascriptMochaTestDiscovery {
            all_test_cases: test_cases,
            coverage_data_baseline,
            _cache_tmp_dir: tmp_dir,
            cache_dir,
        })
    }

    #[instrument(skip_all, fields(perftrace = "platform-specific-test-cases"))]
    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<JavascriptMochaTestIdentifier>,
        eval_target_changed_files: &HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
    ) -> Result<
        PlatformSpecificRelevantTestCaseData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
    > {
        let mut test_cases: HashMap<
            JavascriptMochaTestIdentifier,
            HashSet<TestReason<JavascriptCoverageIdentifier>>,
        > = HashMap::new();

        let mut external_dependencies_changed = None;
        // FIXME: I'm not confident that this check is right -- could there be multiple lock files in a realistic repo?
        // But this is simple and seems pretty applicable for now.
        if eval_target_changed_files.contains(Path::new("package-lock.json")) {
            external_dependencies_changed = Some(Self::package_lock_deps_test_cases(
                eval_target_test_cases,
                scm,
                ancestor_commit,
                coverage_data,
                &mut test_cases,
            )?);
        }

        Ok(PlatformSpecificRelevantTestCaseData {
            additional_test_cases: test_cases,
            external_dependencies_changed,
        })
    }

    #[instrument(skip_all)]
    async fn run_tests<'a, I>(
        test_discovery: &JavascriptMochaTestDiscovery,
        project_dir: &Path,
        test_cases: I,
        jobs: u16,
    ) -> Result<
        CommitCoverageData<JavascriptMochaTestIdentifier, JavascriptCoverageIdentifier>,
        RunTestsErrors,
    >
    where
        I: IntoIterator<Item = &'a JavascriptMochaConcreteTestIdentifier>,
        JavascriptMochaConcreteTestIdentifier: 'a,
    {
        let external_dependencies = Arc::new(Self::parse_project_external_dependencies()?);

        let mut futures = vec![];
        for test_case in test_cases {
            let tc = test_case.clone();
            let ed = external_dependencies.clone();
            futures.push(async move {
                JavascriptMochaTestPlatform::run_test(
                    project_dir,
                    &tc,
                    &ed,
                    &test_discovery.coverage_data_baseline,
                    &test_discovery.cache_dir,
                )
                .instrument(info_span!("npm run test",
                    ui_stage = Into::<u64>::into(UiStage::RunSingleTest),
                    test_case = %tc.test_identifier(),
                ))
                .await
            });
        }
        let concurrency = if jobs == 0 {
            num_cpus::get()
        } else {
            jobs.into()
        };
        tracing::info!(
            ui_info = "run-test-count",
            count = futures.len(),
            concurrency
        );
        let results = spawn_limited_concurrency(concurrency, futures).await;

        let mut coverage_data = CommitCoverageData::new();
        let mut failed_test_results = vec![];
        for result in results {
            match result {
                Ok(res) => coverage_data.merge_in(res),
                Err(RunTestError::TestExecutionFailure(failed_test_result)) => {
                    failed_test_results.push(failed_test_result);
                }
                Err(e) => return Err(e.into()),
            }
        }

        if failed_test_results.is_empty() {
            Ok(coverage_data)
        } else {
            Err(RunTestsErrors::TestExecutionFailures(failed_test_results))
        }
    }

    fn analyze_changed_files(
        _project_dir: &Path,
        _changed_files: &HashSet<PathBuf>,
        _coverage_data: &mut CommitCoverageData<
            JavascriptMochaTestIdentifier,
            JavascriptCoverageIdentifier,
        >,
    ) -> Result<()> {
        Ok(())
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
    }
}
