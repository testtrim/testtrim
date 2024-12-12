// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context as _, Result};
use gomod_rs::{parse_gomod, Directive};
use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::env::{self, current_dir};
use std::fs::{read_to_string, File};
use std::hash::Hash;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::{fmt, fs, io};
use tempdir::TempDir;
use threadpool::ThreadPool;
use tracing::dispatcher::{self, get_default};
use tracing::{info_span, instrument};

use crate::coverage::commit_coverage_data::{
    CommitCoverageData, CoverageIdentifier, FileCoverage, HeuristicCoverage,
};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::{
    FailedTestResult, RunTestError, RunTestsErrors, SubcommandErrors, TestFailure,
};
use crate::scm::{Scm, ScmCommit};
use crate::sys_trace::sys_trace_command;
use crate::sys_trace::trace::Trace;

use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestIdentifierCore, TestPlatform, TestReason,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct GolangTestIdentifier {
    pub binary_name: BinaryName,
    pub test_name: String,
}

impl TestIdentifier for GolangTestIdentifier {}
impl TestIdentifierCore for GolangTestIdentifier {
    fn lightly_unique_name(&self) -> String {
        todo!()
    }
}

impl fmt::Display for GolangTestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {}", self.binary_name.0, self.test_name)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum GolangCoverageIdentifier {
    // Possible future: go version, platform, etc. -- might be better as tags since they'd be pretty universal for the whole commit though?
    PackageDependency(ModuleDependency),
    InferredFromTestFileChange(PathBuf),
    // NetworkDependency(UnifiedSocketAddr),
}

impl CoverageIdentifier for GolangCoverageIdentifier {}

#[derive(Debug, Clone)]
pub struct GolangConcreteTestIdentifier {
    pub test_identifier: GolangTestIdentifier,
    _binary_dir: Arc<TempDir>,
    binary_path: PathBuf,
}

impl PartialEq for GolangConcreteTestIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.test_identifier == other.test_identifier && self.binary_path == other.binary_path
    }
}

impl Hash for GolangConcreteTestIdentifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.test_identifier.hash(state);
        self.binary_path.hash(state);
    }
}

impl Eq for GolangConcreteTestIdentifier {}

impl ConcreteTestIdentifier<GolangTestIdentifier> for GolangConcreteTestIdentifier {
    fn test_identifier(&self) -> &GolangTestIdentifier {
        &self.test_identifier
    }
}

pub struct GolangTestDiscovery {
    all_test_cases: HashSet<GolangConcreteTestIdentifier>,
}

impl TestDiscovery<GolangConcreteTestIdentifier, GolangTestIdentifier> for GolangTestDiscovery {
    fn all_test_cases(&self) -> &HashSet<GolangConcreteTestIdentifier> {
        &self.all_test_cases
    }

    fn map_ti_to_cti(
        &self,
        test_identifier: GolangTestIdentifier,
    ) -> Option<GolangConcreteTestIdentifier> {
        for cti in &self.all_test_cases {
            if cti.test_identifier == test_identifier {
                return Some(cti.clone());
            }
        }
        None
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ModulePath(pub String); // eg. github.com/shopspring/decimal

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct BinaryName(pub String); // eg. go-coverage-specimen.out

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ModuleDependency {
    module_path: ModulePath,
    version: String,
}

struct ModuleInfo {
    module_path: ModulePath,
    dependencies: Vec<ModuleDependency>,
}

#[derive(Clone)]
struct GoCoverageData<'a> {
    module_and_file: &'a str,
    start_marker: &'a str,
    end_marker: &'a str,
    // _num_statements: &'a str,
    hit_count: &'a str,
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
struct GoCoverageStatementIdentity {
    module_and_file: String,
    start_marker: String,
    end_marker: String,
}

impl<'a> From<&GoCoverageData<'a>> for (GoCoverageStatementIdentity, i32) {
    fn from(data: &GoCoverageData<'a>) -> Self {
        let statement_identity = GoCoverageStatementIdentity {
            module_and_file: data.module_and_file.to_string(),
            start_marker: data.start_marker.to_string(),
            end_marker: data.end_marker.to_string(),
        };
        let hit_count: i32 = data.hit_count.parse().unwrap_or(0); // Converts hit_count to i32, defaults to 0 on parse failure
        (statement_identity, hit_count)
    }
}

lazy_static! {
    // See comment in guess_tests_from_test_file_changed for why this exists
    static ref test_func_definition: Regex = Regex::new(
        r"(?xs)
        func
        \s+
        (?<test_name>
            Test
            [A-Z]
            \S+
        )
        \s*    # opt whitespace between name and params
        \(     # start of function parameters
        "
    )
    .unwrap();
}

pub struct GolangTestPlatform;

impl GolangTestPlatform {
    #[must_use]
    pub fn autodetect() -> bool {
        if fs::exists("go.mod")
            .expect("autodetect test project type failed when checking go.mod existence")
        {
            trace!("Detected go.mod; auto-detect result: Golang test project");
            true
        } else {
            false
        }
    }

    fn get_build_test_command(module_info: &ModuleInfo, tmp_dir: &TempDir) -> Command {
        // form the coverpkg arg out of all the dependencies
        let mut coverpkg = String::with_capacity(1024);
        for dep in &module_info.dependencies {
            coverpkg.push_str(&dep.module_path.0);
            coverpkg.push(',');
        }
        coverpkg.push_str("./..."); // include this package and all local subpackages

        let mut cmd = Command::new("go");
        cmd.args([
            "test",
            "-c",
            "-o",
            &(String::from(tmp_dir.path().to_string_lossy()) + "/"),
            "-json",
            "-cover",
            "-covermode",
            "count",
            "-coverpkg",
            &coverpkg,
        ]);
        cmd
    }

    fn get_run_test_command(binary_path: &Path, test_regex: &str, profile_file: &Path) -> Command {
        let mut cmd = Command::new(binary_path);
        cmd.args([
            "-test.run",
            test_regex,
            "-test.coverprofile",
            &profile_file.to_string_lossy(),
        ]);
        cmd
    }

    // When an external dependency is present in Go, constants and their initialization functions are captured even if
    // the library isn't actually touched.  For example, in go-coverage-specimen check-8 when an external dependency is
    // added, every test will record instrumentation data showing that the external dependency is touched when executed.
    // This isn't great because it doesn't allow testtrim to target the tests that actually use that external
    // dependency; as long as it has initialization code, it will be tracked as touched during that test.
    //
    // There is an argument to be made that the behavior is correct: initialization code is executed, and theoretically
    // it could have an impact on the test.  But for testtrim's purposes we're going to try to be more specific.
    //
    // testtrim works around this by, for every module that we're running tests, generating a "no-op" test coverage map.
    // Basically run a test that doesn't exists (eg. "FooBarTestAbc123987!"), and capture its coverage specifically for
    // external dependencies.  And then when we run a later test, we'll use that no-op test coverage map as a baseline.
    // The external dependency will only be considered a dependency of the test if the coverage map for that extermal
    // dependency varies from the baseline.
    //
    // `-mode count` causes Go to collect a count for the number of times each branch is touched, rather than a boolean
    // 1 or 0 (`-mode set`).  The `count` mode is preferred because it causes that external dependency coverage map to
    // reliably detect dependency access -- with mode set, if you happened to hit the same codepaths as the
    // initialization code during a test, the dependency wouldn't be tracked.  (A more aggressive atomic count mode
    // exists which makes the counts threadsafe, but that seems unnecessary as the initialization code, I think, can't
    // be multithreaded.)
    //
    // This same problem *probably* exists if you don't have an external dependency too!  Const values during package
    // initialization would always show as being touched by every test.  A future investigation should be done to
    // identify the best behavior in this case.
    fn get_baseline_ext(
        test_binary_path: &Path,
        tmp_path: &Path,
    ) -> Result<HashMap<GoCoverageStatementIdentity, i32>> {
        let profile_file = tmp_path.join("__baseline__.out");
        let mut cmd = Self::get_run_test_command(
            test_binary_path,
            "^$", // goal is an impossible test name; zero-length string should be impossible?
            &profile_file,
        );
        debug!("running: {cmd:?}");
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to run go test for baseline; exit code: {:?}",
                output.status
            ));
        }

        let mut retval = HashMap::new();
        let reader =
            BufReader::new(File::open(profile_file).context("Failed to open profile file")?);
        for line in reader.lines() {
            let line = line?;
            if line.starts_with("mode: ") {
                continue;
            }
            let line = Self::parse_go_coverage_line(&line);
            if line.hit_count == "0" {
                // No need to keep track of this.
                continue;
            }
            // Currently we don't skip anything from within our own module (eg. using `test_module_name`), and so we'll
            // also end up ignoring coverage that is "always present" in our module.  It isn't super clear whether
            // that's the right thing to do or not.
            let extract: (GoCoverageStatementIdentity, i32) = (&line).into();
            let (identity, count) = extract;
            retval.insert(identity, count);
        }

        Ok(retval)
    }

    fn run_test(
        test_case: &GolangConcreteTestIdentifier,
        tmp_path: &Path,
        module_info: &ModuleInfo,
        package_baseline: &HashMap<BinaryName, HashMap<GoCoverageStatementIdentity, i32>>,
    ) -> Result<CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>, RunTestError>
    {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_executed_test(test_case.test_identifier.clone());

        let coverage_dir = tmp_path
            .join(Path::new("coverage-output").join(&test_case.test_identifier.binary_name.0));
        // Create coverage_dir but ignore if its error is 17 (file exists)
        fs::create_dir_all(&coverage_dir)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .context("Failed to create coverage directory")?;

        let profile_file = coverage_dir
            .join(&test_case.test_identifier.test_name)
            .with_extension("out");
        let strace_file = coverage_dir
            .join(&test_case.test_identifier.test_name)
            .with_extension("strace");

        debug!(
            "Execute test case {:?} into {:?}...",
            test_case, profile_file
        );
        let (output, trace) = info_span!("execute-test", perftrace = "run-test", parallel = true)
            .in_scope(|| {
            let cmd = Self::get_run_test_command(
                &test_case.binary_path,
                // make sure we're matching the one and only test:
                &format!("^{}$", regex::escape(&test_case.test_identifier.test_name)),
                &profile_file,
            );
            sys_trace_command.trace_command(cmd, &strace_file)
        })?;

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

        let Some(package_baseline) = package_baseline.get(&test_case.test_identifier.binary_name)
        else {
            return Err(RunTestError::Other(anyhow!(
                "could not find coverage baseline for binary {:?}",
                test_case.test_identifier.binary_name.0
            )));
        };

        Self::parse_profiling_data(
            test_case,
            &profile_file,
            &mut coverage_data,
            module_info,
            package_baseline,
        )?;
        Self::parse_trace_data(test_case, &trace, &mut coverage_data)?;

        Ok(coverage_data)
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_profiling_data(
        test_case: &GolangConcreteTestIdentifier,
        profile_file: &PathBuf,
        coverage_data: &mut CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
        module_info: &ModuleInfo,
        package_baseline: &HashMap<GoCoverageStatementIdentity, i32>,
    ) -> Result<()> {
        let reader =
            BufReader::new(File::open(profile_file).context("Failed to open profile file")?);

        let mut file_to_module_map = HashSet::new();

        for line in reader.lines() {
            let line = line?;
            if line.starts_with("mode: ") {
                continue;
            }

            let line = Self::parse_go_coverage_line(&line);
            if line.hit_count == "0" {
                continue;
            }

            let extract: (GoCoverageStatementIdentity, i32) = (&line).into();
            let (identity, current_count) = extract;
            if let Some(baseline_count) = package_baseline.get(&identity) {
                match baseline_count.cmp(&current_count) {
                    Ordering::Equal => {
                        // Skip this coverage line -- it's the same as our baseline coverage, so nothing new.
                        continue;
                    }
                    Ordering::Less => {
                        // Good, we've really touched this stmt in this test; the baseline count was lower than the
                        // current count.  Proceed to mark it as a dependency.
                    }
                    Ordering::Greater => {
                        // I think this should never happen; just curious to see if it does
                        warn!("baseline_count {baseline_count} was greater than current count {current_count} for identity {identity:?}");
                    }
                }
            }

            // If we can strip the module name (eg. codeberg.org/testtrim/go-coverage-specimen) from the module + file,
            // then it's a file that is relative to our repo and we can record file coverage.
            //
            // FIXME: we can probably keep track of line.module_and_file and only process it through the rest of this
            // function once, as it will likely be repeated many times in the coverage file.
            let relative_file = line
                .module_and_file
                .strip_prefix(&(module_info.module_path.0.clone() + "/"));

            if let Some(relative_file) = relative_file {
                if relative_file.starts_with('/') {
                    // strip_prefix has a hack above to ensure it is getting relative files (eg. basic_ops.rs, not
                    // /basic_ops.rs); this check just raises the visibility of any problem that might occur here
                    error!("relative_file was incorrectly prefix stripped; {relative_file:?}");
                }
                trace!(
                    "test case {:?} touched file {}",
                    test_case.test_identifier,
                    relative_file
                );
                coverage_data.add_file_to_test(FileCoverage {
                    test_identifier: test_case.test_identifier.clone(),
                    file_name: PathBuf::from(relative_file),
                });
            } else {
                // (otherwise it's a file from a dependency...)
                if !file_to_module_map.contains(line.module_and_file) {
                    // Ideally would use the .insert() retval, but then it would need to clone the module_and_file
                    // string every time... on the other hand this does two traversals of the hash, so, which is better?
                    // FIXME: would be fun to micro-benchmark, but probably not important
                    file_to_module_map.insert(String::from(line.module_and_file));

                    // First time we've found this module/file; need to resolve it to a dependency:
                    let mut dependency = None;
                    for dep in &module_info.dependencies {
                        if line.module_and_file.starts_with(&dep.module_path.0) {
                            dependency = Some(dep);
                        }
                    }

                    if let Some(dependency) = dependency {
                        trace!(
                            "test case {:?} touched file... {:?} -> {dependency:?}",
                            test_case.test_identifier,
                            line.module_and_file
                        );
                        coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
                            test_identifier: test_case.test_identifier.clone(),
                            coverage_identifier: GolangCoverageIdentifier::PackageDependency(
                                ModuleDependency {
                                    module_path: dependency.module_path.clone(),
                                    version: dependency.version.clone(),
                                },
                            ),
                        });
                    } else {
                        warn!("test touched file {:?} but could not identify what dependency this came from", line.module_and_file);
                    }
                }
            }
        }

        Ok(())
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_trace_data(
        test_case: &GolangConcreteTestIdentifier,
        trace: &Trace,
        coverage_data: &mut CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<()> {
        let repo_root = env::current_dir()?;

        // FIXME: This doesn't work right now because the current test execution method runs a build on every individual
        // test.  We'll have to change this to do a build once (go test -c -o test-binary) and then run test-binary
        // separately for each test.  This should be much faster too, and experimental testing shows it will isolate the
        // `strace` to just the specific test.

        for path in trace.get_open_paths() {
            if path.is_relative() || path.starts_with(&repo_root) {
                debug!(
                    "found test {} accessed local file {path:?}",
                    test_case.test_identifier
                );

                let target_path = crate::platform::rust::RustTestPlatform::normalize_path(
                    path,
                    &repo_root.join("fake"), // normalize_path expects relative_to to be a file, not dir; so we add a fake child path
                    &repo_root,
                    |warning| {
                        warn!("syscall trace accessed path {path:?} but couldn't normalize to repo root: {warning}");
                    },
                );
                debug!("target_path = {target_path:?}");
                if let Some(target_path) = target_path {
                    // It might make sense to filter out files that aren't part of the repo... both here and in
                    // parse_profiling_data?
                    coverage_data.add_file_to_test(FileCoverage {
                        file_name: target_path.clone(),
                        test_identifier: test_case.test_identifier.clone(),
                    });
                }
            }
            // FIXME: absolute path case -- check if it's part of the repo/cwd, and if so include it
        }

        // for sockaddr in trace.get_connect_sockets() {
        //     coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
        //         test_identifier: test_case.test_identifier.clone(),
        //         coverage_identifier: RustCoverageIdentifier::NetworkDependency(sockaddr.clone()),
        //     });
        // }

        Ok(())
    }

    fn parse_go_coverage_line<'a>(line: &'a str) -> GoCoverageData<'a> {
        // https://github.com/golang/go/blob/c5d7f2f1cbaca8938a31a022058b1a3300817e33/src/cmd/cover/profile.go#L53-L56
        // First line is "mode: foo", where foo is "set", "count", or "atomic".
        // Rest of file is in the format
        //	encoding/base64/base64.go:34.44,37.40 3 1
        // where the fields are: name.go:line.column,line.column numberOfStatements count
        let parts: Vec<&'a str> = line.split_whitespace().collect();
        let file_and_markers: Vec<&'a str> = parts[0].split(':').collect();
        let markers: Vec<&'a str> = file_and_markers[1].split(',').collect();
        GoCoverageData {
            module_and_file: file_and_markers[0],
            start_marker: markers[0],
            end_marker: markers[1],
            // _num_statements: parts[1],
            hit_count: parts[2],
        }
    }

    fn parse_module_info() -> Result<ModuleInfo> {
        let contents = read_to_string("go.mod")?;
        let gomod = parse_gomod(&contents)?;

        /*
        01:29:22 [DEBUG] (2) testtrim::platform::golang: gomod = [
        Context { range: (Location { line: 1, offset: 0 }, Location { line: 2, offset: 50 }), comments: [], value: Module { module_path: "codeberg.org/testtrim/go-coverage-specimen" } },
        Context { range: (Location { line: 3, offset: 51 }, Location { line: 4, offset: 61 }), comments: [], value: Go { version: Raw("1.23.3") } },
        Context { range: (Location { line: 5, offset: 62 }, Location { line: 6, offset: 107 }), comments: [], value:
            Require { specs: [Context { range: (Location { line: 5, offset: 70 }, Location { line: 6, offset: 107 }), comments: [], value: ("github.com/shopspring/decimal", Raw("v1.3.1"))
        }] } }]
        */

        let mut module_path: Option<String> = None;
        let mut dependencies: Vec<ModuleDependency> = vec![];

        for item in gomod {
            match item.value {
                Directive::Module { module_path: mp } => {
                    module_path = Some(String::from(mp));
                }
                Directive::Require { specs } => {
                    for spec in specs {
                        let (dependency_module_path, version) = spec.value;
                        dependencies.push(ModuleDependency {
                            module_path: ModulePath(String::from(dependency_module_path)),
                            version: String::from(&*version),
                        });
                    }
                }
                // FIXME: Replace, Exclude, Extract -- do these need to be supported?
                _ => {}
            }
        }

        if let Some(module_path) = module_path {
            Ok(ModuleInfo {
                module_path: ModulePath(module_path),
                dependencies,
            })
        } else {
            Err(anyhow!("unable to parse `module` identifier from `go.mod`"))
        }
    }

    fn go_mod_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<GolangTestIdentifier>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
        test_cases: &mut HashMap<GolangTestIdentifier, Vec<TestReason<GolangCoverageIdentifier>>>,
    ) -> Result<usize> {
        // I think there might be plausible cases where Cargo.lock loading from the previous commit would fail, but we
        // wouldn't want to error out... for example, if Cargo.lock was added since the ancestor commit?.  But I'm not
        // confident what those cases would be where we would actually have ancestor coverage data yet be discovering
        // Cargo.lock wasn't present?  And what behavior we'd want.  So for now we'll treat that as an error and wait
        // for the situation to appear.
        let ancestor_lock = scm.fetch_file_content(ancestor_commit, Path::new("go.mod"))?;
        let ancestor_lock = String::from_utf8(ancestor_lock)?;
        let ancestor_lock = parse_gomod(&ancestor_lock)?;

        let current_lock_data = read_to_string("go.mod")?;
        let current_lock = parse_gomod(&current_lock_data)?;
        let mut current_lock_map = HashMap::new();
        for item in current_lock {
            // FIXME: Replace, Exclude, Extract -- do these need to be supported?
            if let Directive::Require { specs } = item.value {
                for spec in specs {
                    let (dependency_module_path, version) = spec.value;
                    current_lock_map.insert(
                        ModulePath(String::from(dependency_module_path)),
                        String::from(&*version),
                    );
                }
            }
        }
        // for p in current_lock.packages {
        //     current_lock_map.insert(String::from(p.name), p.version);
        // }

        // Cases to consider:
        // - Packages with same version in both: Ignore.
        // - Packages that have changed from one version to another: search for coverage data based upon old version,
        //   add tests.
        // - Packages that have were present in ancestor_lock and aren't in current_lock: I think also search and add
        //   those tests?
        // - New packages in current_lock that aren't in ancestor_lock aren't relevant -- they wouldn't be part of the
        //   ancestor's coverage data.

        let mut changed_external_dependencies = 0;
        for item in ancestor_lock {
            // FIXME: Replace, Exclude, Extract -- do these need to be supported?
            if let Directive::Require { specs } = item.value {
                for spec in specs {
                    let (old_module_path, old_version) = spec.value;
                    let old_module_path = ModulePath(String::from(old_module_path));
                    let old_version = String::from(&*old_version);

                    let relevant_change =
                        if let Some(current_version) = current_lock_map.get(&old_module_path) {
                            if *current_version == old_version {
                                false
                            } else {
                                trace!(
                                    "go.mod package changed {:?}, old: {}, current: {}",
                                    old_module_path,
                                    old_version,
                                    current_version
                                );
                                true
                            }
                        } else {
                            trace!("go.mod package removed {:?}", old_module_path);
                            true
                        };

                    if relevant_change {
                        info!(
                            "Change to dependency {:?}; will run all tests that touched it",
                            old_module_path
                        );
                        changed_external_dependencies += 1;
                        let coverage_identifier =
                            GolangCoverageIdentifier::PackageDependency(ModuleDependency {
                                module_path: old_module_path,
                                version: old_version,
                            });

                        if let Some(tests) = coverage_data
                            .coverage_identifier_to_test_map()
                            .get(&coverage_identifier)
                        {
                            for test in tests {
                                if eval_target_test_cases.contains(test) {
                                    debug!("test {test:?} needs rerun");
                                    test_cases.entry(test.clone()).or_default().push(
                                        TestReason::CoverageIdentifier(coverage_identifier.clone()),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(changed_external_dependencies)
    }

    fn guess_tests_from_test_file_changed(
        file: &Path,
        all_test_cases: &HashSet<GolangTestIdentifier>,
        test_cases: &mut HashMap<GolangTestIdentifier, Vec<TestReason<GolangCoverageIdentifier>>>,
    ) -> Result<()> {
        // Go doesn't instrument test files (_test.go).  (eg.
        // https://github.com/golang/go/blob/e0c76d95abfc1621259864adb3d101cf6f1f90fc/src/cmd/go/internal/work/exec.go#L644-L646)
        // Ideally we should work upstream to see if we could add this as an optional capability, but that will likely
        // be a long path forward.  Maybe fun, maybe not.
        //
        // In the mean time, we're going to do an inaccurate workaround -- read any modified _test.go files and try to
        // identify the test cases in them, and mark them as tests that need to be rerun because the _test.go file was
        // modified.  This is inaccurate for a few reasons:
        // - We're not a Go parser, so we're going to do a poor job of parsing the code.
        // - We're encoding Go's testing logic outside of Go, which means that it is subject to inaccuracies due to
        //   change or misunderstanding.
        // - Most importantly, it's possible for files in _test.go to refer to public functions defined in each other.
        //   Coverage-based testing would identify these dependencies, but this hack doesn't -- if you change a_test.go
        //   and it had a function used by b_test.go, we won't know that the tests in b_test.go need to be rerun.
        // However, it's probably "pretty good for most cases"?

        let test_file = fs::read_to_string(file)?;

        for cap in test_func_definition.captures_iter(&test_file) {
            let test_name = String::from(&cap["test_name"]);
            let mut any_match = false;
            for tc in all_test_cases {
                if tc.test_name == test_name {
                    any_match = true;
                    debug!("guessed that modification to {file:?} would require running {tc}");
                    test_cases
                        .entry(tc.clone())
                        .or_default()
                        .push(TestReason::CoverageIdentifier(
                            GolangCoverageIdentifier::InferredFromTestFileChange(PathBuf::from(
                                file,
                            )),
                        ));
                }
            }
            if !any_match {
                warn!("inferred that a test named {test_name} exists in file {file:?} but couldn't find it in test cases");
            }
        }

        Ok(())
    }
}

impl TestPlatform for GolangTestPlatform {
    type TI = GolangTestIdentifier;
    type CI = GolangCoverageIdentifier;
    type TD = GolangTestDiscovery;
    type CTI = GolangConcreteTestIdentifier;

    fn platform_identifier() -> &'static str {
        "golang"
    }

    fn project_name() -> Result<String> {
        Ok(String::from(
            current_dir()?
                .file_name()
                .ok_or_else(|| anyhow!("unable to find name of current directory"))?
                .to_string_lossy(),
        ))
    }

    #[instrument(skip_all, fields(perftrace = "discover-tests"))]
    fn discover_tests() -> Result<GolangTestDiscovery> {
        let module_info = Self::parse_module_info()?;

        // FIXME: one potential problem is that we're creating a temp directory, building go programs to it, and then
        // executing them.  The temp directory space is often configured as a space that can't have executables in it
        // (noexec) which could make this fail.
        //
        // FIXME: this uses an Arc to keep the TempDir from being dropped; it could probably be done instead by making
        // the GolangTestDiscovery outlive the ConcreteTestIdentifier and then hoisting the TempDir into the test
        // discovery object.  That's academically interesting since it's a lifetime problem that would help me learn
        // more about lifetime declarations, but, an Arc is just fine too.
        let tmp_dir = Arc::new(TempDir::new("testtrim")?);

        // First we build all test binaries:
        let mut cmd = Self::get_build_test_command(&module_info, &tmp_dir);
        debug!("running: {cmd:?}");
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("go test -c"),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }
        trace!("test build success");

        // Now we need to iterate through each of the binaries in tmp_dir and run `... -test.list .` to get the tests
        // that they contain:
        let mut all_test_cases: HashSet<GolangConcreteTestIdentifier> = HashSet::new();
        for dirent in fs::read_dir(tmp_dir.path())? {
            let dirent = dirent?;
            let mut cmd = Command::new(dirent.path());
            cmd.args(["-test.list", "."]);
            debug!("running: {cmd:?}");
            let output = cmd.output()?;
            if !output.status.success() {
                return Err(SubcommandErrors::SubcommandFailed {
                    command: String::from("'test-binary' -test.list ."),
                    status: output.status,
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                }
                .into());
            }

            let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
            for line in stdout.lines() {
                debug!("Found test case: {line:?}");
                all_test_cases.insert(GolangConcreteTestIdentifier {
                    test_identifier: GolangTestIdentifier {
                        binary_name: BinaryName(
                            dirent
                                .file_name()
                                .into_string()
                                .expect("must have unicode file names"),
                        ),
                        test_name: String::from(line),
                    },
                    // Hack: make tmp_dir live as long as the test identifiers
                    _binary_dir: tmp_dir.clone(),
                    binary_path: dirent.path(),
                });
            }
        }

        Ok(GolangTestDiscovery { all_test_cases })
    }

    #[instrument(skip_all, fields(perftrace = "platform-specific-test-cases"))]
    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<GolangTestIdentifier>,
        eval_target_changed_files: &HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<PlatformSpecificRelevantTestCaseData<GolangTestIdentifier, GolangCoverageIdentifier>>
    {
        let mut test_cases: HashMap<
            GolangTestIdentifier,
            Vec<TestReason<GolangCoverageIdentifier>>,
        > = HashMap::new();

        let mut external_dependencies_changed = None;
        if eval_target_changed_files.contains(Path::new("go.mod")) {
            external_dependencies_changed = Some(Self::go_mod_test_cases(
                eval_target_test_cases,
                scm,
                ancestor_commit,
                coverage_data,
                &mut test_cases,
            )?);
        }

        for file in eval_target_changed_files {
            if file
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"))
            {
                Self::guess_tests_from_test_file_changed(
                    file,
                    eval_target_test_cases,
                    &mut test_cases,
                )?;
            }
        }

        Ok(PlatformSpecificRelevantTestCaseData {
            additional_test_cases: test_cases,
            external_dependencies_changed,
        })
    }

    fn run_tests<'a, I>(
        test_cases: I,
        _jobs: u16,
    ) -> Result<CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>, RunTestsErrors>
    where
        I: IntoIterator<Item = &'a GolangConcreteTestIdentifier>,
        GolangConcreteTestIdentifier: 'a,
    {
        let tmp_dir = TempDir::new("testtrim")?;

        // FIXME: little confused why I need an Arc here since I want to just send an immutable reference to the
        // threads; that should be doable in some lighter way.
        let module_info = Arc::new(
            Self::parse_module_info().map_err(|e| RunTestsErrors::PlatformError(e.to_string()))?,
        );

        // Will need to collect get_baseline_ext for each module being tested... (At least, I think so?  Dependency
        // access and initialization seems like something that wouldn't be constant across the entire project?)
        let mut vec_test_cases = vec![];
        let mut package_baseline = HashMap::new();
        for test_case in test_cases {
            if !package_baseline.contains_key(&test_case.test_identifier.binary_name) {
                package_baseline.insert(
                    test_case.test_identifier.binary_name.clone(),
                    Self::get_baseline_ext(&test_case.binary_path, tmp_dir.path())
                        .map_err(|e| RunTestsErrors::PlatformError(e.to_string()))?,
                );
            }
            vec_test_cases.push(test_case);
        }
        let package_baseline = Arc::new(package_baseline); // FIXME: can this be done without an Arc since it will be immutable?

        let mut coverage_data = CommitCoverageData::new();

        let pool = Rc::new(ThreadPool::new(1));
        // FIXME: implement concurrency and test:
        /* if jobs == 0 {
            num_cpus::get()
        } else {
            jobs.into()
        })); */
        let (tx, rx) = channel();

        let mut outstanding_tests = 0;
        for test_case in vec_test_cases {
            let tc = test_case.clone();
            let tmp_path = PathBuf::from(tmp_dir.path());
            let tx = tx.clone();
            let pool = pool.clone();
            let module_info = module_info.clone();
            let package_baseline = package_baseline.clone();

            // Dance around a bit here to share the same tracing subscriber in the subthreads, allowing us to collect
            // performance data from them.  Note that, as we're running these tests in parallel, the performance data
            // starts to deviate from wall-clock time at this point.
            get_default(move |dispatcher| {
                let tc = tc.clone();
                let tmp_path = tmp_path.clone();
                let tx = tx.clone();
                let dispatcher = dispatcher.clone();
                let module_info = module_info.clone();
                let package_baseline = package_baseline.clone();
                pool.execute(move || {
                    dispatcher::with_default(&dispatcher, || {
                        tx.send(GolangTestPlatform::run_test(
                            &tc,
                            &tmp_path,
                            &module_info,
                            &package_baseline,
                        ))
                        .unwrap();
                    });
                });
            });

            outstanding_tests += 1;
        }

        pool.join();

        let mut failed_test_results = vec![];
        while outstanding_tests > 0 {
            match rx.recv()? {
                Ok(res) => coverage_data.merge_in(res),
                Err(RunTestError::TestExecutionFailure(failed_test_result)) => {
                    failed_test_results.push(failed_test_result);
                }
                Err(e) => return Err(e.into()),
            }
            outstanding_tests -= 1;
        }

        if failed_test_results.is_empty() {
            Ok(coverage_data)
        } else {
            Err(RunTestsErrors::TestExecutionFailures(failed_test_results))
        }
    }

    fn analyze_changed_files(
        _changed_files: &HashSet<PathBuf>,
        _coverage_data: &mut CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::platform::golang::GolangTestPlatform;

    use super::test_func_definition;

    #[test]
    fn test_parse_go_coverage_line() {
        let line = "encoding/base64/base64.go:34.44,37.40 3 1";
        let coverage_data = GolangTestPlatform::parse_go_coverage_line(line);

        assert_eq!(coverage_data.module_and_file, "encoding/base64/base64.go");
        assert_eq!(coverage_data.start_marker, "34.44");
        assert_eq!(coverage_data.end_marker, "37.40");
        // assert_eq!(coverage_data._num_statements, "3");
        assert_eq!(coverage_data.hit_count, "1");

        let line = "github.com/shopspring/decimal/rounding.go:112.14,114.4 1 317";
        let coverage_data = GolangTestPlatform::parse_go_coverage_line(line);

        assert_eq!(
            coverage_data.module_and_file,
            "github.com/shopspring/decimal/rounding.go"
        );
        assert_eq!(coverage_data.start_marker, "112.14");
        assert_eq!(coverage_data.end_marker, "114.4");
        // assert_eq!(coverage_data._num_statements, "1");
        assert_eq!(coverage_data.hit_count, "317");
    }

    #[test]
    fn test_test_func_definition() {
        let code = r#"
        func TestAdd(t *testing.T) {
	got := Add(2, 3)
	if got != 5 {
		t.Errorf("Add(2, 3) = %d; want 5", got)
	}
	got = Add(-1, 1)
	if got != 0 {
		t.Errorf("Add(-1, 1) = %d; want 0", got)
	}
}

func TestAddDecimal(t *testing.T) {
	got := AddDecimal(decimal.NewFromInt(2), decimal.NewFromInt(3))
	if !got.Equal(decimal.NewFromInt(5)) {
		t.Errorf("AddDecimal(2, 3) = %d; want 5", got)
	}
	got = AddDecimal(decimal.NewFromInt(-1), decimal.NewFromInt(1))
	if !got.Equal(decimal.NewFromInt(0)) {
		t.Errorf("AddDecimal(-1, 1) = %d; want 0", got)
	}
}
"#;
        let caps = test_func_definition.captures_iter(code).collect::<Vec<_>>();
        assert_eq!(caps.len(), 2, "expected two Test... functions to be found");
        assert_eq!(&caps[0]["test_name"], "TestAdd");
    }
}

/*

Test discovery:
$ go test ./... -list=.
TestAdd
TestSub
TestMul
TestDiv
TestFibonacci
TestFactorial
ok      codeberg.org/testtrim/go-coverage-specimen      0.001s
- collect each test name
- then associate them with the package name (codeberg.org/testtrim/go-coverage-specimen) as "ok..." is output

Test execution:
$ go test codeberg.org/testtrim/go-coverage-specimen -run TestAdd -json -cover -covermode set -coverprofile TestAdd.out
{"Time":"2024-12-09T10:49:58.483098468-07:00","Action":"start","Package":"codeberg.org/testtrim/go-coverage-specimen"}
{"Time":"2024-12-09T10:49:58.484227202-07:00","Action":"run","Package":"codeberg.org/testtrim/go-coverage-specimen","Test":"TestAdd"}
{"Time":"2024-12-09T10:49:58.484256971-07:00","Action":"output","Package":"codeberg.org/testtrim/go-coverage-specimen","Test":"TestAdd","Output":"=== RUN   TestAdd\n"}
{"Time":"2024-12-09T10:49:58.484271441-07:00","Action":"output","Package":"codeberg.org/testtrim/go-coverage-specimen","Test":"TestAdd","Output":"--- PASS: TestAdd (0.00s)\n"}
{"Time":"2024-12-09T10:49:58.484274341-07:00","Action":"pass","Package":"codeberg.org/testtrim/go-coverage-specimen","Test":"TestAdd","Elapsed":0}
{"Time":"2024-12-09T10:49:58.484279111-07:00","Action":"output","Package":"codeberg.org/testtrim/go-coverage-specimen","Output":"PASS\n"}
{"Time":"2024-12-09T10:49:58.484391871-07:00","Action":"output","Package":"codeberg.org/testtrim/go-coverage-specimen","Output":"ok  \tcodeberg.org/testtrim/go-coverage-specimen\t0.001s\n"}
{"Time":"2024-12-09T10:49:58.484747148-07:00","Action":"pass","Package":"codeberg.org/testtrim/go-coverage-specimen","Elapsed":0.002}

Produces TestAdd.out:
mode: set
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:3.28,5.2 1 1
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:7.28,9.2 1 0
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:11.28,13.2 1 0
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:15.28,17.2 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:3.31,4.11 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:5.9,6.11 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:7.9,8.11 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:9.10,10.57 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:14.31,15.11 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:16.9,17.11 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:18.9,19.11 1 0
codeberg.org/testtrim/go-coverage-specimen/sequences.go:20.10,21.38 1 0

The last number seems to be whether the bit is set for execution in that specific location of the file -- this could be good enough for file detection.  Although awkwardly we'll have to map from the packagename + filename to the relative filename.

Function coverage can be retrieved with an additional processing command:
$ go tool cover -func TestAdd.out
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:3:      Add             100.0%
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:7:      Sub             0.0%
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:11:     Mul             0.0%
codeberg.org/testtrim/go-coverage-specimen/basic_ops.go:15:     Div             0.0%
codeberg.org/testtrim/go-coverage-specimen/sequences.go:3:      Fibonacci       0.0%
codeberg.org/testtrim/go-coverage-specimen/sequences.go:14:     Factorial       0.0%
total:                                                          (statements)    8.3%

Mapping from the package-relative naming to the source-tree-relative naming probably seems to just involve stripping the prefix from go.mod, labeled as `module ...`

*/
