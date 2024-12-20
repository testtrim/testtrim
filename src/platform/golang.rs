// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context as _, Result};
use gomod_rs::{parse_gomod, Directive};
use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::env::{self, current_dir};
use std::fs::{read_to_string, File};
use std::hash::Hash;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command as SyncCommand;
use std::sync::Arc;
use std::{fmt, fs, io};
use tempdir::TempDir;
use tokio::process::Command;
use tracing::{info_span, instrument, Instrument as _};

use crate::coverage::commit_coverage_data::{
    CommitCoverageData, CoverageIdentifier, FileCoverage, FileReference, HeuristicCoverage,
};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::{
    FailedTestResult, RunTestError, RunTestsErrors, SubcommandErrors, TestFailure,
};
use crate::platform::util::normalize_path;
use crate::scm::{Scm, ScmCommit};
use crate::sys_trace::trace::{Trace, UnifiedSocketAddr};
use crate::sys_trace::{sys_trace_command, SysTraceCommand as _};

use super::util::spawn_limited_concurrency;
use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestIdentifierCore, TestPlatform, TestReason,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct GolangTestIdentifier {
    pub module_path: ModulePath,
    pub test_name: String,
}

impl TestIdentifier for GolangTestIdentifier {}
impl TestIdentifierCore for GolangTestIdentifier {
    fn lightly_unique_name(&self) -> String {
        self.test_name.clone()
    }
}

impl fmt::Display for GolangTestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {}", self.module_path.0, self.test_name)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum GolangCoverageIdentifier {
    // Possible future: go version, platform, etc. -- might be better as tags since they'd be pretty universal for the whole commit though?
    PackageDependency(ModuleDependency),
    InferredFromTestFileChange(PathBuf),
    NetworkDependency(UnifiedSocketAddr),
}

impl CoverageIdentifier for GolangCoverageIdentifier {}

#[derive(Debug, Clone)]
pub struct GolangConcreteTestIdentifier {
    test_identifier: GolangTestIdentifier,
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
    static ref test_func_definition_regex: Regex = Regex::new(
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
    // Really hacky regex; probably should use a parser.  Supports up to five includes on one line.
    static ref embed_regex: Regex = Regex::new(
        r#"(?xm)
        ^
        [\t\v\f\x20]* # optional whitespace, not newlines
        //go:embed
        (?:
            # double-quote w/ path
            [\t\v\f\x20]+
            "
            (?<qpath1>(?:[^"\\]|\\.)*)
            "
            |
            # backtick-quote with path
            [\t\v\f\x20]+
            `
            (?<bpath1>(?:[^`\\]|\\.)*)
            `
            |
            # Unquoted path
            [\t\v\f\x20]+
            (?<path1>[^\n\r\s]+)
        )
        (?:
            # double-quote w/ path
            [\t\v\f\x20]+
            "
            (?<qpath2>(?:[^"\\]|\\.)*)
            "
            |
            # backtick-quote with path
            [\t\v\f\x20]+
            `
            (?<bpath2>(?:[^`\\]|\\.)*)
            `
            |
            # Unquoted path
            [\t\v\f\x20]+
            (?<path2>[^\n\r\s]+)
        )?
        (?:
            # double-quote w/ path
            [\t\v\f\x20]+
            "
            (?<qpath3>(?:[^"\\]|\\.)*)
            "
            |
            # backtick-quote with path
            [\t\v\f\x20]+
            `
            (?<bpath3>(?:[^`\\]|\\.)*)
            `
            |
            # Unquoted path
            [\t\v\f\x20]+
            (?<path3>[^\n\r\s]+)
        )?
        (?:
            # double-quote w/ path
            [\t\v\f\x20]+
            "
            (?<qpath4>(?:[^"\\]|\\.)*)
            "
            |
            # backtick-quote with path
            [\t\v\f\x20]+
            `
            (?<bpath4>(?:[^`\\]|\\.)*)
            `
            |
            # Unquoted path
            [\t\v\f\x20]+
            (?<path4>[^\n\r\s]+)
        )?
        (?:
            # double-quote w/ path
            [\t\v\f\x20]+
            "
            (?<qpath5>(?:[^"\\]|\\.)*)
            "
            |
            # backtick-quote with path
            [\t\v\f\x20]+
            `
            (?<bpath5>(?:[^`\\]|\\.)*)
            `
            |
            # Unquoted path
            [\t\v\f\x20]+
            (?<path5>[^\n\r\s]+)
        )?
        [\t\v\f\x20]* # optional whitespace, not newlines
        $
        "#
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

    fn get_build_test_command(
        module_info: &ModuleInfo,
        tmp_dir: &TempDir,
        module: &ModulePath,
    ) -> SyncCommand {
        // form the coverpkg arg out of all the dependencies
        let mut coverpkg = String::with_capacity(1024);
        for dep in &module_info.dependencies {
            coverpkg.push_str(&dep.module_path.0);
            coverpkg.push(',');
        }
        coverpkg.push_str("./..."); // include this package and all local subpackages

        let mut cmd = SyncCommand::new("go");
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
            &module.0,
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
    async fn get_baseline_ext(
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
        let output = cmd
            .output()
            .await
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: format!("{test_binary_path:?} ...run-noop-test...").to_string(),
                error: e,
            })?;
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

    async fn run_test(
        test_case: &GolangConcreteTestIdentifier,
        tmp_path: &Path,
        module_info: &ModuleInfo,
        package_baseline: &HashMap<ModulePath, HashMap<GoCoverageStatementIdentity, i32>>,
    ) -> Result<CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>, RunTestError>
    {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_executed_test(test_case.test_identifier.clone());

        let coverage_dir = tmp_path
            .join(Path::new("coverage-output").join(&test_case.test_identifier.module_path.0));
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
        let (output, trace) = async {
            let cmd = Self::get_run_test_command(
                &test_case.binary_path,
                // make sure we're matching the one and only test:
                &format!("^{}$", regex::escape(&test_case.test_identifier.test_name)),
                &profile_file,
            );
            sys_trace_command.trace_command(cmd, &strace_file).await
        }
        .instrument(info_span!(
            "execute-test",
            perftrace = "run-test",
            parallel = true
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

        let Some(package_baseline) = package_baseline.get(&test_case.test_identifier.module_path)
        else {
            return Err(RunTestError::Other(anyhow!(
                "could not find coverage baseline for module {:?}",
                test_case.test_identifier.module_path.0
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

                let target_path = normalize_path(
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

        for sockaddr in trace.get_connect_sockets() {
            coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
                test_identifier: test_case.test_identifier.clone(),
                coverage_identifier: GolangCoverageIdentifier::NetworkDependency(sockaddr.clone()),
            });
        }

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
        source_reason: &TestReason<GolangCoverageIdentifier>,
    ) -> Result<()> {
        if !fs::exists(file)? {
            // A file was considered "changed" but doesn't exist -- indicating a deleted file.
            return Ok(());
        }

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
        let test_file = fs::read_to_string(file).context("reading changed test file {file:?}")?;

        for cap in test_func_definition_regex.captures_iter(&test_file) {
            let test_name = String::from(&cap["test_name"]);
            let mut any_match = false;
            for tc in all_test_cases {
                if tc.test_name == test_name {
                    any_match = true;
                    debug!("guessed that modification to {file:?} would require running {tc}");
                    test_cases
                        .entry(tc.clone())
                        .or_default()
                        .push(TestReason::SideEffect(
                            // Because this happened... probably a FileChanged...
                            Box::new(source_reason.clone()),
                            // We did this inference and found this test case should be run.
                            Box::new(TestReason::CoverageIdentifier(
                                GolangCoverageIdentifier::InferredFromTestFileChange(
                                    PathBuf::from(file),
                                ),
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

    fn maybe_guess_tests_from_changed_file(
        changed_file: &PathBuf,
        coverage_data: &FullCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
        eval_target_test_cases: &HashSet<GolangTestIdentifier>,
        test_cases: &mut HashMap<GolangTestIdentifier, Vec<TestReason<GolangCoverageIdentifier>>>,
        prevent_recursive: &mut HashSet<PathBuf>,
        override_reason: Option<&TestReason<GolangCoverageIdentifier>>,
    ) -> Result<()> {
        if !prevent_recursive.insert(changed_file.clone()) {
            return Ok(());
        }

        // Preserve the first file changed as the "reason" for any test cases being included:
        let default_reason = TestReason::FileChanged(changed_file.clone());
        let reason = override_reason.unwrap_or(&default_reason);

        if changed_file
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"))
        {
            Self::guess_tests_from_test_file_changed(
                changed_file,
                eval_target_test_cases,
                test_cases,
                reason,
            )?;
        }

        // In the event that a _test.go file has a //go:embed in it, the normal process of following referenced files
        // (in `compute_changed_file_test_cases`) won't work because we don't have a record of coverage in _test.go
        // files, so we won't know what tests to rerun.  So we have to duplicate that behavior here with these inferred
        // test cases.
        if let Some(referencing_files) = coverage_data
            .file_referenced_by_files_map()
            .get(changed_file)
            && !referencing_files.is_empty()
        {
            for referencing_file in referencing_files {
                Self::maybe_guess_tests_from_changed_file(
                    referencing_file,
                    coverage_data,
                    eval_target_test_cases,
                    test_cases,
                    prevent_recursive,
                    Some(&TestReason::SideEffect(
                        // Because this occurred (probably a FileChanged)
                        Box::new(reason.clone()),
                        // We treated it like this file changed:
                        Box::new(TestReason::FileChanged(referencing_file.clone())),
                    )),
                )?;
            }
        }

        Ok(())
    }

    #[allow(clippy::manual_map)] // much cleaner as-is than the proposed alternative
    fn embed_extract(i: i32, cap: &Captures<'_>) -> Option<PathBuf> {
        if let Some(raw) = cap.name(&format!("path{i}")) {
            Some(PathBuf::from(raw.as_str()))
        } else if let Some(dquote) = cap.name(&format!("qpath{i}")) {
            Some(PathBuf::from(dquote.as_str().replace("\\\"", "\"")))
        } else if let Some(bquote) = cap.name(&format!("bpath{i}")) {
            Some(PathBuf::from(bquote.as_str()))
        } else {
            None
        }
    }

    fn find_embed_includes(src_file: &PathBuf) -> Result<HashSet<PathBuf>> {
        let mut result = HashSet::new();

        let Some(parent) = src_file.parent() else {
            warn!("couldn't resolve path {src_file:?} to its parent directory");
            return Ok(result);
        };

        let file = File::open(src_file).context(format!(
            "error in find_embed_includes opening file {src_file:?}"
        ))?;
        let content =
            io::read_to_string(BufReader::new(file)).context("find_embed_includes file read")?;

        for cap in embed_regex.captures_iter(&content) {
            for i in 1..=5 {
                if let Some(path) = Self::embed_extract(i, &cap) {
                    if path.starts_with("/") || path.starts_with(".") {
                        // Avoid anything suspicious occurring with path.join; these types of paths aren't supported in
                        // //go:embed anyway.
                        continue;
                    }
                    let glob_pattern = parent.join(path);

                    for entry in glob::glob(&glob_pattern.to_string_lossy())? {
                        let entry = entry?;
                        if entry.is_dir() {
                            for dirent in fs::read_dir(entry)? {
                                let dirent = dirent?;
                                let entry = dirent.path();
                                let entry = entry.strip_prefix(parent)?;
                                result.insert(PathBuf::from(entry));
                            }
                        } else {
                            let entry = entry.strip_prefix(parent)?;
                            result.insert(PathBuf::from(entry));
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    fn discover_tests_in_module(
        module_info: &ModuleInfo,
        module_path: &ModulePath,
    ) -> Result<HashSet<GolangConcreteTestIdentifier>> {
        // FIXME: one potential problem is that we're creating a temp directory, building go programs to it, and then
        // executing them.  The temp directory space is often configured as a space that can't have executables in it
        // (noexec) which could make this fail.
        //
        // FIXME: this uses an Arc to keep the TempDir from being dropped; it could probably be done instead by making
        // the GolangTestDiscovery outlive the ConcreteTestIdentifier and then hoisting the TempDir into the test
        // discovery object.  That's academically interesting since it's a lifetime problem that would help me learn
        // more about lifetime declarations, but, an Arc is just fine too.
        //
        // FIXME: as a final problem, we're creating one of these temp dirs for every module.  I guess that's OK?  But
        // it seems like maybe we could just create one and use subdirectories.
        let tmp_dir = Arc::new(TempDir::new("testtrim")?);

        // First we build all test binaries:
        let mut cmd = Self::get_build_test_command(module_info, &tmp_dir, module_path);
        debug!("running: {cmd:?}");
        let output = cmd.output().map_err(|e| SubcommandErrors::UnableToStart {
            command: "go test ...build...".to_string(),
            error: e,
        })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("go test -c"),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }
        trace!("test build success");

        // FIXME: since the change to just build one module at a time, we probably don't need to iterate here -- could
        // just use one binary.
        //
        // Now we need to iterate through each of the binaries in tmp_dir and run `... -test.list .` to get the tests
        // that they contain:
        let mut all_test_cases: HashSet<GolangConcreteTestIdentifier> = HashSet::new();
        for dirent in fs::read_dir(tmp_dir.path())? {
            let dirent = dirent?;
            let mut cmd = SyncCommand::new(dirent.path());
            cmd.args(["-test.list", "."]);
            debug!("running: {cmd:?}");
            let output = cmd.output().map_err(|e| SubcommandErrors::UnableToStart {
                command: format!("{:?} -test.list", cmd.get_program()).to_string(),
                error: e,
            })?;
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
                        // binary_name: BinaryName(
                        //     dirent
                        //         .file_name()
                        //         .into_string()
                        //         .expect("must have unicode file names"),
                        // ),
                        module_path: module_path.clone(),
                        test_name: String::from(line),
                    },
                    // Hack: make tmp_dir live as long as the test identifiers
                    _binary_dir: tmp_dir.clone(),
                    binary_path: dirent.path(),
                });
            }
        }

        Ok(all_test_cases)
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

        // Discover the modules to work with; this limits it to those with tests:
        let mut cmd = SyncCommand::new("go");
        cmd.args([
            "list",
            "-f",
            "{{if .TestGoFiles}}{{.ImportPath}}{{end}}",
            "./...",
        ]);
        debug!("running: {cmd:?}");
        let output = cmd.output().map_err(|e| SubcommandErrors::UnableToStart {
            command: "go list ...discover modules...".to_string(),
            error: e,
        })?;
        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("go list -f {{if .TestGoFiles}}{{.ImportPath}}{{end}} ./..."),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }
        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
        let mut all_test_cases: HashSet<GolangConcreteTestIdentifier> = HashSet::new();
        // FIXME: we might be able to do this in parallel to reduce build times... or maybe there's some way we can make
        // the go cmdline build multiple packages like this?
        for line in stdout.lines() {
            let module_path = ModulePath(String::from(line));
            all_test_cases.extend(Self::discover_tests_in_module(&module_info, &module_path)?);
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

        let mut prevent_recursive: HashSet<PathBuf> = HashSet::new();
        for file in eval_target_changed_files {
            Self::maybe_guess_tests_from_changed_file(
                file,
                coverage_data,
                eval_target_test_cases,
                &mut test_cases,
                &mut prevent_recursive,
                None,
            )?;
        }

        for ci in coverage_data.coverage_identifier_to_test_map() {
            if let (GolangCoverageIdentifier::NetworkDependency(_sockaddr), tests) = ci {
                for test in tests {
                    if eval_target_test_cases.contains(test) {
                        test_cases
                            .entry(test.clone())
                            .or_default()
                            .push(TestReason::CoverageIdentifier(ci.0.clone()));
                    }
                }
            }
        }

        Ok(PlatformSpecificRelevantTestCaseData {
            additional_test_cases: test_cases,
            external_dependencies_changed,
        })
    }

    async fn run_tests<'a, I>(
        test_cases: I,
        jobs: u16,
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
            if !package_baseline.contains_key(&test_case.test_identifier.module_path) {
                package_baseline.insert(
                    test_case.test_identifier.module_path.clone(),
                    Self::get_baseline_ext(&test_case.binary_path, tmp_dir.path())
                        .await
                        .map_err(|e| RunTestsErrors::PlatformError(e.to_string()))?,
                );
            }
            vec_test_cases.push(test_case);
        }
        let package_baseline = Arc::new(package_baseline); // FIXME: can this be done without an Arc since it will be immutable?

        let mut futures = vec![];
        for test_case in vec_test_cases {
            let tc = test_case.clone();
            let tmp_path = PathBuf::from(tmp_dir.path());
            let module_info = module_info.clone();
            let package_baseline = package_baseline.clone();
            futures.push(async move {
                GolangTestPlatform::run_test(&tc, &tmp_path, &module_info, &package_baseline).await
            });
        }

        let concurrency = if jobs == 0 {
            num_cpus::get()
        } else {
            jobs.into()
        };
        let results = spawn_limited_concurrency(concurrency, futures).await?;

        let mut failed_test_results = vec![];
        let mut coverage_data = CommitCoverageData::new();
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
        changed_files: &HashSet<PathBuf>,
        coverage_data: &mut CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<()> {
        let repo_root = env::current_dir()?;

        for file in changed_files {
            if file.extension().is_some_and(|ext| ext == "go") {
                let mut found_references = false;

                if !fs::exists(file)? {
                    // A file was considered "changed" but doesn't exist -- indicating a deleted file.
                    coverage_data.mark_file_makes_no_references(file.clone());
                    continue;
                }

                for target_path in Self::find_embed_includes(file)? {
                    debug!("found that {file:?} references {target_path:?}");
                    // FIXME: It's not clear whether warnings are the right behavior for any of these problems.  Some of
                    // them might be better elevated to errors?
                    let target_path = normalize_path(&target_path, file, &repo_root, |warning| {
                        warn!("file {file:?} had a //go:embed, but reference could not be followed: {warning}");
                    });

                    if let Some(target_path) = target_path {
                        coverage_data.add_file_reference(FileReference {
                            referencing_file: file.clone(),
                            target_file: target_path,
                        });
                        found_references = true;
                    }
                }

                if !found_references {
                    coverage_data.mark_file_makes_no_references(file.clone());
                }
            } else {
                // This probably isn't necessary since it would've never been marked as making references
                coverage_data.mark_file_makes_no_references(file.clone());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::platform::golang::GolangTestPlatform;

    use super::test_func_definition_regex;

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
        let caps = test_func_definition_regex
            .captures_iter(code)
            .collect::<Vec<_>>();
        assert_eq!(caps.len(), 2, "expected two Test... functions to be found");
        assert_eq!(&caps[0]["test_name"], "TestAdd");
    }

    #[test]
    fn find_compile_time_includes() {
        let res = GolangTestPlatform::find_embed_includes(&PathBuf::from(
            "tests/go_parse_examples/embed.go",
        ));
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.len(), 8, "correct # of files read; res={res:?}");
        assert!(res.contains(&PathBuf::from("file1.txt")));
        assert!(res.contains(&PathBuf::from("file2.txt"))); // multiple includes on one line
        assert!(res.contains(&PathBuf::from("file3.txt")));
        assert!(res.contains(&PathBuf::from("dir1/file4.txt"))); // directory include
        assert!(res.contains(&PathBuf::from("dir1/file5.txt")));
        assert!(res.contains(&PathBuf::from("dir2/file6.txt"))); // glob include
        assert!(res.contains(&PathBuf::from("dir \"3\"/file8.txt"))); // double-quoting fixed up
        assert!(res.contains(&PathBuf::from("dir \"4\"/file9.txt")));
    }
}
