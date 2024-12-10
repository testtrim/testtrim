// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context as _, Result};
use log::{debug, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env::current_dir;
use std::fs::File;
use std::hash::Hash;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::{fmt, fs, io};
use tempdir::TempDir;
use threadpool::ThreadPool;
use tracing::dispatcher::{self, get_default};
use tracing::{info_span, instrument};

use crate::coverage::commit_coverage_data::{CommitCoverageData, CoverageIdentifier, FileCoverage};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::{
    FailedTestResult, RunTestError, RunTestsErrors, SubcommandErrors, TestFailure,
};
use crate::scm::{Scm, ScmCommit};
use crate::sys_trace::sys_trace_command;
use crate::sys_trace::trace::Trace;

use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestIdentifierCore, TestPlatform,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct GolangTestIdentifier {
    pub module_name: String,
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
        write!(f, "{} / {}", self.module_name, self.test_name)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum GolangCoverageIdentifier {}

impl CoverageIdentifier for GolangCoverageIdentifier {}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct GolangConcreteTestIdentifier {
    pub test_identifier: GolangTestIdentifier,
}

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
        Some(GolangConcreteTestIdentifier { test_identifier })
    }
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

    pub fn get_all_test_cases() -> Result<HashSet<GolangConcreteTestIdentifier>> {
        let mut result: HashSet<GolangConcreteTestIdentifier> = HashSet::new();

        /*
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
        */
        let output = Command::new("go")
            .args(["test", "./...", "-list=."])
            .output()
            .expect("Failed to execute `go test ./... -list=.` command");

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("go test ./... -list=."),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        let mut test_names: Vec<String> = Vec::new();

        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
        for line in stdout.lines() {
            trace!("output: {line:?}");
            if line.starts_with("ok ") {
                let split: Vec<&str> = line.split('\t').collect();
                match split.get(1) {
                    Some(module_name) => {
                        trace!("module_name: {module_name:?}");
                        for t in &test_names {
                            result.insert(GolangConcreteTestIdentifier {
                                test_identifier: GolangTestIdentifier {
                                    module_name: String::from(*module_name),
                                    test_name: String::from(t),
                                },
                            });
                        }
                        test_names.clear();
                    }
                    None => {
                        return Err(anyhow!(
                            "test discovery encountered output {line:?} that couldn't be parsed"
                        ));
                    }
                }
            } else {
                trace!("test name: {line:?}");
                test_names.push(String::from(line));
            }
        }

        if !test_names.is_empty() {
            return Err(anyhow!(
                "test discovery failed; left with test names and no module name: {test_names:?}"
            ));
        }

        Ok(result)
    }

    fn run_test(
        test_case: &GolangConcreteTestIdentifier,
        tmp_path: &Path,
    ) -> Result<CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>, RunTestError>
    {
        let mut coverage_data = CommitCoverageData::new();

        trace!("preparing for test case {:?}", test_case);

        coverage_data.add_executed_test(test_case.test_identifier.clone());

        let coverage_dir = tmp_path
            .join(Path::new("coverage-output").join(&test_case.test_identifier.module_name));
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
            // go test codeberg.org/testtrim/go-coverage-specimen -run TestAdd -json -cover -covermode set -coverprofile TestAdd.out
            let mut cmd = Command::new("go");

            cmd.args([
                    "test",
                    &test_case.test_identifier.module_name,
                    "-run",
                    &test_case.test_identifier.test_name,
                    "-json",
                    "-cover",
                    "-covermode",
                    "set",
                    "-coverprofile",
                    &profile_file.to_string_lossy(),
                ])
                // cmd.arg("--exact")
                // .arg(&test_case.test_identifier.test_name)
                // .env("LLVM_PROFILE_FILE", &profile_file)
                // .env("RUSTFLAGS", "-C instrument-coverage")
                // .current_dir(test_wd);
                ;
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

        trace!("Successfully ran test {:?}!", test_case.test_identifier);

        Self::parse_profiling_data(test_case, &profile_file, &mut coverage_data)?;
        Self::parse_trace_data(test_case, &trace, &mut coverage_data)?;

        Ok(coverage_data)
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_profiling_data(
        test_case: &GolangConcreteTestIdentifier,
        profile_file: &PathBuf,
        coverage_data: &mut CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<()> {
        let reader =
            BufReader::new(File::open(profile_file).context("Failed to open profile file")?);

        // https://github.com/golang/go/blob/c5d7f2f1cbaca8938a31a022058b1a3300817e33/src/cmd/cover/profile.go#L53-L56
        // First line is "mode: foo", where foo is "set", "count", or "atomic".
        // Rest of file is in the format
        //	encoding/base64/base64.go:34.44,37.40 3 1
        // where the fields are: name.go:line.column,line.column numberOfStatements count
        for line in reader.lines() {
            let line = line?;
            if line.starts_with("mode: ") {
                continue;
            }

            debug!("profile data line: {line}");
            let (module_file, line) = line
                .split_once(':')
                .ok_or_else(|| anyhow!("failed to split profilling line by ':' {line:?}"))?;
            debug!("profile data line: {module_file}     remainder: {line}");
            let (_line, count) = line
                .rsplit_once(' ')
                .ok_or_else(|| anyhow!("failed to split profilling line by ' ' {line:?}"))?;

            debug!("profile data line: {module_file}     count: {count}");

            // module_file = codeberg.org/testtrim/go-coverage-specimen/basic_ops.go
            // count = (0, 1)
            if count == "0" {
                continue;
            }

            // FIXME: temporary hack -- we should really read go.mod and get the module name to strip from the module_file
            let relative_file = module_file
                .strip_prefix("codeberg.org/testtrim/go-coverage-specimen/")
                .ok_or_else(|| anyhow!("unable to strip_prefix from {module_file}"))?;

            coverage_data.add_file_to_test(FileCoverage {
                test_identifier: test_case.test_identifier.clone(),
                file_name: PathBuf::from(relative_file),
            });
        }

        Ok(())
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_trace_data(
        _test_case: &GolangConcreteTestIdentifier,
        _trace: &Trace,
        _coverage_data: &mut CommitCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<()> {
        // let repo_root = env::current_dir()?;

        // for path in trace.get_open_paths() {
        //     if path.is_relative() || path.starts_with(&repo_root) {
        //         debug!(
        //             "found test {} accessed local file {path:?}",
        //             test_case.test_identifier
        //         );

        //         let target_path = Self::normalize_path(
        //             path,
        //             &current_dir.join("fake"), // normalize_path expects relative_to to be a file, not dir; so we add a fake child path
        //             &repo_root,
        //             |warning| {
        //                 warn!("syscall trace accessed path {path:?} but couldn't normalize to repo root: {warning}");
        //             },
        //         );
        //         if let Some(target_path) = target_path {
        //             // It might make sense to filter out files that aren't part of the repo... both here and in
        //             // parse_profiling_data?
        //             coverage_data.add_file_to_test(FileCoverage {
        //                 file_name: target_path.clone(),
        //                 test_identifier: test_case.test_identifier.clone(),
        //             });
        //         }
        //     }
        //     // FIXME: absolute path case -- check if it's part of the repo/cwd, and if so include it
        // }

        // for sockaddr in trace.get_connect_sockets() {
        //     coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
        //         test_identifier: test_case.test_identifier.clone(),
        //         coverage_identifier: RustCoverageIdentifier::NetworkDependency(sockaddr.clone()),
        //     });
        // }

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
        let all_test_cases = GolangTestPlatform::get_all_test_cases()?;
        trace!("all_test_cases: {:?}", all_test_cases);

        Ok(GolangTestDiscovery { all_test_cases })
    }

    #[instrument(skip_all, fields(perftrace = "platform-specific-test-cases"))]
    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        _eval_target_test_cases: &HashSet<GolangTestIdentifier>,
        _eval_target_changed_files: &HashSet<PathBuf>,
        _scm: &MyScm,
        _ancestor_commit: &Commit,
        _coverage_data: &FullCoverageData<GolangTestIdentifier, GolangCoverageIdentifier>,
    ) -> Result<PlatformSpecificRelevantTestCaseData<GolangTestIdentifier, GolangCoverageIdentifier>>
    {
        Ok(PlatformSpecificRelevantTestCaseData {
            additional_test_cases: HashMap::new(),
            external_dependencies_changed: None,
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
        for test_case in test_cases {
            let tc = test_case.clone();
            let tmp_path = PathBuf::from(tmp_dir.path());
            let tx = tx.clone();
            let pool = pool.clone();

            // Dance around a bit here to share the same tracing subscriber in the subthreads, allowing us to collect
            // performance data from them.  Note that, as we're running these tests in parallel, the performance data
            // starts to deviate from wall-clock time at this point.
            get_default(move |dispatcher| {
                let tc = tc.clone();
                let tmp_path = tmp_path.clone();
                let tx = tx.clone();
                let dispatcher = dispatcher.clone();
                pool.execute(move || {
                    dispatcher::with_default(&dispatcher, || {
                        tx.send(GolangTestPlatform::run_test(&tc, &tmp_path))
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
mod tests {}

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
