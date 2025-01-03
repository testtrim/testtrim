// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result, anyhow};
use cargo_lock::Lockfile;
use cargo_toml::Manifest;
use dashmap::DashSet;
use lazy_static::lazy_static;
use log::{debug, info, trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::path::{Component, PathBuf};
use std::process::Command as SyncCommand;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::{env, fmt, fs, io};
use std::{hash::Hash, path::Path};
use tempdir::TempDir;
use tokio::process::Command;
use tracing::{Instrument, info_span, instrument};

use crate::coverage::Tag;
use crate::coverage::commit_coverage_data::{
    CommitCoverageData, CoverageIdentifier, FileCoverage, FileReference, FunctionCoverage,
    HeuristicCoverage,
};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::{
    FailedTestResult, RunTestError, RunTestsErrors, SubcommandErrors, TestFailure,
};
use crate::network::NetworkDependency;
use crate::scm::{Scm, ScmCommit};
use crate::sys_trace::SysTraceCommand as _;
use crate::sys_trace::trace::ResolvedSocketAddr;
use crate::sys_trace::{sys_trace_command, trace::Trace};

use super::TestReason;
use super::util::{normalize_path, spawn_limited_concurrency};
use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestIdentifierCore, TestPlatform,
    rust_llvm::{CoverageLibrary, ProfilingData},
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustTestIdentifier {
    /// Project-relative source path that defines the binary which contains the test.  For example,
    /// `some_module/src/lib.rs`
    pub test_src_path: PathBuf,
    /// Name of the test.  For example, `basic_ops::tests::test_add`
    pub test_name: String,
}

impl TestIdentifier for RustTestIdentifier {}
impl TestIdentifierCore for RustTestIdentifier {
    fn lightly_unique_name(&self) -> String {
        self.test_name.clone()
    }
}

impl fmt::Display for RustTestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} / {}", self.test_src_path, self.test_name)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum RustCoverageIdentifier {
    // Possible future: rustc version, platform, etc. -- might be better as tags since they'd be pretty universal for the whole commit though?
    PackageDependency(RustPackageDependency),
    NetworkDependency(ResolvedSocketAddr),
}

impl CoverageIdentifier for RustCoverageIdentifier {}

impl TryFrom<RustCoverageIdentifier> for NetworkDependency {
    type Error = &'static str;

    #[allow(clippy::match_wildcard_for_single_variants)] // really unlikely that new variations will match
    fn try_from(value: RustCoverageIdentifier) -> std::result::Result<Self, Self::Error> {
        match value {
            RustCoverageIdentifier::NetworkDependency(socket) => Ok(Self { socket }),
            _ => Err("not supported"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustPackageDependency {
    pub package_name: String,
    pub version: String,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustTestBinary {
    pub rel_src_path: PathBuf,
    pub executable_path: PathBuf,
    pub manifest_path: PathBuf,
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct RustConcreteTestIdentifier {
    pub test_binary: RustTestBinary,
    pub test_identifier: RustTestIdentifier,
}

impl ConcreteTestIdentifier<RustTestIdentifier> for RustConcreteTestIdentifier {
    fn test_identifier(&self) -> &RustTestIdentifier {
        &self.test_identifier
    }
}

pub struct RustTestDiscovery {
    test_binaries: HashSet<RustTestBinary>,
    all_test_cases: HashSet<RustConcreteTestIdentifier>,
}

impl TestDiscovery<RustConcreteTestIdentifier, RustTestIdentifier> for RustTestDiscovery {
    fn all_test_cases(&self) -> &HashSet<RustConcreteTestIdentifier> {
        &self.all_test_cases
    }

    fn map_ti_to_cti(
        &self,
        test_identifier: RustTestIdentifier,
    ) -> Option<RustConcreteTestIdentifier> {
        for test_binary in &self.test_binaries {
            if test_binary.rel_src_path == test_identifier.test_src_path {
                let new_test_case = RustConcreteTestIdentifier {
                    test_identifier: test_identifier.clone(),
                    test_binary: test_binary.clone(),
                };
                return Some(new_test_case);
            }
        }
        warn!("Unable to find test binary for test: {test_identifier:?}");
        None
    }
}

lazy_static! {
    static ref include_regex: Regex = Regex::new(
        r#"(?xs)
        [\s=]
        (include|include_str|include_bytes)!
        \(
            (?:[\s\n]*) # optional whitespace or linebreak
            "
            (?<path>(?:[^"\\]|\\.)*)
            "
            (?:[\s\n]*) # optional whitespace or linebreak
        *\)
        "#
    )
    .unwrap();
}

pub struct RustTestPlatform;

impl RustTestPlatform {
    #[must_use]
    pub fn autodetect() -> bool {
        if fs::exists("Cargo.toml")
            .expect("autodetect test project type failed when checking Cargo.toml existence")
        {
            trace!("Detected Cargo.toml; auto-detect result: Rust test project");
            true
        } else {
            false
        }
    }

    fn rust_cargo_deps_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<RustTestIdentifier>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
        test_cases: &mut HashMap<RustTestIdentifier, HashSet<TestReason<RustCoverageIdentifier>>>,
    ) -> Result<usize> {
        // I think there might be plausible cases where Cargo.lock loading from the previous commit would fail, but we
        // wouldn't want to error out... for example, if Cargo.lock was added since the ancestor commit?.  But I'm not
        // confident what those cases would be where we would actually have ancestor coverage data yet be discovering
        // Cargo.lock wasn't present?  And what behavior we'd want.  So for now we'll treat that as an error and wait
        // for the situation to appear.
        let ancestor_lock = scm.fetch_file_content(ancestor_commit, Path::new("Cargo.lock"))?;
        let ancestor_lock = String::from_utf8(ancestor_lock)?;
        let ancestor_lock = Lockfile::from_str(&ancestor_lock)?;

        // FIXME: This doesn't handle the fact that Cargo.lock could have multiple versions of the same dependency...
        // not sure what to do in that case...
        let current_lock = Lockfile::load("Cargo.lock")?;
        let mut current_lock_map = HashMap::new();
        for p in current_lock.packages {
            current_lock_map.insert(String::from(p.name), p.version);
        }

        // Cases to consider:
        // - Packages with same version in both: Ignore.
        // - Packages that have changed from one version to another: search for coverage data based upon old version,
        //   add tests.
        // - Packages that have were present in ancestor_lock and aren't in current_lock: I think also search and add
        //   those tests?
        // - New packages in current_lock that aren't in ancestor_lock aren't relevant -- they wouldn't be part of the
        //   ancestor's coverage data.

        let mut changed_external_dependencies = 0;
        for old in ancestor_lock.packages {
            let relevant_change =
                if let Some(current_version) = current_lock_map.get(old.name.as_str()) {
                    if *current_version == old.version {
                        false
                    } else {
                        trace!(
                            "Cargo.lock package changed {}, old: {}, current: {}",
                            old.name, old.version, current_version
                        );
                        true
                    }
                } else {
                    trace!("Cargo.lock package removed {}", old.name);
                    true
                };

            if relevant_change {
                info!(
                    "Change to dependency {}; will run all tests that touched it",
                    old.name
                );
                changed_external_dependencies += 1;
                let coverage_identifier =
                    RustCoverageIdentifier::PackageDependency(RustPackageDependency {
                        package_name: String::from(old.name.as_str()),
                        version: old.version.to_string(),
                    });

                if let Some(tests) = coverage_data
                    .coverage_identifier_to_test_map()
                    .get(&coverage_identifier)
                {
                    for test in tests {
                        if eval_target_test_cases.contains(test) {
                            debug!("test {test:?} needs rerun");
                            test_cases.entry(test.clone()).or_default().insert(
                                TestReason::CoverageIdentifier(coverage_identifier.clone()),
                            );
                        }
                    }
                }
            }
        }

        Ok(changed_external_dependencies)
    }

    fn find_test_binaries() -> Result<HashSet<RustTestBinary>> {
        let tmp_dir = TempDir::new("testtrim")?;
        let repo_root = env::current_dir()?;

        let output = SyncCommand::new("cargo")
            .args([
                "test",
                "--workspace",
                "--tests",
                "--no-run",
                "--message-format=json",
            ])
            // RUSTFLAGS is needed because we'll load these binaries for their profiling data later; and
            // LLVM_PROFILE_FILE is set to avoid polluting the working-dir with default_*.profraw files during build
            // process.
            .env(
                "LLVM_PROFILE_FILE",
                tmp_dir.path().join("default_%m_%p.profraw"),
            )
            .env("RUSTFLAGS", "-C instrument-coverage")
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "cargo test --no-run".to_string(),
                error: e,
            })?;

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

        let mut test_binaries: HashSet<RustTestBinary> = HashSet::new();
        for line in stdout.lines() {
            let json_value: Result<Value, _> = serde_json::from_str(line);
            match json_value {
                Ok(json_value) => {
                    // FIXME: Cleanup unwraps and any other non-error-checking items here... maybe best to use a struct
                    // rather than a serde_json Value
                    if json_value["reason"] == "compiler-artifact"
                        && json_value["profile"]["test"] == true
                        && !json_value["executable"].is_null()
                    {
                        // src_path will be the source file for the binary that contains this test, but will be an
                        // absolute path, eg. "/home/user/Dev/rust-coverage-specimen/src/lib.rs".  We want to translate
                        // that into a relative path from the root of the repo, eg. "src/lib.rs", which will be stable
                        // from coverage run to run.
                        let abs_src_path = json_value["target"]["src_path"].as_str().unwrap();
                        let rel_src_path = Path::new(abs_src_path).strip_prefix(&repo_root)?;

                        test_binaries.insert(RustTestBinary {
                            rel_src_path: rel_src_path.to_path_buf(),
                            executable_path: PathBuf::from(
                                json_value["executable"].as_str().unwrap(),
                            ),
                            manifest_path: PathBuf::from(
                                json_value["manifest_path"].as_str().unwrap(),
                            ),
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

    fn get_all_test_cases(
        test_binaries: &HashSet<RustTestBinary>,
    ) -> Result<HashSet<RustConcreteTestIdentifier>> {
        let tmp_dir = TempDir::new("testtrim")?;
        let mut result: HashSet<RustConcreteTestIdentifier> = HashSet::new();

        for binary in test_binaries {
            let output = SyncCommand::new(&binary.executable_path)
                .arg("--list")
                .env(
                    "LLVM_PROFILE_FILE",
                    Path::join(tmp_dir.path(), "get_all_test_cases_%m_%p.profraw"),
                )
                .output()
                .map_err(|e| SubcommandErrors::UnableToStart {
                    command: format!("{binary:?} --list").to_string(),
                    error: e,
                })?;

            if !output.status.success() {
                return Err(SubcommandErrors::SubcommandFailed {
                    command: format!("{binary:?} --list").to_string(),
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
                result.insert(RustConcreteTestIdentifier {
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

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_profiling_data(
        test_case: &RustConcreteTestIdentifier,
        profile_file: &PathBuf,
        coverage_library: &CoverageLibrary,
        coverage_data: &mut CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
    ) -> Result<()> {
        let reader = fs::File::open(profile_file).context("Failed to open profile file")?;
        let profiling_data =
            ProfilingData::new_from_profraw_reader(reader, &test_case.test_binary.executable_path)
                .context("new_from_profraw_reader")?;

        for point in profiling_data.get_hit_instrumentation_points() {
            if let Ok(Some(metadata)) = coverage_library.search_metadata(&point) {
                let file = metadata.file_path;
                if file.is_relative() {
                    coverage_data.add_file_to_test(FileCoverage {
                        file_name: file,
                        test_identifier: test_case.test_identifier.clone(),
                    });
                    coverage_data.add_function_to_test(FunctionCoverage {
                        function_name: metadata.function_name,
                        test_identifier: test_case.test_identifier.clone(),
                    });
                    continue;
                }

                // detect a path like:
                // /home/mfenniak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/regex-automata-0.4.7/src/hybrid/search.rs
                // by identifying `.cargo/registry/src` section, and then extract the package name (regex-automata) and
                // version (0.4.7) from the path if present.
                let mut itr = file.components();
                while let Some(comp) = itr.next() {
                    if let Component::Normal(path) = comp
                        && path == ".cargo"
                    {
                        if let Some(Component::Normal(path)) = itr.next()
                            && path == "registry"
                            && let Some(Component::Normal(path)) = itr.next()
                            && path == "src"
                            && let Some(Component::Normal(_registry_path)) = itr.next()
                            && let Some(Component::Normal(package_path)) = itr.next()
                            && let Some((package_name, version)) = parse_cargo_package(package_path)
                        {
                            trace!("Found package reference to {} / {}", package_name, version);
                            coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
                                test_identifier: test_case.test_identifier.clone(),
                                coverage_identifier: RustCoverageIdentifier::PackageDependency(
                                    RustPackageDependency {
                                        package_name,
                                        version,
                                    },
                                ),
                            });
                        }
                        break;
                    }
                }
            } else {
                // FIXME: not sure what the right thing to do here is, if we've hit a point in the instrumentation, but
                // the coverage library can't fetch data about it (eg. the else path)... it might (should?) never
                // happen, so let's log a warning.
                warn!("coverage point {point:?} could not be found in the coverage library");
            }
        }

        Ok(())
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_trace_data(
        test_case: &RustConcreteTestIdentifier,
        trace: &Trace,
        current_dir: &Path,
        coverage_data: &mut CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
    ) -> Result<()> {
        let repo_root = env::current_dir()?;

        for path in trace.get_open_paths() {
            if path.is_relative() || path.starts_with(&repo_root) {
                debug!(
                    "found test {} accessed local file {path:?}",
                    test_case.test_identifier
                );

                let target_path = normalize_path(
                    path,
                    &current_dir.join("fake"), // normalize_path expects relative_to to be a file, not dir; so we add a fake child path
                    &repo_root,
                    |warning| {
                        warn!(
                            "syscall trace accessed path {path:?} but couldn't normalize to repo root: {warning}"
                        );
                    },
                );
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
                coverage_identifier: RustCoverageIdentifier::NetworkDependency(sockaddr.clone()),
            });
        }

        Ok(())
    }

    async fn run_test(
        test_case: &RustConcreteTestIdentifier,
        tmp_path: &Path,
        binaries: &DashSet<PathBuf>,
        coverage_library: &Arc<RwLock<CoverageLibrary>>,
    ) -> Result<CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>, RunTestError> {
        let mut coverage_data = CommitCoverageData::new();

        trace!("preparing for test case {:?}", test_case);

        coverage_data.add_executed_test(test_case.test_identifier.clone());

        if binaries.insert(test_case.test_binary.executable_path.clone()) {
            let mut lock = coverage_library.write().unwrap(); // FIXME: unwrap?
            trace!(
                "binary {:?}; loading instrumentation data...",
                test_case.test_binary
            );
            (*lock).load_binary(&test_case.test_binary.executable_path)?;
        }

        let coverage_dir = tmp_path.join(
            Path::new("coverage-output").join(
                test_case
                    .test_binary
                    .executable_path
                    .file_name()
                    .expect("file_name must be present"),
            ),
        );
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
            .with_extension("profraw");
        let strace_file = coverage_dir
            .join(&test_case.test_identifier.test_name)
            .with_extension("strace");

        // Match `cargo test` behavior by moving CWD into the root of the module
        let test_wd = test_case.test_binary.manifest_path.parent().unwrap();
        debug!(
            "Execute test case {:?} into {:?} from working-dir {:?}...",
            test_case, profile_file, test_wd
        );

        let mut cmd = Command::new(&test_case.test_binary.executable_path);
        cmd.arg("--exact")
            .arg(&test_case.test_identifier.test_name)
            .env("LLVM_PROFILE_FILE", &profile_file)
            .env("RUSTFLAGS", "-C instrument-coverage")
            .current_dir(test_wd);

        let (output, trace) = sys_trace_command
            .trace_command(cmd, &strace_file)
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

        trace!("Successfully ran test {:?}!", test_case.test_identifier);

        let coverage_library_lock = coverage_library.read().unwrap();
        Self::parse_profiling_data(
            test_case,
            &profile_file,
            &coverage_library_lock,
            &mut coverage_data,
        )?;
        Self::parse_trace_data(test_case, &trace, test_wd, &mut coverage_data)?;

        Ok(coverage_data)
    }

    fn find_compile_time_includes(file: &PathBuf) -> Result<HashSet<PathBuf>> {
        let mut result = HashSet::new();

        let file = File::open(file).context(format!(
            "error in find_compile_time_includes opening file {file:?}"
        ))?;
        let content = io::read_to_string(BufReader::new(file))
            .context("find_compile_time_includes file read")?;

        for cap in include_regex.captures_iter(&content) {
            let path = String::from(&cap["path"])
                // Un-escape any escaped double-quotes
                .replace("\\\"", "\"");
            result.insert(PathBuf::from(path));
        }

        Ok(result)
    }
}

impl TestPlatform for RustTestPlatform {
    type TI = RustTestIdentifier;
    type CI = RustCoverageIdentifier;
    type TD = RustTestDiscovery;
    type CTI = RustConcreteTestIdentifier;

    fn platform_identifier() -> &'static str {
        "rust"
    }

    fn platform_tags() -> Vec<Tag> {
        vec![Tag {
            key: String::from("__testtrim_rust"),
            value: String::from("1"),
        }]
    }

    fn project_name() -> Result<String> {
        // It could make more sense to make this method infallible and return an "unknown" tag or something.  But I'm
        // thinking to start restrictive and see if it ever becomes an issue.

        // We avoid using `Manifest`'s advanced workspace features since we're just trying to read the project name; so
        // read the Cargo.toml file ourselves and use `from_str` to parse it with the least fuss.
        let toml_contents = fs::read_to_string("Cargo.toml").context("reading Cargo.toml")?;
        let manifest = Manifest::from_str(&toml_contents).context("parsing Cargo.toml")?;

        if let Some(package) = manifest.package {
            Ok(package.name)
        } else {
            if let Some(workspace) = manifest.workspace
                && !workspace.members.is_empty()
            {
                // This is a bit hacky... not sure what the right behavior is yet.
                return Ok(workspace.members[0].clone());
            }
            Err(anyhow!("unable to access package metadata in Cargo.toml"))
        }
    }

    #[instrument(skip_all, fields(perftrace = "discover-tests"))]
    fn discover_tests() -> Result<RustTestDiscovery> {
        let test_binaries = RustTestPlatform::find_test_binaries()?;
        trace!("test_binaries: {:?}", test_binaries);

        let all_test_cases = RustTestPlatform::get_all_test_cases(&test_binaries)?;
        trace!("all_test_cases: {:?}", all_test_cases);

        Ok(RustTestDiscovery {
            test_binaries,
            all_test_cases,
        })
    }

    #[instrument(skip_all, fields(perftrace = "platform-specific-test-cases"))]
    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<RustTestIdentifier>,
        eval_target_changed_files: &HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
    ) -> Result<PlatformSpecificRelevantTestCaseData<RustTestIdentifier, RustCoverageIdentifier>>
    {
        let mut test_cases: HashMap<
            RustTestIdentifier,
            HashSet<TestReason<RustCoverageIdentifier>>,
        > = HashMap::new();

        let mut external_dependencies_changed = None;
        // FIXME: I'm not confident that this check is right -- could there be multiple lock files in a realistic repo?
        // But this is simple and seems pretty applicable for now.
        if eval_target_changed_files.contains(Path::new("Cargo.lock")) {
            external_dependencies_changed = Some(RustTestPlatform::rust_cargo_deps_test_cases(
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
        test_cases: I,
        jobs: u16,
    ) -> Result<CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>, RunTestsErrors>
    where
        I: IntoIterator<Item = &'a RustConcreteTestIdentifier>,
        RustConcreteTestIdentifier: 'a,
    {
        let tmp_dir = TempDir::new("testtrim")?;

        let coverage_library = Arc::new(RwLock::new(CoverageLibrary::new()));
        let mut coverage_data = CommitCoverageData::new();
        let binaries = Arc::new(DashSet::new());

        let mut futures = vec![];
        for test_case in test_cases {
            let tmp_path = PathBuf::from(tmp_dir.path());
            let b = binaries.clone();
            let cl = coverage_library.clone();
            let tc = test_case.clone();
            futures.push(async move { RustTestPlatform::run_test(&tc, &tmp_path, &b, &cl).await });
        }

        let concurrency = if jobs == 0 {
            num_cpus::get()
        } else {
            jobs.into()
        };
        let results = spawn_limited_concurrency(concurrency, futures).await?;

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
        changed_files: &HashSet<PathBuf>,
        coverage_data: &mut CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
    ) -> Result<()> {
        let repo_root = env::current_dir()?;

        for file in changed_files {
            if file.extension().is_some_and(|ext| ext == "rs") {
                let mut found_references = false;

                if !fs::exists(file)? {
                    // A file was considered "changed" but doesn't exist -- indicating a deleted file.
                    coverage_data.mark_file_makes_no_references(file.clone());
                    continue;
                }

                for target_path in Self::find_compile_time_includes(file)? {
                    // FIXME: It's not clear whether warnings are the right behavior for any of these problems.  Some of
                    // them might be better elevated to errors?
                    let target_path = normalize_path(&target_path, file, &repo_root, |warning| {
                        warn!(
                            "file {file:?} had an include/include_str/include_bytes macro, but reference could not be followed: {warning}"
                        );
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

lazy_static! {
    static ref parse_cargo_package_regex: Regex =
        Regex::new(r"^(?<package_name>.+)-(?<package_version>[0-9]+\..*)$").unwrap();
}

/// Parse a path from .cargo/registry/src/*/... (eg. `ws2_32-sys-0.2.1`) and return the package name (`ws2_32`) and
/// version ("0.2.1") if they could be distinguished.
///
/// Some awkward examples:
///   - ws2_32-sys-0.2.1
///   - winit-0.29.1-beta
///   - yeslogic-fontconfig-sys-5.0.0
///   - wasi-0.11.0+wasi-snapshot-preview1
fn parse_cargo_package(path: &OsStr) -> Option<(String, String)> {
    // I think splitting on "-[0-9]\." is probably reasonably good.
    match path.to_str() {
        Some(path) => parse_cargo_package_regex.captures(path).map(|captures| {
            (
                String::from(&captures["package_name"]),
                String::from(&captures["package_version"]),
            )
        }),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, ffi::OsStr, path::PathBuf};

    use crate::{
        coverage::commit_coverage_data::CommitCoverageData,
        platform::{TestPlatform, rust::RustTestPlatform},
    };

    use super::parse_cargo_package;

    #[test]
    fn test_parse_cargo_package() {
        assert_eq!(
            parse_cargo_package(OsStr::new("regex-automata-0.4.7")),
            Some((String::from("regex-automata"), String::from("0.4.7")))
        );
        assert_eq!(
            parse_cargo_package(OsStr::new("ws2_32-sys-0.2.1")),
            Some((String::from("ws2_32-sys"), String::from("0.2.1")))
        );
        assert_eq!(
            parse_cargo_package(OsStr::new("winit-0.29.1-beta")),
            Some((String::from("winit"), String::from("0.29.1-beta")))
        );
        assert_eq!(
            parse_cargo_package(OsStr::new("yeslogic-fontconfig-sys-5.0.0")),
            Some((
                String::from("yeslogic-fontconfig-sys"),
                String::from("5.0.0")
            ))
        );
        assert_eq!(
            parse_cargo_package(OsStr::new("wasi-0.11.0+wasi-snapshot-preview1")),
            Some((
                String::from("wasi"),
                String::from("0.11.0+wasi-snapshot-preview1")
            ))
        );
    }

    #[test]
    fn find_compile_time_includes() {
        let res = RustTestPlatform::find_compile_time_includes(&PathBuf::from(
            "tests/rust_parse_examples/sequences.rs",
        ));
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.len(), 5, "correct # of files read");
        assert!(res.contains(&PathBuf::from("../test_data/Factorial_Vec.txt")));
        assert!(res.contains(&PathBuf::from(
            "/this-is-not-a-file-path-that-really-exists-but-it-is-quite-long-wouldnt-you-say?"
        )));
        assert!(res.contains(&PathBuf::from("abc.txt ")));
        assert!(res.contains(&PathBuf::from("file\"with\"quotes.txt")));
        assert!(res.contains(&PathBuf::from("/proc/cpuinfo")));
    }

    #[test]
    fn analyze_changed_files_include() {
        let mut files = HashSet::new();
        files.insert(PathBuf::from("tests/rust_parse_examples/sequences.rs"));

        let mut coverage_data = CommitCoverageData::new();

        let res = RustTestPlatform::analyze_changed_files(&files, &mut coverage_data);
        assert!(res.is_ok());
        assert_eq!(
            coverage_data.file_references_files_map().len(),
            1,
            "correct # of files read"
        );
        assert_eq!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("tests/rust_parse_examples/sequences.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("tests/rust_parse_examples/sequences.rs"))
                .unwrap()
                .contains(&PathBuf::from("tests/test_data/Factorial_Vec.txt"))
        );
    }
}
