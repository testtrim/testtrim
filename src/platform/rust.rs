// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use cargo_lock::Lockfile;
use lazy_static::lazy_static;
use log::{debug, info, trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::{env, fs, io};
use std::{hash::Hash, path::Path};
use tempdir::TempDir;

use crate::commit_coverage_data::{
    CommitCoverageData, CoverageIdentifier, FileCoverage, FunctionCoverage, HeuristicCoverage,
};
use crate::errors::SubcommandErrors;
use crate::full_coverage_data::FullCoverageData;
use crate::rust_llvm::{CoverageLibrary, ProfilingData};
use crate::scm::{Scm, ScmCommit};

use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestPlatform,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustTestIdentifier {
    /// Project-relative source path that defines the binary which contains the test.  For example,
    /// some_module/src/lib.rs.
    pub test_src_path: PathBuf,
    /// Name of the test.  For example, basic_ops::tests::test_add.
    pub test_name: String,
}

impl TestIdentifier for RustTestIdentifier {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum RustCoverageIdentifier {
    ExternalDependency(RustExternalDependency),
    // Future: information like the rust version used
}

impl CoverageIdentifier for RustCoverageIdentifier {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustExternalDependency {
    pub package_name: String,
    pub version: String,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustTestBinary {
    pub rel_src_path: PathBuf,
    pub executable_path: PathBuf,
    pub manifest_path: PathBuf,
}

// FIXME: rename to ConcreteRustTestIdentifier -- name is horrible... this is more like a "concrete" version of a
// RustTestIdentifier, w/ specific knowledge required to execute this test, rather than the abstract system-to-system
// reusable test identifier that RustTestIdentifier is
#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct RustTestCase {
    pub test_binary: RustTestBinary,
    pub test_identifier: RustTestIdentifier,
}

impl ConcreteTestIdentifier<RustTestIdentifier> for RustTestCase {
    fn test_identifier(&self) -> &RustTestIdentifier {
        &self.test_identifier
    }
}

pub struct RustTestDiscovery {
    test_binaries: HashSet<RustTestBinary>,
    all_test_cases: HashSet<RustTestCase>,
}

impl TestDiscovery<RustTestCase, RustTestIdentifier> for RustTestDiscovery {
    fn all_test_cases(&self) -> &HashSet<RustTestCase> {
        &self.all_test_cases
    }

    fn map_ti_to_cti(&self, test_identifier: RustTestIdentifier) -> Option<RustTestCase> {
        for test_binary in &self.test_binaries {
            if test_binary.rel_src_path == test_identifier.test_src_path {
                let new_test_case = RustTestCase {
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

pub struct RustTestPlatform;

impl RustTestPlatform {
    fn rust_cargo_deps_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<RustTestIdentifier>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
        test_cases: &mut HashSet<RustTestIdentifier>,
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
            let relevant_change = match current_lock_map.get(old.name.as_str()) {
                Some(current_version) => {
                    if *current_version != old.version {
                        trace!(
                            "Cargo.lock package changed {}, old: {}, current: {}",
                            old.name,
                            old.version,
                            current_version
                        );
                        true
                    } else {
                        false
                    }
                }
                None => {
                    trace!("Cargo.lock package removed {}", old.name);
                    true
                }
            };

            if relevant_change {
                info!(
                    "Change to dependency {}; will run all tests that touched it",
                    old.name
                );
                changed_external_dependencies += 1;
                let coverage_identifier =
                    RustCoverageIdentifier::ExternalDependency(RustExternalDependency {
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
                            test_cases.insert(test.clone());
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

        let output = Command::new("cargo")
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
    ) -> Result<HashSet<RustTestCase>> {
        let tmp_dir = TempDir::new("testtrim")?;
        let mut result: HashSet<RustTestCase> = HashSet::new();

        for binary in test_binaries {
            let output = Command::new(&binary.executable_path)
                .arg("--list")
                .env(
                    "LLVM_PROFILE_FILE",
                    Path::join(tmp_dir.path(), "get_all_test_cases_%m_%p.profraw"),
                )
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
                result.insert(RustTestCase {
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
}

impl TestPlatform<RustTestIdentifier, RustCoverageIdentifier, RustTestDiscovery, RustTestCase>
    for RustTestPlatform
{
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

    fn platform_specific_relevant_test_cases<
        Commit: crate::scm::ScmCommit,
        MyScm: crate::scm::Scm<Commit>,
    >(
        eval_target_test_cases: &std::collections::HashSet<RustTestIdentifier>,
        eval_target_changed_files: &std::collections::HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &crate::full_coverage_data::FullCoverageData<
            RustTestIdentifier,
            RustCoverageIdentifier,
        >,
    ) -> anyhow::Result<PlatformSpecificRelevantTestCaseData<RustTestIdentifier>> {
        let mut test_cases = HashSet::new();

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

    fn run_tests<'a, I>(
        test_cases: I,
    ) -> Result<
        crate::commit_coverage_data::CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
    >
    where
        I: IntoIterator<Item = &'a RustTestCase>,
        RustTestCase: 'a,
    {
        let tmp_dir = TempDir::new("testtrim")?;
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

            let coverage_dir = tmp_dir.path().join(
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

            // Match `cargo test` behavior by moving CWD into the root of the module
            let test_wd = test_case.test_binary.manifest_path.parent().unwrap();
            debug!(
                "Execute test case {:?} into {:?} from working-dir {:?}...",
                test_case, profile_file, test_wd
            );
            let output = Command::new(&test_case.test_binary.executable_path)
                .arg("--exact")
                .arg(&test_case.test_identifier.test_name)
                .env("LLVM_PROFILE_FILE", &profile_file)
                .env("RUSTFLAGS", "-C instrument-coverage")
                .current_dir(test_wd)
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
            let profiling_data = ProfilingData::new_from_profraw_reader(reader)
                .context("new_from_profraw_reader")?;

            for point in profiling_data.get_hit_instrumentation_points() {
                // FIXME: not sure what the right thing to do here is, if we've hit a point in the instrumentation, but
                // the coverage library can't fetch data about it... for the moment we'll just ignore it until we come
                // up with a test that hits this case and breaks
                if let Ok(Some(metadata)) = coverage_library.search_metadata(&point) {
                    for file in metadata.file_paths {
                        // detect a path like:
                        // /home/mfenniak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/regex-automata-0.4.7/src/hybrid/search.rs
                        // by identifying `.cargo/registry/src` section, and then extract the package name
                        // (regex-automata) and version (0.4.7) from the path if present.
                        let mut itr = file.components();
                        while let Some(comp) = itr.next() {
                            if let std::path::Component::Normal(path) = comp
                                && path == ".cargo"
                                && let Some(std::path::Component::Normal(path)) = itr.next()
                                && path == "registry"
                                && let Some(std::path::Component::Normal(path)) = itr.next()
                                && path == "src"
                                && let Some(std::path::Component::Normal(_registry_path)) =
                                    itr.next()
                                && let Some(std::path::Component::Normal(package_path)) = itr.next()
                                && let Some((package_name, version)) =
                                    parse_cargo_package(package_path)
                            {
                                trace!("Found package reference to {} / {}", package_name, version);
                                coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
                                    test_identifier: test_case.test_identifier.clone(),
                                    coverage_identifier: RustCoverageIdentifier::ExternalDependency(
                                        RustExternalDependency {
                                            package_name,
                                            version,
                                        },
                                    ),
                                })
                            }
                        }
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
}

lazy_static! {
    static ref parse_cargo_package_regex: Regex =
        Regex::new(r"^(?<package_name>.+)-(?<package_version>[0-9]+\..*)$").unwrap();
}

/// Parse a path from .cargo/registry/src/*/... (eg. ws2_32-sys-0.2.1) and return the package name ("ws2_32") and
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
    use std::ffi::OsStr;

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
}
