// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use dashmap::DashSet;
use lazy_static::lazy_static;
use log::{trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env::current_dir;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::{fmt, fs};
use std::{hash::Hash, path::Path};
use tempdir::TempDir;
use threadpool::ThreadPool;
use tracing::dispatcher::{self, get_default};
use tracing::instrument;

use crate::coverage::commit_coverage_data::{CommitCoverageData, CoverageIdentifier, FileCoverage};
use crate::coverage::full_coverage_data::FullCoverageData;
use crate::errors::{
    FailedTestResult, RunTestError, RunTestsErrors, SubcommandErrors, TestFailure,
};

use super::dotnet_cobertura::Coverage;
use super::TestReason;
use super::{
    ConcreteTestIdentifier, PlatformSpecificRelevantTestCaseData, TestDiscovery, TestIdentifier,
    TestIdentifierCore, TestPlatform,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DotnetTestIdentifier {
    // FIXME: should I store an assembly-qualified name?  Currently test discovery doesn't give me the assembly, so that would be a challenge.
    /// Name of the test.  For example, `MathFunctions.Tests.BasicOpsTests.TestAdd`
    pub fully_qualified_name: String,
}

impl TestIdentifier for DotnetTestIdentifier {}
impl TestIdentifierCore for DotnetTestIdentifier {
    fn lightly_unique_name(&self) -> String {
        self.fully_qualified_name.clone()
    }
}

impl fmt::Display for DotnetTestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fully_qualified_name)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum DotnetCoverageIdentifier {
    // Possible future: dotnet version, platform, etc. -- might be better as tags since they'd be pretty universal for the whole commit though?
    PackageDependency(DotnetPackageDependency),
    // NetworkDependency(UnifiedSocketAddr),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DotnetPackageDependency {
    pub package_name: PackageName,
    pub version: PackageVersion,
}

impl CoverageIdentifier for DotnetCoverageIdentifier {}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct DotnetConcreteTestIdentifier {
    pub test_identifier: DotnetTestIdentifier,
}

impl ConcreteTestIdentifier<DotnetTestIdentifier> for DotnetConcreteTestIdentifier {
    fn test_identifier(&self) -> &DotnetTestIdentifier {
        &self.test_identifier
    }
}

pub struct DotnetTestDiscovery {
    all_test_cases: HashSet<DotnetConcreteTestIdentifier>,
}

impl TestDiscovery<DotnetConcreteTestIdentifier, DotnetTestIdentifier> for DotnetTestDiscovery {
    fn all_test_cases(&self) -> &HashSet<DotnetConcreteTestIdentifier> {
        &self.all_test_cases
    }

    fn map_ti_to_cti(
        &self,
        test_identifier: DotnetTestIdentifier,
    ) -> Option<DotnetConcreteTestIdentifier> {
        Some(DotnetConcreteTestIdentifier { test_identifier })
    }
}

lazy_static! {
    static ref slnProject: Regex =
        Regex::new(r#"(?m)^Project\(\"[^"]+\"\)\s=\s\"[^"]+\",\s\"(?<path>[^"]+)\","#).unwrap();
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
struct TargetFrameworkName(String);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
struct ProjectFile(PathBuf);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct PackageName(String);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct PackageVersion(String);

// TODO: external dependency tracking
// type SolutionDependencyMap = HashMap<PackageName, PackageVersion>;

#[derive(Debug, Serialize, Deserialize)]
struct PackageLock {
    version: i32,
    dependencies: HashMap<TargetFrameworkName, TargetFrameworkDependencies>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetFrameworkDependencies {
    #[serde(flatten)]
    dependencies: HashMap<PackageName, DependencyData>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum DependencyType {
    Transitive,
    Project,
    Direct,
}

#[derive(Debug, Serialize, Deserialize)]
struct DependencyData {
    #[serde(rename = "type")]
    dependency_type: DependencyType,
    requested: Option<String>, // eg. "[17.11.1, )"
    resolved: Option<String>,  // eg. "17.11.1"
    #[serde(rename = "contentHash")]
    content_hash: Option<String>, // eg. "U3Ty4BaGoEu+T2bwSko9tWqWUOU16WzSFkq6U8zve75oRBMSLTBdMAZrVNNz1Tq12aCdDom9fcOcM9QZaFHqFg=="
    dependencies: Option<HashMap<String, String>>, // eg. "Microsoft.CodeCoverage": "17.11.1",
}

pub struct DotnetTestPlatform;

impl DotnetTestPlatform {
    #[must_use]
    pub fn autodetect() -> bool {
        let slns = Self::find_sln_file()
            .expect("autodetect test project type failed when checking for *.sln files");
        if slns.is_empty() {
            false
        } else {
            trace!("Detected one-or-more .sln files; auto-detect result: .NET test project");
            true
        }
    }

    fn get_all_test_cases() -> Result<HashSet<DotnetConcreteTestIdentifier>> {
        let mut result: HashSet<DotnetConcreteTestIdentifier> = HashSet::new();

        let output = Command::new("dotnet")
            .args(["test", "--list-tests", "--", "NUnit.DisplayName=FullName"])
            .output()
            .expect("Failed to execute dotnet test --list-tests command");

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("dotnet test --list-tests"),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
        let mut found_intro = false;
        for line in stdout.lines() {
            if found_intro {
                result.insert(DotnetConcreteTestIdentifier {
                    test_identifier: DotnetTestIdentifier {
                        fully_qualified_name: String::from(line.trim_start()),
                    },
                });
            }
            if line.starts_with("The following Tests are available:") {
                found_intro = true;
            }
        }

        Ok(result)
    }

    fn run_test(
        test_case: &DotnetConcreteTestIdentifier,
        _tmp_path: &Path,
        _binaries: &DashSet<PathBuf>,
        // dep_map: &SolutionDependencyMap, // TODO: external dependency tracking
    ) -> Result<CommitCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>, RunTestError>
    {
        let mut coverage_data = CommitCoverageData::new();

        coverage_data.add_executed_test(test_case.test_identifier.clone());

        // dotnet test --collect:"XPlat Code Coverage;Format=json,lcov,cobertura" --filter "FullyQualifiedName=MathFunctions.Tests.BasicOpsTests.TestAdd"

        let output = Command::new("dotnet")
            .args([
                "test",
                // Saves a bit of time during the test command as the test discovery would've already built.
                "--no-build",
                "--collect:\"XPlat Code Coverage;Format=cobertura",
                "--filter",
                &format!(
                    "FullyQualifiedName={}",
                    test_case.test_identifier.fully_qualified_name
                ),
                "--",
                // Configure to collect coverage in test assembly itself, usually disabled; required to give us which
                // test files changes will affect which tests in future changes.
                "DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.IncludeTestAssembly=true",
                // At least in Linux (haven't tested Windows), the "filename" reported in the cobertura report isn't
                // really usable because it is either relative to the user's HOME, or relative to the root fs (/), and
                // there's no indication of which.  DeterministicReport turns it into an absolute file path which is
                // much more predictable to work with when identifying which files within the repo were touched when a
                // test was run.
                "DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.DeterministicReport=true",
                // TODO: external dependency tracking
                // Even if we don't have sources (eg. for external dependencies), instrument them for coverage.  This
                // still only works for libraries with pdb files, though.
                // "DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.ExcludeAssembliesWithoutSources=None",
            ])
            .output()
            .expect("Failed to execute dotnet test --list-tests command");

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

        // Expected output like:
        // Attachments:
        //     /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/TestResults/c2ecc800-ae19-442c-8788-0cc46073d401/coverage.json
        //     /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/TestResults/c2ecc800-ae19-442c-8788-0cc46073d401/coverage.info
        //     /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/TestResults/c2ecc800-ae19-442c-8788-0cc46073d401/coverage.cobertura.xml

        let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
        let mut found_intro = false;
        for line in stdout.lines() {
            if found_intro {
                // Avoiding treating "Passed!" or other output as an lcov file -- the "attachments" start with whitespace...
                if line.starts_with(' ') {
                    let path = PathBuf::from(line.trim_start());
                    Self::parse_profiling_data(
                        test_case,
                        &path,
                        /* &dep_map, */ &mut coverage_data,
                    )?;
                }
            }
            if line.starts_with("Attachments:") {
                found_intro = true;
            }
        }

        Ok(coverage_data)
    }

    #[instrument(skip_all, fields(perftrace = "parse-test-data"))]
    fn parse_profiling_data(
        test_case: &DotnetConcreteTestIdentifier,
        profile_file: &PathBuf,
        // dep_map: &SolutionDependencyMap, // TODO: external dependency tracking
        coverage_data: &mut CommitCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>,
    ) -> Result<()> {
        let project_dir = current_dir().context("error getting current_dir()")?;
        let reader = File::open(profile_file).context("error opening {profile_file:?}")?; // fs::Op::Reader::open_file(profile_file)?;

        let coverage: Coverage = quick_xml::de::from_reader(BufReader::new(reader))?;

        for ref pkg in coverage.packages.package {
            // TODO: external dependency tracking
            // if pkg.line_rate > 0.0 {
            //     warn!("test hit external dependency {}", pkg.name); // FIXME: change to trace or debug
            //     let package_name = PackageName(pkg.name.clone());
            //     match dep_map.get(&package_name) {
            //         Some(pkg_version) => {
            //             warn!("dep_map had version {pkg_version:?}");
            //             coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            //                 test_identifier: test_case.test_identifier.clone(),
            //                 coverage_identifier: DotnetCoverageIdentifier::PackageDependency(
            //                     DotnetPackageDependency {
            //                         package_name,
            //                         version: pkg_version.clone(),
            //                     },
            //                 ),
            //             });
            //         }
            //         None => {
            //             warn!("test {test_case:?} accessed package {package_name:?} but dependency map didn't track what version of that package; missing packages.lock.json?");
            //         }
            //     }
            // }

            for cls in &pkg.classes.class {
                if cls.line_rate > 0.0 {
                    let current_source_file = Path::new(&cls.filename);
                    trace!(
                        "test hit file {} {} {current_source_file:?}; project_dir: {project_dir:?}",
                        pkg.name,
                        cls.name
                    );

                    // current_source_file should be an absolute path thanks to the DeterministicReport setting, but
                    // this might require testing in Windows as the coverlet documentation doesn't seem to say this is
                    // how it works, but it is how it works in Linux.  As-is, we can check if it's part of our repo by
                    // strip_prefix:
                    if let Ok(relative_path) =
                        Path::new(&current_source_file).strip_prefix(&project_dir)
                    {
                        trace!("test hit file relative path: {relative_path:?}");
                        coverage_data.add_file_to_test(FileCoverage {
                            file_name: relative_path.to_path_buf(),
                            test_identifier: test_case.test_identifier.clone(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    // TODO: external dependency tracking
    // fn try_populate_package_pdbs() -> Result<SolutionDependencyMap> {
    //     // The goal of this routine is to populate the .pdb files for any package references that test projects have,
    //     // which will allow those packages to be instrumented for code coverage tracking.  This routine is going to be
    //     // quite a hack, but maybe over time it will become more sophisticated (or be replaced).
    //     //
    //     // While we're doing all of this, we're going to build up a library of each project's references and their
    //     // specific versions.  We need this later as we parse coverage data and see a reference to an external
    //     // dependency in order to identify what version was in-use.
    //     let mut dep_map = SolutionDependencyMap::new();
    //
    //     // Find all the "test projects".  sln -> all projects -> all projects that end in ".Test" or ".Tests" (could be
    //     // done through package, or project type)
    //     let solutions = Self::find_sln_file()?;
    //     if solutions.len() > 1 {
    //         return Err(anyhow!("multiple *.sln files found; not sure which to use"));
    //     } else if solutions.is_empty() {
    //         return Err(anyhow!(
    //             "zero *.sln files found; unable to find test projects"
    //         ));
    //     }
    //     let solution = &solutions[0];
    //
    //     let projects =
    //         Self::parse_projects_from_sln(&fs::read_to_string(solution).context("read sln file")?);
    //     let projects = Self::filter_test_projects(projects);
    //     let mut last_error = None;
    //     for project in projects {
    //         // If an error occurs in one project, let's keep track of that error but keep trying the other projects.
    //         // This is a bit hacky but since I know the error handling external to here is going to log a warning, it
    //         // makes sense to try to get the most success out before the process continues onwards.  That knowledge is
    //         // the hacky bit... probably implies it would be better to make this function infallible and just log the
    //         // warnings  FIXME: do that
    //         if let Err(e) = Self::try_populate_package_pdbs_for_project(&project, &mut dep_map) {
    //             last_error = Some(e);
    //         }
    //     }
    //
    //     info!("dep_map generated -> {dep_map:?}");
    //
    //     match last_error {
    //         Some(error) => Err(error),
    //         None => Ok(dep_map),
    //     }
    // }

    fn find_sln_file() -> Result<Vec<PathBuf>> {
        let mut retval = vec![];
        for entry in fs::read_dir(".")? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "sln") && path.is_file() {
                retval.push(path);
            }
        }
        Ok(retval)
    }

    // TODO: external dependency tracking
    // fn parse_projects_from_sln(sln: &str) -> Vec<ProjectFile> {
    //     let mut retval = vec![];
    //     // FIXME: this is currently being tested in Linux, and might need tweaks in Windows...
    //     for caps in slnProject.captures_iter(sln) {
    //         let p = &caps["path"];
    //         let path = PathBuf::from(p.replace('\\', std::path::MAIN_SEPARATOR_STR));
    //         retval.push(ProjectFile(path));
    //     }
    //     retval
    // }

    // TODO: external dependency tracking
    // fn filter_test_projects(projects: Vec<ProjectFile>) -> impl Iterator<Item = ProjectFile> {
    //     // FIXME: This is a super imprecise way to find a test project and should be improved.
    //     projects
    //         .into_iter()
    //         .filter(|p| p.0.to_string_lossy().contains("Test"))
    // }

    // TODO: external dependency tracking
    // fn try_populate_package_pdbs_for_project(
    //     project_file: &ProjectFile,
    //     dep_map: &mut SolutionDependencyMap,
    // ) -> Result<()> {
    //     // For each of the test projects -> read packages.lock.json and find all the dependencies, and calculate the
    //     // output directory
    //     let project_dir = project_file
    //         .0
    //         .parent()
    //         .ok_or_else(|| anyhow!("unable to find parent directory of project file"))?;
    //
    //     let package_lock_json_path = project_dir.join("packages.lock.json");
    //     if !fs::exists(&package_lock_json_path)? {
    //         // This package doesn't have a packages.lock.json.  That could be either because RestorePackagesWithLockFile
    //         // is diabled (which we would want to warn about as we need this for coverage tracking), or because there
    //         // are no external dependencies (which is fine).  Let's err on the side of warning.
    //         warn!("project {project_file:?} has no accompanying packages.lock.json which will prevent external dependency update tracking by testtrim");
    //         return Ok(());
    //     }
    //
    //     let target_framework = "net6.0"; // FIXME: hard coded target framework name
    //     let output_dir = project_dir.join("bin/Debug").join(target_framework); // FIXME: hardcoded output dir
    //
    //     let package_lock: PackageLock = serde_json::from_reader(
    //         File::open(package_lock_json_path).context("open packages.lock.json")?,
    //     )
    //     .context("deserialize packages.lock.json")?;
    //
    //     // For each of the dependencies -> check if a pdb is present and the "right version" "right version" -> either
    //     // we didn't provide it (dotnet build did), or, it has a marker file indicating the version and it matches the
    //     // dependency
    //     if let Some(framework) = package_lock
    //         .dependencies
    //         .get(&TargetFrameworkName(String::from("net6.0")))
    //     {
    //         for (package_name, info) in &framework.dependencies {
    //             trace!("checking pdb for dependency {project_file:?} -> {package_name:?}");
    //             if let Some(ref resolved_version) = info.resolved {
    //                 let new_value = PackageVersion(resolved_version.clone());
    //                 let prev_value = dep_map.insert(package_name.clone(), new_value.clone());
    //                 if let Some(prev_value) = prev_value
    //                     && prev_value != new_value
    //                 {
    //                     // Theoretically we could track that {project_file} -> {package_name}/{package_version}, but
    //                     // later when we run tests we don't know what project they came out of because our test
    //                     // discovery doesn't give us that information.  Without that information, we'll only be able to
    //                     // track tests that need reexecution when an external dependency changes if that external
    //                     // dependency is consistent across the entire solution.  That's a reasonable enough limitation
    //                     // for now but could probably be improved if needed.
    //                     warn!("project {project_file:?} had a reference to package {package_name:?} version {new_value:?}, but another project had a reference to version {prev_value:?}; testtrim will not be able to accurately track test cases to rerun when this dependency changes")
    //                 }
    //             }
    //             Self::populate_package_pdb(&output_dir, package_name, info)?;
    //         }
    //     }
    //
    //     Ok(())
    // }

    // TODO: external dependency tracking
    // fn populate_package_pdb(
    //     output_dir: &Path,
    //     package_name: &PackageName,
    //     info: &DependencyData,
    // ) -> Result<()> {
    //     let Some(ref resolved_version) = info.resolved else {
    //         // no resolved version in the package.lock.json; not much to do here
    //         return Ok(());
    //     };
    //
    //     let pdb_path = output_dir.join(&package_name.0).with_extension("pdb");
    //     let pdb_version_marker = pdb_path.with_extension(".pdb.testtrim_version");
    //
    //     let do_update = if fs::exists(&pdb_path).context("checking pdb file existence")? {
    //         if fs::exists(&pdb_version_marker).context("checking pdb version marker existence")? {
    //             // We've previously populated this pdb ourselves, which means we're responsible for updating it if the
    //             // version has changed
    //             let stored_version = fs::read_to_string(&pdb_version_marker)
    //                 .context("reading testtrim pdb version marker")?;
    //             info!("dependency {package_name:?} has pdb for version {stored_version}, need pdb for version {resolved_version}"); // FIXME: change to trace later
    //             stored_version != *resolved_version
    //         } else {
    //             // Assumption is that since we didn't mark it, we didn't populate it, and the build tooling is
    //             // maintaining this pdb file.  Therefore we don't touch it.
    //             info!("dependency {package_name:?} has pdb, assuming from build tooling"); // FIXME: change to trace later
    //             false
    //         }
    //     } else {
    //         // Not present, let's try to populate it.
    //         info!("dependency {package_name:?} is missing pdb"); // FIXME: change to trace later
    //         true
    //     };
    //
    //     if !do_update {
    //         return Ok(());
    //     }
    //
    //     // Requires the dotnet-symbol tool as a shortcut for interacting with symbol servers... would be neat to
    //     // implement this ourselves but probably very intricate to read the assemblies and interact with the symbol
    //     // servers.
    //     let target_file = output_dir.join(format!("{}.dll", package_name.0));
    //
    //     // FIXME: This is broken because it assumes that a dependency's package name and its output dll are related to
    //     // each other.  In reality they aren't; the package DecimalMath.DecimalEx has a library that is just
    //     // DecimalEx.dll, and the package Microsoft.TestPlatform.ObjectModel has a library that is
    //     // Microsoft.VisualStudio.TestPlatform.ObjectModel.dll, etc.  This probably requires that we track all coverage
    //     // by the assembly name, and but then we won't be able to look at packages.lock.json to find the changes and run
    //     // related tests if we do that, so, we'll have to create a map between the names.  Unfortunately this data
    //     // doesn't seem to exist on-disk...
    //     // - dotnet restore, even with "diagnostic" logging and force restore, doesn't print out the dll paths...
    //     //   probably would need to be part of the build
    //     // - dotnet test -v:diag --list-tests does print out the information we need... specifically we'd want a map of
    //     //   NuGetPackageId to HintPath (or relative HintPath I guess), but, ugly as hell to rely on the log output like
    //     //   this:
    //     //
    //     //         ExternallyResolved=true
    //     //         HintPath=/home/mfenniak/.nuget/packages/decimalmath.decimalex/1.0.2/lib/netstandard2.0/DecimalEx.dll
    //     //         NuGetPackageId=DecimalMath.DecimalEx
    //     //         NuGetPackageVersion=1.0.2
    //     //         NuGetSourceType=Package
    //     //         PathInPackage=lib/netstandard2.0/DecimalEx.dll
    //     //         Private=false (TaskId:85)
    //     //
    //     // - Hypothetically could build an MSBuild task, which could be put into a package and distributed, which might
    //     //   allow this data to be output... but not sure how to "extend" the dotnet tooling safely these days since
    //     //   MSBuild is still used, but the dotnet CLI is our primary interface
    //
    //     info!("dotnet-symbol target_file: {target_file:?}");
    //     let output = Command::new("dotnet-symbol")
    //         .args([
    //             "--microsoft-symbol-server",
    //             "--server-path",
    //             "https://symbols.nuget.org/download/symbols",
    //             "--symbols",
    //             &target_file.to_string_lossy(),
    //             // eg. "MathFunctions.Tests/bin/Debug/net6.0/DecimalEx.dll",
    //         ])
    //         .output()
    //         .context("failed to execute dotnet-symbol command")?;
    //
    //     if !output.status.success() {
    //         return Err(anyhow!(
    //             "error in dotnet-symbol (code {0:?}): {1}, {2}",
    //             output.status.code(),
    //             String::from_utf8_lossy(&output.stdout).into_owned(),
    //             String::from_utf8_lossy(&output.stderr).into_owned(),
    //         ));
    //     }
    //
    //     let stdout = String::from_utf8_lossy(&output.stdout);
    //     // Pretty hacky, but dotnet-symbol doesn't provide useful exit codes.  Example outputs we're looking for:
    //     //
    //     // (OK, already present)
    //     // Downloading from https://msdl.microsoft.com/download/symbols/
    //     // Downloading from https://symbols.nuget.org/download/symbols/
    //     // MathFunctions.Tests/bin/Debug/net6.0/DecimalEx.pdb already exists, file not written
    //     //
    //     // (OK, failed to find it on one symbol server, found on another)
    //     // Downloading from https://msdl.microsoft.com/download/symbols/
    //     // Downloading from https://symbols.nuget.org/download/symbols/
    //     // ERROR: Not Found: C:\Dev\DecimalEx\DecimalEx\obj\Release\netstandard2.0\DecimalEx.pdb - 'https://msdl.microsoft.com/download/symbols/decimalex.pdb/4f8226dd70734ae48e775e804968157dFFFFFFFF/decimalex.pdb'
    //     // Writing: MathFunctions.Tests/bin/Debug/net6.0/DecimalEx.pdb
    //     if stdout.contains("ERROR")
    //         && !(stdout.contains("Writing:") || stdout.contains("already exists"))
    //     {
    //         return Err(anyhow!(
    //             "error in dotnet-symbol (code {0:?}): {1}, {2}",
    //             output.status.code(),
    //             stdout,
    //             String::from_utf8_lossy(&output.stderr).into_owned(),
    //         ));
    //     }
    //
    //     // Mark the pdb file version that we've populated.
    //     info!("fetched pdb for version {resolved_version} via dotnet-symbol; output: {stdout}");
    //     fs::write(pdb_version_marker, resolved_version)
    //         .context("writing testtrim pdb version marker")?;
    //
    //     Ok(())
    // }
}

impl
    TestPlatform<
        DotnetTestIdentifier,
        DotnetCoverageIdentifier,
        DotnetTestDiscovery,
        DotnetConcreteTestIdentifier,
    > for DotnetTestPlatform
{
    fn project_name() -> Result<String> {
        Ok(String::from(
            current_dir()?
                .file_name()
                .ok_or_else(|| anyhow!("unable to find name of current directory"))?
                .to_string_lossy(),
        ))
    }

    #[instrument(skip_all, fields(perftrace = "discover-tests"))]
    fn discover_tests() -> Result<DotnetTestDiscovery> {
        let all_test_cases = Self::get_all_test_cases()?;
        trace!("all_test_cases: {:?}", all_test_cases);
        Ok(DotnetTestDiscovery { all_test_cases })
    }

    #[instrument(skip_all, fields(perftrace = "platform-specific-test-cases"))]
    fn platform_specific_relevant_test_cases<
        Commit: crate::scm::ScmCommit,
        MyScm: crate::scm::Scm<Commit>,
    >(
        _eval_target_test_cases: &std::collections::HashSet<DotnetTestIdentifier>,
        _eval_target_changed_files: &std::collections::HashSet<PathBuf>,
        _scm: &MyScm,
        _ancestor_commit: &Commit,
        _coverage_data: &FullCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>,
    ) -> anyhow::Result<
        PlatformSpecificRelevantTestCaseData<DotnetTestIdentifier, DotnetCoverageIdentifier>,
    > {
        let test_cases: HashMap<DotnetTestIdentifier, Vec<TestReason<DotnetCoverageIdentifier>>> =
            HashMap::new();

        Ok(PlatformSpecificRelevantTestCaseData {
            additional_test_cases: test_cases,
            external_dependencies_changed: None,
        })
    }

    fn run_tests<'a, I>(
        test_cases: I,
        _jobs: u16, // FIXME: parallel tests are causing errors
    ) -> Result<CommitCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>, RunTestsErrors>
    where
        I: IntoIterator<Item = &'a DotnetConcreteTestIdentifier>,
        DotnetConcreteTestIdentifier: 'a,
    {
        let tmp_dir = TempDir::new("testtrim")?;

        // TODO: external dependency tracking
        // Before running any tests with coverage, evaluate whether there are any PDB files that need to be restored for
        // external dependencies.  This is a complete and total hack, but when it works, it allows tracking the code
        // coverage in external dependencies and therefore running tests that are affected by package updates.
        // let dep_map = match Self::try_populate_package_pdbs() {
        //     Ok(dep_map) => dep_map,
        //     Err(err) => {
        //         warn!("try_populate_package_pdbs failed with error; external dependency coverage tracking will be inaccurate: {err}");
        //         HashMap::new()
        //     }
        // };
        // let dep_map = Arc::new(dep_map);

        let mut coverage_data = CommitCoverageData::new();
        let binaries = Arc::new(DashSet::new());

        let pool = Rc::new(ThreadPool::new(1));
        /*if jobs == 0 {
            num_cpus::get()
        } else {
            jobs.into()
        }));
        */
        let (tx, rx) = channel();

        let mut outstanding_tests = 0;
        for test_case in test_cases {
            let tc = test_case.clone();
            let tmp_path = PathBuf::from(tmp_dir.path());
            let b = binaries.clone();
            // let dep_map = dep_map.clone(); // TODO: external dependency tracking
            let tx = tx.clone();
            let pool = pool.clone();

            // Dance around a bit here to share the same tracing subscriber in the subthreads, allowing us to collect
            // performance data from them.  Note that, as we're running these tests in parallel, the performance data
            // starts to deviate from wall-clock time at this point.
            get_default(move |dispatcher| {
                let tc = tc.clone();
                let tmp_path = tmp_path.clone();
                let b = b.clone();
                // let dep_map = dep_map.clone(); // TODO: external dependency tracking
                let tx = tx.clone();
                let dispatcher = dispatcher.clone();
                pool.execute(move || {
                    dispatcher::with_default(&dispatcher, || {
                        tx.send(Self::run_test(&tc, &tmp_path, &b)).unwrap();
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
        _d_files: &HashSet<PathBuf>,
        _ge_data: &mut CommitCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // TODO: external dependency tracking
    // #[test]
    // fn parse_projects_from_sln() {
    //     let sln = include_str!("../../tests/test_data/dotnet-coverage-specimen.sln");
    //     let result = DotnetTestPlatform::parse_projects_from_sln(sln);
    //     assert!(
    //         result.contains(&ProjectFile(PathBuf::from(
    //             "MathFunctions/MathFunctions.csproj"
    //         ))),
    //         "expected to contain MathFunctions.csproj, but was: {result:?}"
    //     );
    //     assert!(
    //         result.contains(&ProjectFile(PathBuf::from(
    //             "MathFunctions.Tests/MathFunctions.Tests.csproj"
    //         ))),
    //         "expected to contain MathFunctions.Tests.csproj, but was: {result:?}"
    //     );
    // }
    //
    // #[test]
    // fn parse_package_lock_json() -> Result<()> {
    //     let package_lock_json = include_bytes!("../../tests/test_data/packages.lock.json");
    //     let package_lock: PackageLock = serde_json::from_slice(package_lock_json)?;
    //     assert_eq!(package_lock.version, 1);
    //     assert_eq!(package_lock.dependencies.len(), 1);
    //     let net60 = package_lock
    //         .dependencies
    //         .get(&TargetFrameworkName(String::from("net6.0")))
    //         .ok_or(anyhow!("can't find net6.0"))?;
    //     let testsdk = net60
    //         .dependencies
    //         .get(&PackageName(String::from("Microsoft.NET.Test.Sdk")))
    //         .ok_or(anyhow!("Microsoft.NET.Test.Sdk"))?;
    //     assert_eq!(testsdk.dependency_type, DependencyType::Direct);
    //     assert_eq!(testsdk.requested, Some(String::from("[17.11.1, )")));
    //     assert_eq!(testsdk.resolved, Some(String::from("17.11.1")));
    //     Ok(())
    // }
}

/*
dotnet test --collect:"XPlat Code Coverage;Format=json,lcov,cobertura"

- outputs to TestResults/{guid}/ .json, .info (lcov), .cobertura.xml

- Seems to have some default exclusions in the coverage -- in particular the test assembly itself has no coverage output

- Need to be cautious of the "hits" property -- some functions will be listed as being in the coverage file even if they aren't hit


$ dotnet test --list-tests -- NUnit.DisplayName=FullName
  Determining projects to restore...
  All projects are up-to-date for restore.
  MathFunctions -> /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions/bin/Debug/net6.0/MathFunctions.dll
  MathFunctions.Tests -> /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/bin/Debug/net6.0/MathFunctions.Tests.dll
Test run for /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/bin/Debug/net6.0/MathFunctions.Tests.dll (.NETCoreApp,Version=v6.0)
Microsoft (R) Test Execution Command Line Tool Version 17.3.3 (x64)
Copyright (c) Microsoft Corporation.  All rights reserved.

The following Tests are available:
    MathFunctions.Tests.BasicOpsTests.TestAdd
    MathFunctions.Tests.BasicOpsTests.TestSub


$ dotnet test --collect:"XPlat Code Coverage;Format=json,lcov,cobertura" --filter "FullyQualifiedName=MathFunctions.Tests.BasicOpsTests.TestAdd"
  Determining projects to restore...
  All projects are up-to-date for restore.
  MathFunctions -> /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions/bin/Debug/net6.0/MathFunctions.dll
  MathFunctions.Tests -> /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/bin/Debug/net6.0/MathFunctions.Tests.dll
Test run for /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/bin/Debug/net6.0/MathFunctions.Tests.dll (.NETCoreApp,Version=v6.0)
Microsoft (R) Test Execution Command Line Tool Version 17.3.3 (x64)
Copyright (c) Microsoft Corporation.  All rights reserved.

Starting test execution, please wait...
A total of 1 test files matched the specified pattern.

Attachments:
  /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/TestResults/c2ecc800-ae19-442c-8788-0cc46073d401/coverage.json
  /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/TestResults/c2ecc800-ae19-442c-8788-0cc46073d401/coverage.info
  /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/TestResults/c2ecc800-ae19-442c-8788-0cc46073d401/coverage.cobertura.xml
Passed!  - Failed:     0, Passed:     1, Skipped:     0, Total:     1, Duration: 5 ms - /home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions.Tests/bin/Debug/net6.0/MathFunctions.Tests.dll (net6.0)

*/
