// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    hash::Hash,
    path::PathBuf,
};

use crate::{
    coverage::{
        commit_coverage_data::{CommitCoverageData, CoverageIdentifier},
        full_coverage_data::FullCoverageData,
        Tag,
    },
    errors::RunTestsErrors,
    scm::{Scm, ScmCommit},
};

pub mod dotnet;
mod dotnet_cobertura;
pub mod golang;
pub mod rust;
mod rust_llvm;
mod util;

/// `TestIdentifier` is a machine-independent way to reference a test in a project.
///
/// It must contain data such that, if it was serialized between machines, it could be picked up and contain relevant
/// data to find and execute the test on another host.
pub trait TestIdentifier: Eq + Hash + Clone + Debug + Serialize {}

/// An alternate trait of `TestIdentifier` which can be used with dynamic dispatch.  Test identifiers must implement
/// both traits.
pub trait TestIdentifierCore: Debug + Send + Sync + Display {
    /// Returns the name of this test.
    ///
    /// This should only be used in testtrim's integration tests -- for runtime execution the identity of the
    /// `TestIdentifier` *is* the identity of the test, which might contain multiple data fields and dimensions to
    /// uniquely identify the test.  But for testtrim's own testing, a "lightly unique" name is handy.
    ///
    /// `#[cfg(test)]` would be ideal but can't be accessed by integration tests.
    fn lightly_unique_name(&self) -> String;
}

/// Represents a machine-dependent reference to a test.
///
/// `ConcreteTestIdentifier` is "ready to execute" on the current machine, as compared to `TestIdentifier` which may be
/// missing information, such as specific pathing or tooling references, to be able to be executed.
pub trait ConcreteTestIdentifier<TI: TestIdentifier>: Eq + Hash + Clone + Debug {
    fn test_identifier(&self) -> &TI;
}

pub trait TestDiscovery<CTI: ConcreteTestIdentifier<TI>, TI: TestIdentifier> {
    fn all_test_cases(&self) -> &HashSet<CTI>;
    fn map_ti_to_cti(&self, test_identifier: TI) -> Option<CTI>;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TestReason<CI: CoverageIdentifier> {
    NoCoverageMap,
    NewTest,
    FileChanged(PathBuf),
    CoverageIdentifier(CI),
    NetworkPolicy(String),
    // This is reason 0 caused reason 1 -- for example, changing "file a" caused "file b" to be considered change.
    SideEffect(Box<TestReason<CI>>, Box<TestReason<CI>>),
}

pub struct PlatformSpecificRelevantTestCaseData<TI: TestIdentifier, CI: CoverageIdentifier> {
    /// Key data, which additional test cases should be executed
    pub additional_test_cases: HashMap<TI, HashSet<TestReason<CI>>>,

    /// Instrumentation: how many "external dependencies" changed that caused those additional test cases?
    pub external_dependencies_changed: Option<usize>,
}

#[allow(async_fn_in_trait)] // should be fine to the extent that this is only used internally to this project
pub trait TestPlatform {
    type TI: TestIdentifier + Serialize + DeserializeOwned + 'static;
    type CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static;
    type TD: TestDiscovery<Self::CTI, Self::TI>;
    type CTI: ConcreteTestIdentifier<Self::TI>;

    /// eg. "rust", "dotnet"; must be safe to be used as a single URL path component
    fn platform_identifier() -> &'static str;

    fn project_name() -> Result<String>;

    fn discover_tests() -> Result<Self::TD>;

    /// `platform_tags` give each test platform the opportunity to tag coverage data stored in the coverage database.
    /// If the test platform changes in such a way that older coverage data cannot be used effectively anymore, the tags
    /// can be changed to separate the old and new data and prevent them from conflicting.
    fn platform_tags() -> Vec<Tag>;

    async fn run_tests<'a, I>(
        test_cases: I,
        jobs: u16,
    ) -> Result<CommitCoverageData<Self::TI, Self::CI>, RunTestsErrors>
    where
        I: IntoIterator<Item = &'a Self::CTI>,
        Self::CTI: 'a;

    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<Self::TI>,
        eval_target_changed_files: &HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<Self::TI, Self::CI>,
    ) -> Result<PlatformSpecificRelevantTestCaseData<Self::TI, Self::CI>>;

    fn analyze_changed_files(
        changed_files: &HashSet<PathBuf>,
        coverage_data: &mut CommitCoverageData<Self::TI, Self::CI>,
    ) -> Result<()>;

    fn get_function_hashes();
}
