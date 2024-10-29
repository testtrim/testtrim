// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    hash::Hash,
    path::PathBuf,
};

use crate::{
    commit_coverage_data::{CommitCoverageData, CoverageIdentifier},
    errors::RunTestsErrors,
    full_coverage_data::FullCoverageData,
    scm::{Scm, ScmCommit},
};

pub mod rust;
mod rust_llvm;

/// `TestIdentifier` is a machine-independent way to reference a test in a project.
///
/// It must contain data such that, if it was serialized between machines, it could be picked up and contain relevant
/// data to find and execute the test on another host.
pub trait TestIdentifier: Eq + Hash + Clone + Debug {}

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

pub struct PlatformSpecificRelevantTestCaseData<TI: TestIdentifier> {
    /// Key data, which additional test cases should be executed
    pub additional_test_cases: HashSet<TI>,

    /// Instrumentation: how many "external dependencies" changed that caused those additional test cases?
    pub external_dependencies_changed: Option<usize>,
}

pub trait TestPlatform<TI, CI, TD, CTI>
where
    TI: TestIdentifier,
    CI: CoverageIdentifier,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
{
    fn discover_tests() -> Result<TD>;

    fn run_tests<'a, I>(
        test_cases: I,
        jobs: u16,
    ) -> Result<CommitCoverageData<TI, CI>, RunTestsErrors>
    where
        I: IntoIterator<Item = &'a CTI>,
        CTI: 'a;

    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<TI>,
        eval_target_changed_files: &HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<TI, CI>,
    ) -> Result<PlatformSpecificRelevantTestCaseData<TI>>;

    fn analyze_changed_files(
        changed_files: &HashSet<PathBuf>,
        coverage_data: &mut CommitCoverageData<TI, CI>,
    ) -> Result<()>;
}
