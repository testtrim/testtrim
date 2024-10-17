// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::{collections::HashSet, fmt::Debug, hash::Hash, path::PathBuf};

use crate::{
    commit_coverage_data::{CommitCoverageData, CoverageIdentifier},
    full_coverage_data::FullCoverageData,
    scm::{Scm, ScmCommit},
};

pub mod rust;

/// TestIdentifier is a machine-independent way to reference a test in a project.  It should contain data such that, if
/// it was serialized to a DB, it could be picked up on another machine and the data would be useable to find and
/// execute the test.
pub trait TestIdentifier: Eq + Hash + Clone + Debug {}

/// Similar to TestIdentifier, but this represents a machine-dependent reference to a test.  ConcreteTestIdentifier is
/// "ready to execute" on the current machine, where TestIdentifier may be missing specific pathing data (for example).
pub trait ConcreteTestIdentifier<TI: TestIdentifier>: Eq + Hash + Clone + Debug {
    fn test_identifier(&self) -> &TI;
}

pub trait TestDiscovery<CTI: ConcreteTestIdentifier<TI>, TI: TestIdentifier> {
    fn all_test_cases(&self) -> &HashSet<CTI>;
    fn map_ti_to_cti(&self, test_identifier: TI) -> Option<CTI>;
}

pub trait TestPlatform<TI, CI, TD, CTI>
where
    TI: TestIdentifier,
    CI: CoverageIdentifier,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
{
    fn discover_tests() -> Result<TD>;

    fn run_tests<'a, I>(test_cases: I) -> Result<CommitCoverageData<TI, CI>>
    where
        I: IntoIterator<Item = &'a CTI>,
        CTI: 'a;

    fn platform_specific_relevant_test_cases<Commit: ScmCommit, MyScm: Scm<Commit>>(
        eval_target_test_cases: &HashSet<TI>,
        eval_target_changed_files: &HashSet<PathBuf>,
        scm: &MyScm,
        ancestor_commit: &Commit,
        coverage_data: &FullCoverageData<TI, CI>,
    ) -> Result<HashSet<TI>>;
}
