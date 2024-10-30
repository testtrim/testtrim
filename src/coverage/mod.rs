// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use commit_coverage_data::{CommitCoverageData, CoverageIdentifier};
use full_coverage_data::FullCoverageData;

use crate::platform::TestIdentifier;

pub mod commit_coverage_data;
pub mod db;
pub mod full_coverage_data;

pub trait CoverageDatabase<TI: TestIdentifier, CI: CoverageIdentifier> {
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData<TI, CI>,
        // FIXME: should take an `impl ScmCommit`?
        commit_sha: &str,
        // FIXME: should take an `impl ScmCommit`?
        ancestor_commit_sha: Option<&str>,
    ) -> Result<()>;
    fn read_coverage_data(&mut self, commit_sha: &str) -> Result<Option<FullCoverageData<TI, CI>>>;
    fn has_any_coverage_data(&mut self) -> Result<bool>;
    fn clear_project_data(&mut self) -> Result<()>;
}
