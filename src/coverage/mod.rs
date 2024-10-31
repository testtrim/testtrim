// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;

use anyhow::Result;
use commit_coverage_data::{CommitCoverageData, CoverageIdentifier};
use full_coverage_data::FullCoverageData;
use postgres_sqlx::PostgresCoverageDatabase;
use serde::{de::DeserializeOwned, Serialize};
use sqlite_diesel::DieselCoverageDatabase;

use crate::platform::TestIdentifier;

pub mod commit_coverage_data;
#[cfg(test)]
mod db_tests;
pub mod full_coverage_data;
pub mod postgres_sqlx;
pub mod sqlite_diesel;

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

pub fn create_db<TI, CI>() -> Box<dyn CoverageDatabase<TI, CI>>
where
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
{
    // FIXME: this probably isn't the right strategy, but for now it causes both of the PG & SQLite code paths to avoid
    // compiler errors about one of them not being referenced, so that's the goal right now
    match env::var("DATABASE_URL") {
        Ok(_db_url) => Box::new(PostgresCoverageDatabase::new()),
        Err(_) => Box::new(DieselCoverageDatabase::new_sqlite_from_default_path()),
    }
}
