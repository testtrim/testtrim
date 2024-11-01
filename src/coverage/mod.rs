// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;

use anyhow::{anyhow, Result};
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
mod postgres_sqlx;
mod sqlite_diesel;

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

pub fn create_db<TI, CI>(project_name: String) -> Result<Box<dyn CoverageDatabase<TI, CI>>>
where
    TI: TestIdentifier + Serialize + DeserializeOwned + 'static,
    CI: CoverageIdentifier + Serialize + DeserializeOwned + 'static,
{
    match env::var("TESTTRIM_DATABASE_URL") {
        Ok(db_url) if db_url.starts_with("postgres") => Ok(Box::new(
            PostgresCoverageDatabase::new(db_url, project_name),
        )),
        Ok(db_url) if db_url.starts_with("file://") => Ok(Box::new(
            DieselCoverageDatabase::new_sqlite(db_url, project_name),
        )),
        Ok(db_url) if db_url.starts_with(":memory:") => Ok(Box::new(
            DieselCoverageDatabase::new_sqlite(db_url, project_name),
        )),
        Ok(db_url) => Err(anyhow!("unsupported database url: {db_url}")),
        Err(_) => Ok(Box::new(
            DieselCoverageDatabase::new_sqlite_from_default_url(project_name)?,
        )),
    }
}
