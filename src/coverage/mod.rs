// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, fmt};

use anyhow::Result;
use commit_coverage_data::{CommitCoverageData, CoverageIdentifier};
use full_coverage_data::FullCoverageData;
use postgres_sqlx::PostgresCoverageDatabase;
use serde::{de::DeserializeOwned, Serialize};
use sqlite_diesel::DieselCoverageDatabase;
use testtrim_api::TesttrimApiCoverageDatabase;
use thiserror::Error;

use crate::platform::TestIdentifier;

pub mod commit_coverage_data;
#[cfg(test)]
mod db_tests;
pub mod full_coverage_data;
mod postgres_sqlx;
mod sqlite_diesel;
mod tag;
mod testtrim_api;

pub use tag::Tag;

pub trait CoverageDatabase<TI: TestIdentifier, CI: CoverageIdentifier> {
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData<TI, CI>,
        commit_identifier: &str,
        ancestor_commit_identifier: Option<&str>,
        tags: &[Tag],
    ) -> Result<(), CoverageDatabaseDetailedError>;
    fn read_coverage_data(
        &mut self,
        commit_identifier: &str,
        tags: &[Tag],
    ) -> Result<Option<FullCoverageData<TI, CI>>, CoverageDatabaseDetailedError>;
    fn has_any_coverage_data(&mut self) -> Result<bool, CoverageDatabaseDetailedError>;
    fn clear_project_data(&mut self) -> Result<(), CoverageDatabaseDetailedError>;
}

#[derive(Error, Debug)]
pub enum CreateDatabaseError {
    #[error("unsupported database url: `{0}`")]
    UnsupportedDatabaseUrl(String),
    #[error("error managing default SQLite DB: `{0}`")]
    SqliteDefaultDatabaseError(#[from] sqlite_diesel::DefaultDatabaseError),
}

#[derive(Error, Debug)]
pub struct CoverageDatabaseDetailedError {
    pub error: CoverageDatabaseError,
    pub context: Option<String>,
}

impl fmt::Display for CoverageDatabaseDetailedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Some(context) => write!(f, "{} ({})", self.error, context),
            None => write!(f, "{}", self.error),
        }
    }
}

impl CoverageDatabaseDetailedError {
    fn context(self, context: &str) -> CoverageDatabaseDetailedError {
        CoverageDatabaseDetailedError {
            error: self.error,
            context: Some(String::from(context)),
        }
    }
}

impl From<serde_json::Error> for CoverageDatabaseDetailedError {
    fn from(value: serde_json::Error) -> Self {
        CoverageDatabaseDetailedError {
            error: CoverageDatabaseError::DeserializeError(value),
            context: None,
        }
    }
}

trait ResultWithContext<T> {
    fn context(self, context: &str) -> Result<T, CoverageDatabaseDetailedError>;
}

impl<T> ResultWithContext<T> for Result<T, CoverageDatabaseDetailedError> {
    fn context(self, context: &str) -> Result<T, CoverageDatabaseDetailedError> {
        self.map_err(|e| e.context(context))
    }
}

impl<Res, Err> ResultWithContext<Res> for Result<Res, Err>
where
    Err: Into<CoverageDatabaseError>,
{
    fn context(self, context: &str) -> Result<Res, CoverageDatabaseDetailedError> {
        self.map_err(|e| CoverageDatabaseDetailedError {
            error: e.into(),
            context: Some(String::from(context)),
        })
    }
}

#[derive(Error, Debug)]
pub enum CoverageDatabaseError {
    #[error("database error: `{0}`")]
    DatabaseError(String),
    #[error("JSON deserialize error: `{0}`")]
    DeserializeError(#[from] serde_json::Error),
    #[error("data parsing error: `{0}`")]
    ParsingError(String),
}

impl From<CoverageDatabaseError> for CoverageDatabaseDetailedError {
    fn from(value: CoverageDatabaseError) -> Self {
        CoverageDatabaseDetailedError {
            error: value,
            context: None,
        }
    }
}

pub fn create_db<TI, CI>(
    project_name: String,
) -> Result<Box<dyn CoverageDatabase<TI, CI>>, CreateDatabaseError>
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
        Ok(db_url) if db_url.starts_with("http://") || db_url.starts_with("https://") => Ok(
            Box::new(TesttrimApiCoverageDatabase::new(db_url, project_name)),
        ),
        Ok(db_url) => Err(CreateDatabaseError::UnsupportedDatabaseUrl(db_url)),
        Err(_) => Ok(Box::new(
            DieselCoverageDatabase::new_sqlite_from_default_url(project_name)?,
        )),
    }
}
