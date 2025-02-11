// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, fmt, time::Duration};

use anyhow::Result;
use commit_coverage_data::{CommitCoverageData, CoverageIdentifier};
use enum_dispatch::enum_dispatch;
use full_coverage_data::FullCoverageData;
use log::error;
use postgres_sqlx::PostgresCoverageDatabase;
use serde::{Serialize, de::DeserializeOwned};
use sqlite_diesel::DieselCoverageDatabase;
use testtrim_api::TesttrimApiCoverageDatabase;
use thiserror::Error;

use crate::platform::{TestIdentifier, TestPlatform};

pub mod commit_coverage_data;
#[cfg(test)]
mod db_tests;
pub mod full_coverage_data;
mod postgres_sqlx;
mod sqlite_diesel;
mod tag;
mod testtrim_api;

pub use tag::Tag;

#[enum_dispatch]
#[allow(async_fn_in_trait)] // should be fine to the extent that this is only used internally to this project
pub trait CoverageDatabase {
    async fn save_coverage_data<TP>(
        &self,
        project_name: &str,
        coverage_data: &CommitCoverageData<TP::TI, TP::CI>,
        commit_identifier: &str,
        ancestor_commit_identifier: Option<&str>,
        tags: &[Tag],
    ) -> Result<(), CoverageDatabaseDetailedError>
    where
        TP: TestPlatform,
        TP::TI: TestIdentifier + Serialize + DeserializeOwned,
        TP::CI: CoverageIdentifier + Serialize + DeserializeOwned;

    async fn read_coverage_data<TP>(
        &self,
        project_name: &str,
        commit_identifier: &str,
        tags: &[Tag],
    ) -> Result<Option<FullCoverageData<TP::TI, TP::CI>>, CoverageDatabaseDetailedError>
    where
        TP: TestPlatform,
        TP::TI: TestIdentifier + Serialize + DeserializeOwned,
        TP::CI: CoverageIdentifier + Serialize + DeserializeOwned;

    async fn read_first_available_coverage_data<'a, TP>(
        &self,
        project_name: &str,
        commit_identifiers: &[&'a str],
        tags: &[Tag],
    ) -> Result<Option<(&'a str, FullCoverageData<TP::TI, TP::CI>)>, CoverageDatabaseDetailedError>
    where
        TP: TestPlatform,
        TP::TI: TestIdentifier + Serialize + DeserializeOwned,
        TP::CI: CoverageIdentifier + Serialize + DeserializeOwned,
    {
        for commit_identifier in commit_identifiers {
            let coverage_data = self
                .read_coverage_data::<TP>(project_name, commit_identifier, tags)
                .await?;
            if let Some(coverage_data) = coverage_data {
                return Ok(Some((commit_identifier, coverage_data)));
            }
        }
        Ok(None)
    }

    async fn has_any_coverage_data<TP: TestPlatform>(
        &self,
        project_name: &str,
    ) -> Result<bool, CoverageDatabaseDetailedError>;

    async fn clear_project_data<TP: TestPlatform>(
        &self,
        project_name: &str,
    ) -> Result<(), CoverageDatabaseDetailedError>;

    async fn intermittent_clean(
        &self,
        older_than: &Duration,
    ) -> Result<(), CoverageDatabaseDetailedError>;
}

#[derive(Error, Debug)]
pub enum CreateDatabaseError {
    #[error("unsupported database url: `{0}`")]
    UnsupportedDatabaseUrl(String),
    #[error("error managing default SQLite DB: `{0}`")]
    SqliteDefaultDatabaseError(#[from] sqlite_diesel::DefaultDatabaseError),
    #[error("error with invalid configuration: `{0}`")]
    InvalidConfiguration(String),
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

#[enum_dispatch(CoverageDatabase)]
pub enum CoverageDatabaseDispatch {
    Postgres(PostgresCoverageDatabase),
    Sqlite(DieselCoverageDatabase),
    TesttrimApi(TesttrimApiCoverageDatabase),
}

pub fn create_db() -> Result<CoverageDatabaseDispatch, CreateDatabaseError> {
    match env::var("TESTTRIM_DATABASE_URL") {
        Ok(db_url) if db_url.starts_with("postgres") => {
            Ok(PostgresCoverageDatabase::new(db_url).into())
        }
        Ok(db_url) if db_url.starts_with("file://") => {
            Ok(DieselCoverageDatabase::new_sqlite(db_url).into())
        }
        Ok(db_url) if db_url.starts_with(":memory:") => {
            Ok(DieselCoverageDatabase::new_sqlite(db_url).into())
        }
        Ok(db_url) if db_url.starts_with("http://") || db_url.starts_with("https://") => {
            Ok(TesttrimApiCoverageDatabase::new(&db_url)?.into())
        }
        Ok(db_url) => Err(CreateDatabaseError::UnsupportedDatabaseUrl(db_url)),
        Err(_) => Ok(DieselCoverageDatabase::new_sqlite_from_default_url()?.into()),
    }
}

pub fn create_test_db() -> Result<CoverageDatabaseDispatch, CreateDatabaseError> {
    Ok(DieselCoverageDatabase::new_sqlite(String::from(":memory:")).into())
}

#[must_use]
pub fn create_db_infallible() -> CoverageDatabaseDispatch {
    match create_db() {
        Ok(db) => db,
        Err(e) => {
            error!("Unable to create coverage DB: {e:?}");
            panic!("Unable to create coverage DB: {e:?}");
        }
    }
}
