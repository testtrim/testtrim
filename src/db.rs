use crate::coverage_map::CoverageData;
use crate::models::CoverageDataModel;
use crate::schema::coverage_data::{self};
use anyhow::{anyhow, Result};
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

pub fn save_coverage_data(coverage_data: &CoverageData, commit_sha: &str) -> Result<()> {
    // FIXME: centralized & flexible database access/storage
    let mut conn = SqliteConnection::establish("test.db")?;

    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

    let model = CoverageDataModel {
        commit_sha: String::from(commit_sha),
        raw_coverage_data: serde_json::to_string(&coverage_data)?,
    };

    diesel::insert_into(coverage_data::table)
        .values(&model)
        .on_conflict(coverage_data::commit_sha)
        .do_update()
        .set(&model)
        .execute(&mut conn)?;

    Ok(())
}

pub fn read_coverage_data(commit_sha: &str) -> Result<Option<CoverageData>> {
    // FIXME: centralized & flexible database access/storage
    let mut conn = SqliteConnection::establish("test.db")?;

    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

    let results = coverage_data::dsl::coverage_data
        .find(commit_sha)
        .select(CoverageDataModel::as_select())
        .first(&mut conn)
        .optional()?;

    Ok(match results {
        Some(model) => serde_json::from_str(&model.raw_coverage_data)?,
        None => None,
    })
}
