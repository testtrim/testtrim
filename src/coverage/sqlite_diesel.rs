// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    coverage::commit_coverage_data::{
        CommitCoverageData, CoverageIdentifier, FileCoverage, FileReference, FunctionCoverage,
    },
    coverage::full_coverage_data::FullCoverageData,
    platform::TestIdentifier,
};

use anyhow::{anyhow, Context, Result};
use diesel::{
    connection::{Instrumentation, SimpleConnection as _},
    prelude::*,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use log::trace;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::{uuid, Uuid};

use super::CoverageDatabase;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./db/sqlite/migrations");
const DEFAULT_PROJECT_ID: Uuid = uuid!("b4574300-9d65-4099-8383-1e1d9f69254e");

struct DbLogger;

impl Instrumentation for DbLogger {
    fn on_connection_event(&mut self, event: diesel::connection::InstrumentationEvent<'_>) {
        trace!("DB event: {:?}", event);
    }
}

pub struct DieselCoverageDatabase<TI: TestIdentifier, CI: CoverageIdentifier> {
    database_url: String,
    connection: Option<SqliteConnection>,
    test_identifier_type: PhantomData<TI>,
    coverage_identifier_type: PhantomData<CI>,
}

impl<
        TI: TestIdentifier + Serialize + DeserializeOwned,
        CI: CoverageIdentifier + Serialize + DeserializeOwned,
    > DieselCoverageDatabase<TI, CI>
{
    pub fn new_sqlite_from_default_path() -> DieselCoverageDatabase<TI, CI> {
        // FIXME: hard-coded... ideally this could be overriden by CLI and ENV var and use different DBs, but this is a stopgap
        DieselCoverageDatabase::new_sqlite(
            // FIXME: ~/testtrim.db is clearly a bad place
            &Path::join(
                Path::new(&std::env::var_os("HOME").expect("HOME env var")),
                "testtrim.db",
            )
            .to_string_lossy(),
        )
    }

    pub fn new_sqlite(path: &str) -> DieselCoverageDatabase<TI, CI> {
        DieselCoverageDatabase {
            database_url: String::from(path),
            connection: None,
            test_identifier_type: PhantomData,
            coverage_identifier_type: PhantomData,
        }
    }

    fn get_connection(&mut self) -> Result<&mut SqliteConnection> {
        // Check if the connection already exists
        if self.connection.is_none() {
            // Create a new connection if it doesn't exist
            let mut connection = SqliteConnection::establish(&self.database_url)
                .context("connecting to the database")?;
            connection.set_instrumentation(DbLogger {});

            connection.batch_execute(
                "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = OFF; -- don't fsync; let OS handle it
            PRAGMA wal_autocheckpoint = 1000;
            PRAGMA wal_checkpoint(TRUNCATE);
            ",
            )?;
            // FIXME: maybe enable foreign_keys -- but would have a performance hit so it might not be important for now

            self.connection = Some(connection);
        }

        // Unwrap is safe here because we've ensured it's `Some`
        Ok(self.connection.as_mut().unwrap())
    }

    fn save_test_case_file_coverage(
        conn: &mut SqliteConnection,
        test_case_execution_id: &Uuid,
        test_case: &TI,
        coverage_data: &CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        use crate::schema::test_case_file_covered;

        if let Some(files_covered) = coverage_data.executed_test_to_files_map().get(test_case) {
            let mut tuples = vec![];
            for tc in files_covered {
                tuples.push((
                    test_case_file_covered::dsl::test_case_execution_id
                        .eq(test_case_execution_id.to_string()),
                    test_case_file_covered::dsl::file_identifier.eq(tc.to_string_lossy()), // FIXME: lossy?
                ));
            }
            for chunk in tuples.chunks(10000) {
                // HACK: avoid "too many SQL variables"
                diesel::insert_into(test_case_file_covered::dsl::test_case_file_covered)
                    .values(chunk)
                    .execute(conn)
                    .context("bulk insert into test_case_file_covered")?;
            }
        }

        Ok(())
    }

    fn save_test_case_function_coverage(
        conn: &mut SqliteConnection,
        test_case_execution_id: &Uuid,
        test_case: &TI,
        coverage_data: &CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        use crate::schema::test_case_function_covered;

        if let Some(functions_covered) = coverage_data
            .executed_test_to_functions_map()
            .get(test_case)
        {
            let mut tuples = vec![];
            for tc in functions_covered {
                tuples.push((
                    test_case_function_covered::dsl::test_case_execution_id
                        .eq(test_case_execution_id.to_string()),
                    test_case_function_covered::dsl::function_identifier.eq(tc),
                ));
            }
            for chunk in tuples.chunks(10000) {
                // HACK: avoid "too many SQL variables"
                diesel::insert_into(test_case_function_covered::dsl::test_case_function_covered)
                    .values(chunk)
                    .execute(conn)
                    .context("bulk insert into test_case_function_covered")?;
            }
        }

        Ok(())
    }

    fn save_test_case_coverage_identifiers(
        conn: &mut SqliteConnection,
        test_case_execution_id: &Uuid,
        test_case: &TI,
        coverage_data: &CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        use crate::schema::test_case_coverage_identifier_covered;

        if let Some(coverage_identifiers) = coverage_data
            .executed_test_to_coverage_identifier_map()
            .get(test_case)
        {
            let mut tuples = vec![];
            for tc in coverage_identifiers {
                tuples.push((
                    test_case_coverage_identifier_covered::dsl::test_case_execution_id
                        .eq(test_case_execution_id.to_string()),
                    test_case_coverage_identifier_covered::dsl::coverage_identifier
                        .eq(serde_json::to_string(&tc)?),
                ));
            }
            for chunk in tuples.chunks(10000) {
                // HACK: avoid "too many SQL variables"
                diesel::insert_into(test_case_coverage_identifier_covered::dsl::test_case_coverage_identifier_covered)
                    .values(chunk)
                    .execute(conn)
                    .context("bulk insert into test_case_coverage_identifier_covered")?;
            }
        }

        Ok(())
    }

    /// Now we build a comprehensive full test map by reading the ancestor commit's `coverage_map_test_case_executed`,
    /// and replacing any test cases in it from the commit that we just ran.  If there was no ancestor commit test map,
    /// then our current test suite should-be/must-be complete and we use that for `coverage_map_test_case_executed`.
    ///
    /// Hypothetically this entire operation could be done DB-side with a few commands, but:
    /// - `SQLite` doesn't have a server-side UUID generate function, preventing this from working with creating new IDs
    ///   in the denormalized tables
    /// - It's moderately complex to do in SQL, and when operating through the wet-noodle of a query builder it's even
    ///   more complex
    fn save_coverage_map(
        conn: &mut SqliteConnection,
        scm_commit_id: Uuid,
        ancestor_scm_commit_id: Option<&String>,
        test_case_id_to_test_case_map: &HashMap<Uuid, &TI>,
        test_case_to_test_case_id_map: &HashMap<&TI, Uuid>,
        test_case_to_test_case_execution_id_map: &HashMap<&TI, Uuid>,
        coverage_data: &CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        use crate::schema::{
            commit_file_reference, coverage_map, coverage_map_test_case_executed,
            test_case_execution,
        };

        let coverage_map_id = Uuid::new_v4();
        diesel::insert_into(coverage_map::dsl::coverage_map)
            .values((
                coverage_map::dsl::id.eq(coverage_map_id.to_string()),
                coverage_map::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
            ))
            .execute(conn)
            .context("insert into coverage_map")?;

        #[derive(Queryable, Selectable)]
        #[diesel(table_name = crate::schema::test_case_execution)]
        struct TestCaseExecution {
            id: String,
            test_case_id: String,
        }
        let ancestor_test_cases: Option<Vec<TestCaseExecution>> = match ancestor_scm_commit_id {
            Some(ref ancestor_scm_commit_id) => {
                let scm_commit_id = coverage_map::dsl::coverage_map
                    .inner_join(
                        coverage_map_test_case_executed::dsl::coverage_map_test_case_executed
                            .inner_join(test_case_execution::dsl::test_case_execution),
                    )
                    .filter(coverage_map::dsl::scm_commit_id.eq(ancestor_scm_commit_id))
                    .select(TestCaseExecution::as_select())
                    .get_results(conn)
                    .context("loading coverage_map_test_case_executed from ancestor_commit_sha")?;
                Some(scm_commit_id)
            }
            None => None,
        };
        let ancestor_test_cases = ancestor_test_cases.unwrap_or_default();

        let mut coverage_map_test_case_executed = HashMap::new();
        // Insert all the ancestor test executions.
        for test_case_execution in ancestor_test_cases {
            // Even if it's part of the ancestor commit, if it doesn't exist anymore in this commit let's not copy it
            // forward; this indicates a test case removed since the ancestor.
            if test_case_id_to_test_case_map
                .contains_key(&Uuid::parse_str(&test_case_execution.test_case_id)?)
            {
                coverage_map_test_case_executed
                    .insert(test_case_execution.test_case_id, test_case_execution.id);
            }
        }
        // Overwrite with all the test executions that we stored in this commit.
        for tc in coverage_data.executed_test_set() {
            let test_case_id = test_case_to_test_case_id_map
                .get(tc)
                .expect("populated earlier");
            let test_case_execution_id = test_case_to_test_case_execution_id_map
                .get(&tc)
                .expect("populated earlier");
            coverage_map_test_case_executed
                .insert(test_case_id.to_string(), test_case_execution_id.to_string());
        }

        let mut insertables = vec![];
        for test_case_execution_id in coverage_map_test_case_executed.values() {
            insertables.push((
                coverage_map_test_case_executed::dsl::coverage_map_id
                    .eq(coverage_map_id.to_string()),
                coverage_map_test_case_executed::dsl::test_case_execution_id
                    .eq(test_case_execution_id),
            ));
        }
        for chunk in insertables.chunks(10000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(
                coverage_map_test_case_executed::dsl::coverage_map_test_case_executed,
            )
            .values(chunk)
            .execute(conn)
            .context("insert into coverage_map_test_case_executed")?;
        }

        #[derive(Queryable, Selectable, Debug)]
        #[diesel(table_name = crate::schema::commit_file_reference)]
        struct CommitFileReference {
            referencing_filepath: String,
            target_filepath: String,
        }
        let ancestor_file_references: Option<Vec<CommitFileReference>> =
            match ancestor_scm_commit_id {
                Some(ref ancestor_scm_commit_id) => {
                    let scm_commit_id = commit_file_reference::dsl::commit_file_reference
                        .filter(
                            commit_file_reference::dsl::scm_commit_id.eq(ancestor_scm_commit_id),
                        )
                        .select(CommitFileReference::as_select())
                        .order(commit_file_reference::dsl::referencing_filepath)
                        .get_results(conn)
                        .context("loading commit_file_reference from ancestor_commit_sha")?;
                    Some(scm_commit_id)
                }
                None => None,
            };
        let ancestor_file_references = ancestor_file_references.unwrap_or_default();
        let mut file_references_map: HashMap<String, Vec<String>> = HashMap::new();
        for anc in ancestor_file_references {
            file_references_map
                .entry(anc.referencing_filepath)
                .or_default()
                .push(anc.target_filepath);
        }
        // Overwrite file_references_map with any data that is in coverage_data; if a referencing file is in
        // coverage_data then it is understood to be a complete set of files referenced by that file.
        for (referencing_file, target_files) in coverage_data.file_references_files_map() {
            // FIXME: lossy PathBuf -> String
            let vec = target_files
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect();
            file_references_map.insert(referencing_file.to_string_lossy().to_string(), vec);
        }
        let mut insertables = vec![];
        for (referencing_file, target_files) in file_references_map {
            for target_file in target_files {
                insertables.push((
                    commit_file_reference::dsl::id.eq(Uuid::new_v4().to_string()),
                    commit_file_reference::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                    commit_file_reference::dsl::referencing_filepath.eq(referencing_file.clone()),
                    commit_file_reference::dsl::target_filepath.eq(target_file),
                ));
            }
        }
        for chunk in insertables.chunks(10000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(commit_file_reference::dsl::commit_file_reference)
                .values(chunk)
                .execute(conn)
                .context("insert into commit_file_reference")?;
        }

        Ok(())
    }
}

impl<
        TI: TestIdentifier + Serialize + DeserializeOwned,
        CI: CoverageIdentifier + Serialize + DeserializeOwned,
    > CoverageDatabase<TI, CI> for DieselCoverageDatabase<TI, CI>
{
    // impl CoverageDatabase<TI, CI> for DieselCoverageDatabase {
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData<TI, CI>,
        commit_sha: &str,
        ancestor_commit_sha: Option<&str>,
    ) -> Result<()> {
        use crate::schema::{
            commit_test_case, commit_test_case_executed, project, scm_commit, test_case,
            test_case_execution,
        };

        let conn = self.get_connection()?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

        // FIXME: ideally all of this should happen in a transaction, but I'm not sure it matters for SQLite

        let project_id = DEFAULT_PROJECT_ID;
        diesel::insert_into(project::dsl::project)
            .values(project::dsl::id.eq(project_id.to_string()))
            .on_conflict(project::dsl::id)
            .do_nothing()
            .execute(conn)
            .context("upsert into project")?;

        // In case this was a "re-run" on a commit, delete the old associated data.  Ideally this delete should
        // cascade...
        //
        // FIXME: does cascade delete require PRAGMA foreign_keys = ON?
        diesel::delete(
            scm_commit::dsl::scm_commit.filter(scm_commit::dsl::scm_identifier.eq(commit_sha)),
        )
        .execute(conn)
        .context("delete from scm_commit")?;

        let ancestor_scm_commit_id: Option<String> = match ancestor_commit_sha {
            Some(ancestor_commit_sha) => {
                let scm_commit_id = scm_commit::dsl::scm_commit
                    .filter(scm_commit::dsl::scm_identifier.eq(ancestor_commit_sha))
                    .select(scm_commit::dsl::id)
                    .get_result::<String>(conn)
                    .context("loading scm_commit from ancestor_commit_sha")?;
                Some(scm_commit_id)
            }
            None => None,
        };

        let scm_commit_id = Uuid::new_v4();
        diesel::insert_into(scm_commit::dsl::scm_commit)
            .values((
                scm_commit::dsl::id.eq(scm_commit_id.to_string()),
                scm_commit::dsl::project_id.eq(project_id.to_string()),
                scm_commit::dsl::ancestor_scm_commit_id.eq(&ancestor_scm_commit_id),
                scm_commit::dsl::scm_identifier.eq(commit_sha),
            ))
            .execute(conn)
            .context("insert into scm_commit")?;

        let mut test_case_to_test_case_id_map = HashMap::new();
        let mut test_case_id_to_test_case_map = HashMap::new();
        let mut test_case_to_test_case_execution_id_map = HashMap::new();

        #[derive(Queryable, Selectable)]
        #[diesel(table_name = crate::schema::test_case)]
        struct TestCase {
            id: String,
            test_identifier: String,
        }
        let project_test_cases = test_case::dsl::test_case
            .filter(test_case::dsl::project_id.eq(project_id.to_string()))
            .select(TestCase::as_select())
            .get_results(conn)
            .context("loading project_test_cases")?;
        for project_test_case in project_test_cases {
            let test_identifier: TI = serde_json::from_str(&project_test_case.test_identifier)?;
            if let Some(stored_ti) = coverage_data.existing_test_set().get(&test_identifier) {
                let test_case_id = Uuid::parse_str(&project_test_case.id)?;
                test_case_to_test_case_id_map.insert(stored_ti, test_case_id);
                test_case_id_to_test_case_map.insert(test_case_id, stored_ti);
            }
        }

        let mut insertables = vec![];
        for tc in coverage_data.existing_test_set() {
            if !test_case_to_test_case_id_map.contains_key(tc) {
                // New test identifier...
                let test_case_id = Uuid::new_v4();
                insertables.push((
                    test_case::dsl::id.eq(test_case_id.to_string()),
                    test_case::dsl::project_id.eq(project_id.to_string()),
                    test_case::dsl::test_identifier.eq(serde_json::to_string(&tc)?),
                ));
                test_case_to_test_case_id_map.insert(tc, test_case_id);
                test_case_id_to_test_case_map.insert(test_case_id, tc);
            }
        }
        for chunk in insertables.chunks(10000) {
            diesel::insert_into(test_case::dsl::test_case)
                .values(chunk)
                .execute(conn)
                .context("insert into test_case")?;
        }

        // Batch insert into commit_test_case...
        let mut insertables = vec![];
        for tc in coverage_data.existing_test_set() {
            let test_case_id = test_case_to_test_case_id_map
                .get(tc)
                .expect("populated earlier");
            insertables.push((
                commit_test_case::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                commit_test_case::dsl::test_case_id.eq(test_case_id.to_string()),
            ));
        }
        for chunk in insertables.chunks(10000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(commit_test_case::dsl::commit_test_case)
                .values(chunk)
                .execute(conn)
                .context("insert into commit_test_case")?;
        }

        let mut test_case_execution_insertables = vec![];
        let mut commit_test_case_insertables = vec![];
        for tc in coverage_data.existing_test_set() {
            if coverage_data.executed_test_set().contains(tc) {
                let test_case_id = test_case_to_test_case_id_map
                    .get(tc)
                    .expect("populated earlier");

                let test_case_execution_id = Uuid::new_v4();
                test_case_to_test_case_execution_id_map.insert(tc, test_case_execution_id);
                test_case_execution_insertables.push((
                    test_case_execution::dsl::id.eq(test_case_execution_id.to_string()),
                    test_case_execution::dsl::test_case_id.eq(test_case_id.to_string()),
                ));

                commit_test_case_insertables.push((
                    commit_test_case_executed::dsl::test_case_execution_id
                        .eq(test_case_execution_id.to_string()),
                    commit_test_case_executed::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                ));

                DieselCoverageDatabase::save_test_case_file_coverage(
                    conn,
                    &test_case_execution_id,
                    tc,
                    coverage_data,
                )?;

                DieselCoverageDatabase::save_test_case_function_coverage(
                    conn,
                    &test_case_execution_id,
                    tc,
                    coverage_data,
                )?;

                DieselCoverageDatabase::save_test_case_coverage_identifiers(
                    conn,
                    &test_case_execution_id,
                    tc,
                    coverage_data,
                )?;
            }
        }

        for chunk in test_case_execution_insertables.chunks(10000) {
            diesel::insert_into(test_case_execution::dsl::test_case_execution)
                .values(chunk)
                .execute(conn)
                .context("bulk insert into test_case_execution")?;
        }
        for chunk in commit_test_case_insertables.chunks(10000) {
            diesel::insert_into(commit_test_case_executed::dsl::commit_test_case_executed)
                .values(chunk)
                .execute(conn)
                .context("bulk insert into commit_test_case_executed")?;
        }

        DieselCoverageDatabase::save_coverage_map(
            conn,
            scm_commit_id,
            ancestor_scm_commit_id.as_ref(),
            &test_case_id_to_test_case_map,
            &test_case_to_test_case_id_map,
            &test_case_to_test_case_execution_id_map,
            coverage_data,
        )?;

        Ok(())
    }

    fn read_coverage_data(&mut self, commit_sha: &str) -> Result<Option<FullCoverageData<TI, CI>>> {
        use crate::schema::{
            commit_file_reference, coverage_map, coverage_map_test_case_executed, scm_commit,
            test_case, test_case_coverage_identifier_covered, test_case_execution,
            test_case_file_covered, test_case_function_covered,
        };

        let conn = self.get_connection()?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

        let project_id = DEFAULT_PROJECT_ID;

        let coverage_map_id = coverage_map::dsl::coverage_map
            .inner_join(scm_commit::dsl::scm_commit)
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select(coverage_map::dsl::id)
            .get_result::<String>(conn)
            .optional()
            .context("loading coverage_map_id")?;
        if coverage_map_id.is_none() {
            // This commit doesn't have any data.
            return Ok(None);
        }

        let now = OffsetDateTime::now_utc();
        let now = PrimitiveDateTime::new(now.date(), now.time());
        diesel::update(coverage_map::dsl::coverage_map)
            .set(coverage_map::dsl::last_read_timestamp.eq(now))
            .filter(coverage_map::dsl::id.eq(coverage_map_id.unwrap()))
            .execute(conn)
            .context("update coverage_map.last_read_timestamp")?;

        // FIXME: typing isn't helping us; this type is (test_case_id, test_identifier)
        let all_test_cases = coverage_map::dsl::coverage_map
            .inner_join(scm_commit::dsl::scm_commit)
            .inner_join(
                coverage_map_test_case_executed::dsl::coverage_map_test_case_executed.inner_join(
                    test_case_execution::dsl::test_case_execution
                        .inner_join(test_case::dsl::test_case),
                ),
            )
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select((test_case::dsl::id, test_case::dsl::test_identifier))
            .get_results::<(String, String)>(conn)
            .context("loading test cases from coverage_map for commit_sha")?;

        let mut coverage_data = FullCoverageData::new();

        if all_test_cases.is_empty() {
            // The denormalized coverage data was saved but was empty -- there were no test cases at all.
            return Ok(Some(coverage_data));
        }

        let mut test_case_id_to_test_identifier_map = HashMap::new();
        for (test_case_id, test_identifier) in all_test_cases {
            let test_identifier: TI = serde_json::from_str(&test_identifier)?;
            test_case_id_to_test_identifier_map.insert(test_case_id, test_identifier.clone());
            coverage_data.add_existing_test(test_identifier);
        }

        // FIXME: typing isn't helping us; this type is (test_case_id, file_identifier)
        let all_files_by_test_case = test_case_file_covered::dsl::test_case_file_covered
            .inner_join(test_case_execution::dsl::test_case_execution.inner_join(
                coverage_map_test_case_executed::dsl::coverage_map_test_case_executed.inner_join(
                    coverage_map::dsl::coverage_map.inner_join(scm_commit::dsl::scm_commit),
                ),
            ))
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select((
                test_case_execution::dsl::test_case_id,
                test_case_file_covered::dsl::file_identifier,
            ))
            .get_results::<(String, String)>(conn)
            .context("loading from test_case_file_covered for commit_sha via coverage_map")?;
        for (test_case_id, file_identifier) in all_files_by_test_case {
            coverage_data.add_file_to_test(FileCoverage {
                test_identifier: test_case_id_to_test_identifier_map
                    .get(&test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                file_name: PathBuf::from(file_identifier),
            });
        }

        // FIXME: typing isn't helping us; this type is (test_case_id, function_identifier)
        let all_functions_by_test_case =
            test_case_function_covered::dsl::test_case_function_covered
                .inner_join(
                    test_case_execution::dsl::test_case_execution.inner_join(
                        coverage_map_test_case_executed::dsl::coverage_map_test_case_executed
                            .inner_join(
                                coverage_map::dsl::coverage_map
                                    .inner_join(scm_commit::dsl::scm_commit),
                            ),
                    ),
                )
                .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
                .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
                .select((
                    test_case_execution::dsl::test_case_id,
                    test_case_function_covered::dsl::function_identifier,
                ))
                .get_results::<(String, String)>(conn)
                .context(
                    "loading from test_case_function_covered for commit_sha via coverage_map",
                )?;
        for (test_case_id, function_identifier) in all_functions_by_test_case {
            coverage_data.add_function_to_test(FunctionCoverage {
                test_identifier: test_case_id_to_test_identifier_map
                    .get(&test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                function_name: function_identifier,
            });
        }

        // FIXME: typing isn't helping us; this type is (test_case_id, function_identifier)
        let all_coverage_identifiers_by_test_case = test_case_coverage_identifier_covered::dsl::test_case_coverage_identifier_covered
            .inner_join(test_case_execution::dsl::test_case_execution.inner_join(
                coverage_map_test_case_executed::dsl::coverage_map_test_case_executed.inner_join(
                    coverage_map::dsl::coverage_map.inner_join(scm_commit::dsl::scm_commit),
                ),
            ))
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select((
                test_case_execution::dsl::test_case_id,
                test_case_coverage_identifier_covered::dsl::coverage_identifier,
            ))
            .get_results::<(String, String)>(conn)
            .context("loading from test_case_coverage_identifier_covered for commit_sha via coverage_map")?;
        for (test_case_id, coverage_identifier) in all_coverage_identifiers_by_test_case {
            coverage_data.add_heuristic_coverage_to_test(
                test_case_id_to_test_identifier_map
                    .get(&test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                serde_json::from_str(&coverage_identifier)?,
            );
        }

        #[derive(Queryable, Selectable)]
        #[diesel(table_name = crate::schema::commit_file_reference)]
        struct CommitFileReference {
            referencing_filepath: String,
            target_filepath: String,
        }
        let all_referenced_files = commit_file_reference::dsl::commit_file_reference
            .inner_join(scm_commit::dsl::scm_commit)
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select(CommitFileReference::as_select())
            .get_results::<CommitFileReference>(conn)
            .context("loading from commit_file_reference for commit_sha")?;
        for fr in all_referenced_files {
            coverage_data.add_file_reference(FileReference {
                referencing_file: fr.referencing_filepath.into(),
                target_file: fr.target_filepath.into(),
            });
        }

        Ok(Some(coverage_data))
    }

    fn has_any_coverage_data(&mut self) -> Result<bool> {
        use crate::schema::{coverage_map, scm_commit};

        let conn = self.get_connection()?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

        let project_id = DEFAULT_PROJECT_ID;
        let coverage_map_id = coverage_map::dsl::coverage_map
            .inner_join(scm_commit::dsl::scm_commit)
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .select(coverage_map::dsl::id)
            .limit(1)
            .first::<String>(conn)
            .optional()
            .context("loading denormalized_coverage_map_id")?;

        Ok(coverage_map_id.is_some())
    }

    fn clear_project_data(&mut self) -> Result<()> {
        use crate::schema::{
            commit_test_case, commit_test_case_executed, coverage_map,
            coverage_map_test_case_executed, project, scm_commit, test_case,
            test_case_coverage_identifier_covered, test_case_execution, test_case_file_covered,
            test_case_function_covered,
        };

        let conn = self.get_connection()?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

        diesel::delete(coverage_map_test_case_executed::dsl::coverage_map_test_case_executed)
            .execute(conn)?;
        diesel::delete(coverage_map::dsl::coverage_map).execute(conn)?;
        diesel::delete(
            test_case_coverage_identifier_covered::dsl::test_case_coverage_identifier_covered,
        )
        .execute(conn)?;
        diesel::delete(test_case_file_covered::dsl::test_case_file_covered).execute(conn)?;
        diesel::delete(test_case_function_covered::dsl::test_case_function_covered)
            .execute(conn)?;
        diesel::delete(commit_test_case_executed::dsl::commit_test_case_executed).execute(conn)?;
        diesel::delete(test_case_execution::dsl::test_case_execution).execute(conn)?;
        diesel::delete(commit_test_case::dsl::commit_test_case).execute(conn)?;
        diesel::delete(test_case::dsl::test_case).execute(conn)?;
        diesel::delete(scm_commit::dsl::scm_commit).execute(conn)?;
        diesel::delete(project::dsl::project).execute(conn)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coverage::{commit_coverage_data::CommitCoverageData, db_tests},
        platform::rust::{RustCoverageIdentifier, RustTestIdentifier},
    };

    #[test]
    fn has_any_coverage_data_false() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::has_any_coverage_data_false(db);
    }

    #[test]
    fn save_empty() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::save_empty(db);
    }

    #[test]
    fn has_any_coverage_data_true() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::has_any_coverage_data_true(db);
    }

    #[test]
    fn load_empty() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::load_empty(db);
    }

    #[test]
    fn load_updates_last_read_timestamp() {
        use crate::schema::*;

        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );

        let saved_data = CommitCoverageData::new();
        let result = db.save_coverage_data(&saved_data, "c1", None);
        assert!(result.is_ok());

        {
            let conn = db.get_connection().unwrap();

            let data = coverage_map::dsl::coverage_map
                .inner_join(scm_commit::dsl::scm_commit)
                .select((
                    coverage_map::dsl::id,
                    coverage_map::dsl::last_read_timestamp,
                ))
                .get_result::<(String, Option<PrimitiveDateTime>)>(conn)
                .optional();
            assert!(data.is_ok());
            let data = data.unwrap();
            assert!(data.is_some());
            let data = data.unwrap();
            assert!(data.1.is_none());
        }

        let result = db.read_coverage_data("c1");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());

        {
            let conn = db.get_connection().unwrap();

            let data = coverage_map::dsl::coverage_map
                .inner_join(scm_commit::dsl::scm_commit)
                .select((
                    coverage_map::dsl::id,
                    coverage_map::dsl::last_read_timestamp,
                ))
                .get_result::<(String, Option<PrimitiveDateTime>)>(conn)
                .optional();
            assert!(data.is_ok());
            let data = data.unwrap();
            assert!(data.is_some());
            let data = data.unwrap();
            assert!(data.1.is_some());
        }
    }

    #[test]
    fn save_and_load_no_ancestor() {
        let db = DieselCoverageDatabase::new_sqlite(":memory:");
        db_tests::save_and_load_no_ancestor(db);
    }

    /// Test an additive-only child coverage data set -- no overwrite/replacement of the ancestor
    #[test]
    fn save_and_load_new_case_in_child() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::save_and_load_new_case_in_child(db);
    }

    /// Test a replacement-only child coverage data set -- the same test was run with new coverage data in the child
    #[test]
    fn save_and_load_replacement_case_in_child() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::save_and_load_replacement_case_in_child(db);
    }

    /// Test a child coverage set which indicates a test was removed and no longer present
    #[test]
    fn save_and_load_removed_case_in_child() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::save_and_load_removed_case_in_child(db);
    }

    /// Test that we can remove file references from an ancestor
    #[test]
    fn remove_file_references_in_child() {
        let db = DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
            ":memory:",
        );
        db_tests::remove_file_references_in_child(db);
    }
}
