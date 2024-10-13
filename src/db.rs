use crate::{
    commit_coverage_data::{
        CommitCoverageData, CoverageIdentifier, FileCoverage, FunctionCoverage,
    },
    full_coverage_data::FullCoverageData,
    platform::TestIdentifier,
};

use anyhow::{anyhow, Context, Result};
use diesel::{connection::Instrumentation, prelude::*};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use log::trace;
use serde::{de::DeserializeOwned, Serialize};
use std::hash::Hash;
use std::{
    collections::HashMap,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::{uuid, Uuid};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");
const DEFAULT_PROJECT_ID: Uuid = uuid!("b4574300-9d65-4099-8383-1e1d9f69254e");

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
}

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
        TI: TestIdentifier + Eq + Hash + Serialize + DeserializeOwned,
        CI: CoverageIdentifier + Eq + Hash + Serialize + DeserializeOwned,
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
        use crate::schema::*;

        if let Some(files_covered) = coverage_data.executed_test_to_files_map().get(test_case) {
            let mut tuples = vec![];
            for tc in files_covered {
                tuples.push((
                    test_case_file_covered::dsl::test_case_execution_id
                        .eq(test_case_execution_id.to_string()),
                    test_case_file_covered::dsl::file_identifier.eq(tc.to_string_lossy()), // FIXME: lossy?
                ))
            }
            for chunk in tuples.chunks(1000) {
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
        use crate::schema::*;

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
                ))
            }
            for chunk in tuples.chunks(1000) {
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
        use crate::schema::*;

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
                ))
            }
            for chunk in tuples.chunks(1000) {
                // HACK: avoid "too many SQL variables"
                diesel::insert_into(test_case_coverage_identifier_covered::dsl::test_case_coverage_identifier_covered)
                    .values(chunk)
                    .execute(conn)
                    .context("bulk insert into test_case_coverage_identifier_covered")?;
            }
        }

        Ok(())
    }

    /// Now we build a comprehensive full test map by reading the ancestor commit's coverage_map_test_case_executed, and
    /// replacing any test cases in it from the commit that we just ran.  If there was no ancestor commit test map, then
    /// our current test suite should-be/must-be complete and we use that for coverage_map_test_case_executed.
    ///
    /// Hypothetically this entire operation could be done DB-side with a few commands, but:
    /// - SQLite doesn't have a server-side UUID generate function, preventing this from working with creating new IDs
    ///   in the denormalized tables
    /// - It's moderately complex to do in SQL, and when operating through the wet-noodle of a query builder it's even
    ///   more complex
    fn save_coverage_map(
        conn: &mut SqliteConnection,
        scm_commit_id: Uuid,
        ancestor_scm_commit_id: Option<String>,
        test_case_id_to_test_case_map: &HashMap<Uuid, &TI>,
        test_case_to_test_case_id_map: &HashMap<&TI, Uuid>,
        test_case_to_test_case_execution_id_map: &HashMap<&TI, Uuid>,
        coverage_data: &CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        use crate::schema::*;

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
                    // .inner_join(denormalized_coverage_map::dsl::denormalized_coverage_map)
                    .filter(coverage_map::dsl::scm_commit_id.eq(&ancestor_scm_commit_id))
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
        for (_, test_case_execution_id) in coverage_map_test_case_executed.iter() {
            insertables.push((
                coverage_map_test_case_executed::dsl::coverage_map_id
                    .eq(coverage_map_id.to_string()),
                coverage_map_test_case_executed::dsl::test_case_execution_id
                    .eq(test_case_execution_id),
            ));
        }

        for chunk in insertables.chunks(1000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(
                coverage_map_test_case_executed::dsl::coverage_map_test_case_executed,
            )
            .values(chunk)
            .execute(conn)
            .context("insert into coverage_map_test_case_executed")?;
        }

        Ok(())
    }
}

impl<
        TI: TestIdentifier + Eq + Hash + Clone + Serialize + DeserializeOwned,
        CI: CoverageIdentifier + Eq + Hash + Clone + Serialize + DeserializeOwned,
    > CoverageDatabase<TI, CI> for DieselCoverageDatabase<TI, CI>
{
    // impl CoverageDatabase<TI, CI> for DieselCoverageDatabase {
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData<TI, CI>,
        commit_sha: &str,
        ancestor_commit_sha: Option<&str>,
    ) -> Result<()> {
        use crate::schema::*;

        let conn = self.get_connection()?;
        // FIXME: PRAGMA foreign_keys = ON;

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
        for tc in coverage_data.existing_test_set() {
            let test_case_id: String = diesel::insert_into(test_case::dsl::test_case)
                .values((
                    test_case::dsl::id.eq(Uuid::new_v4().to_string()),
                    test_case::dsl::project_id.eq(project_id.to_string()),
                    test_case::dsl::test_identifier.eq(serde_json::to_string(&tc)?),
                ))
                // This is really what I'd like -- if there's a conflict, ignore it.  But this causes the returning()
                // clause to skip the row, which is no good because I need the test case ID for later inserts.  So...
                // we'll do a pointless on_conflict().do_update().set() which is basically a no-op.  This allows the
                // returning() to work though.
                //
                // .on_conflict((test_case::dsl::project_id, test_case::dsl::test_identifier))
                // .do_nothing()
                .on_conflict((test_case::dsl::project_id, test_case::dsl::test_identifier))
                .do_update()
                .set(test_case::dsl::project_id.eq(project_id.to_string()))
                .returning(test_case::dsl::id)
                .get_result(conn)
                .context("upsert into test_case")?;
            test_case_to_test_case_id_map.insert(tc, Uuid::parse_str(&test_case_id)?);
            test_case_id_to_test_case_map.insert(Uuid::parse_str(&test_case_id)?, tc);

            diesel::insert_into(commit_test_case::dsl::commit_test_case)
                .values((
                    commit_test_case::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                    commit_test_case::dsl::test_case_id.eq(&test_case_id),
                ))
                .execute(conn)
                .context("insert into commit_test_case")?;

            if coverage_data.executed_test_set().contains(tc) {
                let test_case_execution_id = Uuid::new_v4();
                test_case_to_test_case_execution_id_map.insert(tc, test_case_execution_id);
                diesel::insert_into(test_case_execution::dsl::test_case_execution)
                    .values((
                        test_case_execution::dsl::id.eq(test_case_execution_id.to_string()),
                        // test_case_execution::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                        test_case_execution::dsl::test_case_id.eq(&test_case_id),
                    ))
                    .execute(conn)
                    .context("insert into test_case_execution")?;

                diesel::insert_into(commit_test_case_executed::dsl::commit_test_case_executed)
                    .values((
                        commit_test_case_executed::dsl::test_case_execution_id
                            .eq(test_case_execution_id.to_string()),
                        commit_test_case_executed::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                    ))
                    .execute(conn)
                    .context("insert into commit_test_case_executed")?;

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

        DieselCoverageDatabase::save_coverage_map(
            conn,
            scm_commit_id,
            ancestor_scm_commit_id,
            &test_case_id_to_test_case_map,
            &test_case_to_test_case_id_map,
            &test_case_to_test_case_execution_id_map,
            coverage_data,
        )?;

        Ok(())
    }

    fn read_coverage_data(&mut self, commit_sha: &str) -> Result<Option<FullCoverageData<TI, CI>>> {
        use crate::schema::*;

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

        Ok(Some(coverage_data))
    }

    fn has_any_coverage_data(&mut self) -> Result<bool> {
        use crate::schema::*;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commit_coverage_data::{CommitCoverageData, HeuristicCoverage},
        platform::rust::{RustCoverageIdentifier, RustExternalDependency, RustTestIdentifier},
    };
    use lazy_static::lazy_static;

    lazy_static! {
        static ref test1: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
        static ref test2: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test2".to_string(),
            }
        };
        static ref test3: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("sub_module/src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
    }

    #[test]
    fn has_any_coverage_data_false() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );
        let result = db.has_any_coverage_data();
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn save_empty() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );
        let data1 = CommitCoverageData::new();
        let result = db.save_coverage_data(&data1, "c1", None);
        assert!(result.is_ok());
    }

    #[test]
    fn has_any_coverage_data_true() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );
        let data1 = CommitCoverageData::new();
        let result = db.save_coverage_data(&data1, "c1", None);
        assert!(result.is_ok());
        let result = db.has_any_coverage_data();
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn load_empty() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );
        let result = db.read_coverage_data("c1");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
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
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");

        let mut saved_data = CommitCoverageData::new();
        let thiserror = RustCoverageIdentifier::ExternalDependency(RustExternalDependency {
            package_name: String::from("thiserror"),
            version: String::from("0.1"),
        });
        let regex = RustCoverageIdentifier::ExternalDependency(RustExternalDependency {
            package_name: String::from("regex"),
            version: String::from("0.1"),
        });
        // note -- no ancestor, so the only case that makes sense is for all existing tests to be executed tests
        saved_data.add_executed_test(test1.clone());
        saved_data.add_executed_test(test2.clone());
        saved_data.add_executed_test(test3.clone());
        saved_data.add_existing_test(test1.clone());
        saved_data.add_existing_test(test2.clone());
        saved_data.add_existing_test(test3.clone());
        saved_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test1.clone(),
        });
        saved_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test2.clone(),
        });
        saved_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file2.rs"),
            test_identifier: test1.clone(),
        });
        saved_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test1.clone(),
        });
        saved_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test2.clone(),
        });
        saved_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_identifier: test1.clone(),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: test1.clone(),
            coverage_identifier: regex.clone(),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: test2.clone(),
            coverage_identifier: regex.clone(),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: test1.clone(),
            coverage_identifier: thiserror.clone(),
        });

        let result = db.save_coverage_data(&saved_data, "c1", None);
        assert!(result.is_ok());

        let result = db.read_coverage_data("c1");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let loaded_data = result.unwrap();
        assert_eq!(loaded_data.all_tests().len(), 3);
        assert!(loaded_data.all_tests().contains(&test1));
        assert!(loaded_data.all_tests().contains(&test2));
        assert!(loaded_data.all_tests().contains(&test3));
        assert_eq!(loaded_data.file_to_test_map().len(), 2);
        assert_eq!(
            loaded_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            loaded_data
                .file_to_test_map()
                .get(&PathBuf::from("file2.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file2.rs"))
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test2));
        assert_eq!(loaded_data.function_to_test_map().len(), 2);
        assert_eq!(
            loaded_data
                .function_to_test_map()
                .get("func1")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            loaded_data
                .function_to_test_map()
                .get("func2")
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .function_to_test_map()
            .get("func2")
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test2));
        assert_eq!(loaded_data.coverage_identifier_to_test_map().len(), 2);
        assert_eq!(
            loaded_data
                .coverage_identifier_to_test_map()
                .get(&regex)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            loaded_data
                .coverage_identifier_to_test_map()
                .get(&thiserror)
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .coverage_identifier_to_test_map()
            .get(&thiserror)
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .coverage_identifier_to_test_map()
            .get(&regex)
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .coverage_identifier_to_test_map()
            .get(&regex)
            .unwrap()
            .contains(&test2));
    }

    /// Test an additive-only child coverage data set -- no overwrite/replacement of the ancestor
    #[test]
    fn save_and_load_new_case_in_child() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );

        let mut ancestor_data = CommitCoverageData::new();
        ancestor_data.add_executed_test(test1.clone());
        ancestor_data.add_existing_test(test1.clone());
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file2.rs"),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_identifier: test1.clone(),
        });

        let result = db.save_coverage_data(&ancestor_data, "c1", None);
        assert!(result.is_ok());

        let mut child_data = CommitCoverageData::new();
        child_data.add_executed_test(test2.clone());
        child_data.add_existing_test(test1.clone());
        child_data.add_existing_test(test2.clone());
        child_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test2.clone(),
        });
        child_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test2.clone(),
        });

        let result = db.save_coverage_data(&child_data, "c2", Some("c1"));
        assert!(result.is_ok());

        let result = db.read_coverage_data("c2");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let loaded_data = result.unwrap();
        assert_eq!(loaded_data.all_tests().len(), 2);
        assert!(loaded_data.all_tests().contains(&test1));
        assert!(loaded_data.all_tests().contains(&test2));
        assert_eq!(loaded_data.file_to_test_map().len(), 2);
        assert_eq!(
            loaded_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            loaded_data
                .file_to_test_map()
                .get(&PathBuf::from("file2.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file2.rs"))
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test2));
        assert_eq!(loaded_data.function_to_test_map().len(), 2);
        assert_eq!(
            loaded_data
                .function_to_test_map()
                .get("func1")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            loaded_data
                .function_to_test_map()
                .get("func2")
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .function_to_test_map()
            .get("func2")
            .unwrap()
            .contains(&test1));
        assert!(loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test2));
    }

    /// Test a replacement-only child coverage data set -- the same test was run with new coverage data in the child
    #[test]
    fn save_and_load_replacement_case_in_child() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );

        let mut ancestor_data = CommitCoverageData::new();
        ancestor_data.add_executed_test(test1.clone());
        ancestor_data.add_existing_test(test1.clone());
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file2.rs"),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_identifier: test1.clone(),
        });

        let result = db.save_coverage_data(&ancestor_data, "c1", None);
        assert!(result.is_ok());

        let mut child_data = CommitCoverageData::new();
        child_data.add_executed_test(test1.clone());
        child_data.add_existing_test(test1.clone());
        child_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file3.rs"),
            test_identifier: test1.clone(),
        });
        child_data.add_function_to_test(FunctionCoverage {
            function_name: "func3".to_string(),
            test_identifier: test1.clone(),
        });

        let result = db.save_coverage_data(&child_data, "c2", Some("c1"));
        assert!(result.is_ok());

        let result = db.read_coverage_data("c2");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let loaded_data = result.unwrap();
        assert_eq!(loaded_data.all_tests().len(), 1);
        assert!(loaded_data.all_tests().contains(&test1));
        assert_eq!(loaded_data.file_to_test_map().len(), 1);
        assert_eq!(
            loaded_data
                .file_to_test_map()
                .get(&PathBuf::from("file3.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file3.rs"))
            .unwrap()
            .contains(&test1));
        assert_eq!(loaded_data.function_to_test_map().len(), 1);
        assert_eq!(
            loaded_data
                .function_to_test_map()
                .get("func3")
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .function_to_test_map()
            .get("func3")
            .unwrap()
            .contains(&test1));
    }

    /// Test a child coverage set which indicates a test was removed and no longer present
    #[test]
    fn save_and_load_removed_case_in_child() {
        let mut db =
            DieselCoverageDatabase::<RustTestIdentifier, RustCoverageIdentifier>::new_sqlite(
                ":memory:",
            );

        let mut ancestor_data = CommitCoverageData::new();
        ancestor_data.add_executed_test(test1.clone());
        ancestor_data.add_executed_test(test2.clone());
        ancestor_data.add_existing_test(test1.clone());
        ancestor_data.add_existing_test(test2.clone());
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test2.clone(),
        });
        ancestor_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file2.rs"),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test1.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test2.clone(),
        });
        ancestor_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_identifier: test1.clone(),
        });

        let result = db.save_coverage_data(&ancestor_data, "c1", None);
        assert!(result.is_ok());

        // Also an odd case -- we'll give child_data no executed tests just to make sure that no "inner joins" turn
        // into no data.  We should get all the test2 data from the ancestor because we're indicating that it still
        // exists though...
        let mut child_data = CommitCoverageData::new();
        child_data.add_existing_test(test2.clone());

        let result = db.save_coverage_data(&child_data, "c2", Some("c1"));
        assert!(result.is_ok());

        let result = db.read_coverage_data("c2");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let loaded_data = result.unwrap();
        assert_eq!(loaded_data.all_tests().len(), 1);
        assert!(loaded_data.all_tests().contains(&test2));
        assert_eq!(loaded_data.file_to_test_map().len(), 1);
        assert_eq!(
            loaded_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test2));
        assert_eq!(loaded_data.function_to_test_map().len(), 1);
        assert_eq!(
            loaded_data
                .function_to_test_map()
                .get("func1")
                .unwrap()
                .len(),
            1
        );
        assert!(loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test2));
    }
}
