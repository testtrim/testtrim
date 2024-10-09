use crate::{
    commit_coverage_data::{
        CommitCoverageData, FileCoverage, FunctionCoverage, RustTestIdentifier,
    },
    full_coverage_data::FullCoverageData,
};
use anyhow::{anyhow, Context, Result};
use diesel::{connection::Instrumentation, prelude::*};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use log::trace;
use std::{collections::HashMap, path::PathBuf};
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::{uuid, Uuid};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");
const DEFAULT_PROJECT_ID: Uuid = uuid!("b4574300-9d65-4099-8383-1e1d9f69254e");

pub trait CoverageDatabase {
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData,
        // FIXME: should take an `impl ScmCommit`?
        commit_sha: &str,
        // FIXME: should take an `impl ScmCommit`?
        ancestor_commit_sha: Option<&str>,
    ) -> Result<()>;
    fn read_coverage_data(&mut self, commit_sha: &str) -> Result<Option<FullCoverageData>>;
    fn has_any_coverage_data(&mut self) -> Result<bool>;
}

struct DbLogger;

impl Instrumentation for DbLogger {
    fn on_connection_event(&mut self, event: diesel::connection::InstrumentationEvent<'_>) {
        trace!("DB event: {:?}", event);
    }
}

pub struct DieselCoverageDatabase {
    database_url: String,
    connection: Option<SqliteConnection>,
}

impl DieselCoverageDatabase {
    pub fn new_sqlite(path: &str) -> DieselCoverageDatabase {
        DieselCoverageDatabase {
            database_url: String::from(path),
            connection: None,
        }
    }

    fn get_connection(&mut self) -> Result<&mut SqliteConnection> {
        // Check if the connection already exists
        if self.connection.is_none() {
            // Create a new connection if it doesn't exist
            let connection = SqliteConnection::establish(&self.database_url)
                .context("connecting to the database")?;
            self.connection = Some(connection);
        }

        // Unwrap is safe here because we've ensured it's `Some`
        Ok(self.connection.as_mut().unwrap())
    }
}

impl CoverageDatabase for DieselCoverageDatabase {
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData,
        commit_sha: &str,
        ancestor_commit_sha: Option<&str>,
    ) -> Result<()> {
        use crate::schema::*;

        let conn = self.get_connection()?;
        // FIXME: PRAGMA foreign_keys = ON;

        conn.set_instrumentation(DbLogger {});

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

        let ancesor_scm_commit_id: Option<String> = match ancestor_commit_sha {
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
                scm_commit::dsl::ancestor_scm_commit_id.eq(&ancesor_scm_commit_id),
                scm_commit::dsl::scm_identifier.eq(commit_sha),
            ))
            .execute(conn)
            .context("insert into scm_commit")?;

        let mut test_case_to_test_case_id_map = HashMap::new();
        let mut test_case_id_to_test_case_map = HashMap::new();
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
            test_case_to_test_case_id_map.insert(tc, test_case_id.clone());
            test_case_id_to_test_case_map.insert(test_case_id.clone(), tc);

            diesel::insert_into(commit_test_case::dsl::commit_test_case)
                .values((
                    commit_test_case::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                    commit_test_case::dsl::test_case_id.eq(&test_case_id),
                ))
                .execute(conn)
                .context("insert into commit_test_case")?;

            if coverage_data.executed_test_set().contains(tc) {
                let test_case_execution_id = Uuid::new_v4();
                diesel::insert_into(test_case_execution::dsl::test_case_execution)
                    .values((
                        test_case_execution::dsl::id.eq(test_case_execution_id.to_string()),
                        test_case_execution::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
                        test_case_execution::dsl::test_case_id.eq(&test_case_id),
                    ))
                    .execute(conn)
                    .context("insert into test_case_execution")?;

                if let Some(files_covered) = coverage_data.executed_test_to_files_map().get(tc) {
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

                if let Some(functions_covered) =
                    coverage_data.executed_test_to_functions_map().get(tc)
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
                        diesel::insert_into(
                            test_case_function_covered::dsl::test_case_function_covered,
                        )
                        .values(chunk)
                        .execute(conn)
                        .context("bulk insert into test_case_function_covered")?;
                    }
                }
            }
        }

        // Now we build a comprehensive full test map by reading the previous commit's test map and overwriting it,
        // test-by-test, with the test map from the commit we just ran.  If there was no previous commit test map, then
        // our current test suite should-be/must-be complete.
        //
        // - copy all the TestCaseExecution from the earlier commit
        // - remove all of those that have the same TestCase as were run in the second commit (could be merged by
        //   avoiding copying as an optimization)
        // - copy in the TestCaseExecution from the second commit
        //
        // Hypothetically this entire operation could be done DB-side with a few commands, but:
        // - SQLite doesn't have a server-side UUID generate function, preventing this from working with creating new
        //   IDs in the denormalized tables
        // - It's moderately complex to do in SQL, and when operating through the wet-noodle of a query builder it's
        //   even more complex

        // FIXME: eventually this will be "too large" to do entirely in-memory like this; it should probably be done
        // DB-side... but then again our strategy in the short-term is also to load this entire map into memory so I
        // guess this is a general scaling problem for the future.

        let denormalized_coverage_map_id = Uuid::new_v4();
        diesel::insert_into(denormalized_coverage_map::dsl::denormalized_coverage_map)
            .values((
                denormalized_coverage_map::dsl::id.eq(denormalized_coverage_map_id.to_string()),
                denormalized_coverage_map::dsl::scm_commit_id.eq(scm_commit_id.to_string()),
            ))
            .execute(conn)
            .context("insert into denormalized_coverage_map")?;

        // FIXME: typing isn't helping us; this type is (denormalized_coverage_map_test_case_id, test_case_id)
        // FIXME: I think denormalized_coverage_map_test_case_id isn't really needed as a return from this?
        let ancestor_test_cases: Option<Vec<(String, String)>> = match ancesor_scm_commit_id {
            Some(ref ancesor_scm_commit_id) => {
                let scm_commit_id =
                    denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case
                        .inner_join(denormalized_coverage_map::dsl::denormalized_coverage_map)
                        .filter(
                            denormalized_coverage_map::dsl::scm_commit_id
                                .eq(&ancesor_scm_commit_id),
                        )
                        .select((
                            denormalized_coverage_map_test_case::dsl::id,
                            denormalized_coverage_map_test_case::dsl::test_case_id,
                        ))
                        .get_results::<(String, String)>(conn)
                        .context("loading denormalized_map_test_case from ancestor_commit_sha")?;
                Some(scm_commit_id)
            }
            None => None,
        };
        let ancestor_test_cases = ancestor_test_cases.unwrap_or_default();

        // FIXME: typing isn't helping us; this type is (test_case_id, file_identifier)
        let ancestor_file_covered: Option<Vec<(String, String)>> = match ancesor_scm_commit_id {
            Some(ref ancesor_scm_commit_id) => {
                let scm_commit_id = denormalized_coverage_map_test_case_file_covered::dsl::denormalized_coverage_map_test_case_file_covered
                        .inner_join(
                            denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case
                            .inner_join(denormalized_coverage_map::dsl::denormalized_coverage_map)
                        )
                        .filter(denormalized_coverage_map::dsl::scm_commit_id.eq(&ancesor_scm_commit_id))
                        .select((
                            denormalized_coverage_map_test_case::dsl::test_case_id,
                            denormalized_coverage_map_test_case_file_covered::dsl::file_identifier
                        ))
                        .get_results::<(String, String)>(conn)
                        .context("loading denormalized_coverage_map_test_case_file_covered from ancestor_commit_sha")?;
                Some(scm_commit_id)
            }
            None => None,
        };
        let mut ancestor_file_covered = ancestor_file_covered.unwrap_or_default();

        // FIXME: typing isn't helping us; this type is (test_case_id, function_identifier)
        let ancestor_function_covered: Option<Vec<(String, String)>> = match ancesor_scm_commit_id {
            Some(ref ancesor_scm_commit_id) => {
                let scm_commit_id = denormalized_coverage_map_test_case_function_covered::dsl::denormalized_coverage_map_test_case_function_covered
                    .inner_join(
                        denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case
                        .inner_join(denormalized_coverage_map::dsl::denormalized_coverage_map)
                    )
                    .filter(denormalized_coverage_map::dsl::scm_commit_id.eq(&ancesor_scm_commit_id))
                    .select((
                        denormalized_coverage_map_test_case::dsl::test_case_id,
                        denormalized_coverage_map_test_case_function_covered::dsl::function_identifier
                    ))
                    .get_results::<(String, String)>(conn)
                    .context("loading denormalized_coverage_map_test_case_function_covered from ancestor_commit_sha")?;
                Some(scm_commit_id)
            }
            None => None,
        };
        let mut ancestor_function_covered = ancestor_function_covered.unwrap_or_default();

        // Remove test cases that aren't valid anymore.
        for (_denormalized_coverage_map_test_case_id, test_case_id) in ancestor_test_cases {
            if !test_case_id_to_test_case_map.contains_key(&test_case_id) {
                // Ancestor had a test case that no longer exists in "all existing test set"; typically this indicates
                // that a test case was removed from the code base.  We don't want to copy that forward forever in the
                // denormalized data -- so trim it out.
                ancestor_file_covered.retain(|(tc_id2, _)| *tc_id2 != test_case_id);
                ancestor_function_covered.retain(|(tc_id2, _)| *tc_id2 != test_case_id);
            }
        }

        // Remove test cases that were executed in coverage_data.
        // Add in the newly covered data.
        for tc in coverage_data.executed_test_set() {
            let tc_id = test_case_to_test_case_id_map
                .get(tc)
                .expect("must have been populated in earlier iteration");
            ancestor_file_covered.retain(|(tc_id2, _)| tc_id2 != tc_id);
            ancestor_function_covered.retain(|(tc_id2, _)| tc_id2 != tc_id);

            if let Some(files_covered) = coverage_data.executed_test_to_files_map().get(tc) {
                for file in files_covered {
                    ancestor_file_covered.push((tc_id.clone(), file.to_string_lossy().to_string()));
                    // FIXME: lossy?
                }
            }
            if let Some(functions_covered) = coverage_data.executed_test_to_functions_map().get(tc)
            {
                for func in functions_covered {
                    ancestor_function_covered.push((tc_id.clone(), func.clone()));
                }
            }
        }

        let mut test_case_to_denormalized_id_map = HashMap::new();
        let mut denormalized_coverage_map_test_case_values = vec![];
        for tc in coverage_data.existing_test_set() {
            let id = Uuid::new_v4();
            test_case_to_denormalized_id_map.insert(tc, id);
            denormalized_coverage_map_test_case_values.push((
                denormalized_coverage_map_test_case::dsl::id.eq(id.to_string()),
                denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_id
                    .eq(denormalized_coverage_map_id.to_string()),
                denormalized_coverage_map_test_case::dsl::test_case_id.eq(
                    test_case_to_test_case_id_map
                        .get(tc)
                        .expect("must have been populated in earlier iteration"),
                ),
            ))
        }
        for chunk in denormalized_coverage_map_test_case_values.chunks(1000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(
                denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case,
            )
            .values(chunk)
            .execute(conn)
            .context("insert into denormalized_coverage_map_test_case")?;
        }

        let mut denormalized_coverage_map_test_case_file_covered_values = vec![];
        for (test_case_id, file_identifier) in ancestor_file_covered {
            let test_case = test_case_id_to_test_case_map
                .get(&test_case_id)
                .expect("test_case_id_to_test_case_map");
            denormalized_coverage_map_test_case_file_covered_values.push((
                denormalized_coverage_map_test_case_file_covered::dsl::denormalized_coverage_map_test_case_id.eq(
                    test_case_to_denormalized_id_map.get(test_case).expect("must have been populated in earlier iteration")
                    .to_string()),
                denormalized_coverage_map_test_case_file_covered::dsl::file_identifier
                    .eq(file_identifier),
            ))
        }
        for chunk in denormalized_coverage_map_test_case_file_covered_values.chunks(1000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(
                denormalized_coverage_map_test_case_file_covered::dsl::denormalized_coverage_map_test_case_file_covered,
            )
            .values(chunk)
            .execute(conn)
            .context("insert into denormalized_coverage_map_test_case_file_covered")?;
        }

        let mut denormalized_coverage_map_test_case_function_covered_values = vec![];
        for (test_case_id, function_identifier) in ancestor_function_covered {
            let test_case = test_case_id_to_test_case_map
                .get(&test_case_id)
                .expect("test_case_id_to_test_case_map");
            denormalized_coverage_map_test_case_function_covered_values.push((
                denormalized_coverage_map_test_case_function_covered::dsl::denormalized_coverage_map_test_case_id.eq(
                    test_case_to_denormalized_id_map.get(test_case).expect("must have been populated in earlier iteration")
                    .to_string()),
                denormalized_coverage_map_test_case_function_covered::dsl::function_identifier
                    .eq(function_identifier),
            ))
        }
        for chunk in denormalized_coverage_map_test_case_function_covered_values.chunks(1000) {
            // HACK: avoid "too many SQL variables"
            diesel::insert_into(
                denormalized_coverage_map_test_case_function_covered::dsl::denormalized_coverage_map_test_case_function_covered,
            )
            .values(chunk)
            .execute(conn)
            .context("insert into denormalized_coverage_map_test_case_function_covered")?;
        }

        Ok(())
    }

    fn read_coverage_data(&mut self, commit_sha: &str) -> Result<Option<FullCoverageData>> {
        use crate::schema::*;

        let conn = self.get_connection()?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

        // FIXME: bump/populate last_read_timestamp in denormalized_coverage_map

        let project_id = DEFAULT_PROJECT_ID;

        let denormalized_coverage_map_id =
            denormalized_coverage_map::dsl::denormalized_coverage_map
                .inner_join(scm_commit::dsl::scm_commit)
                .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
                .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
                .select(denormalized_coverage_map::dsl::id)
                .get_result::<String>(conn)
                .optional()
                .context("loading denormalized_coverage_map_id")?;
        if denormalized_coverage_map_id.is_none() {
            // This commit doesn't have any data.
            return Ok(None);
        }

        let now = OffsetDateTime::now_utc();
        let now = PrimitiveDateTime::new(now.date(), now.time());
        diesel::update(denormalized_coverage_map::dsl::denormalized_coverage_map)
            .set(denormalized_coverage_map::dsl::last_read_timestamp.eq(now))
            .filter(denormalized_coverage_map::dsl::id.eq(denormalized_coverage_map_id.unwrap()))
            .execute(conn)
            .context("update denormalized_coverage_map.last_read_timestamp")?;

        // FIXME: typing isn't helping us; this type is (test_case_id, test_identifier)
        let all_test_cases = denormalized_coverage_map::dsl::denormalized_coverage_map
            .inner_join(scm_commit::dsl::scm_commit)
            .inner_join(
                denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case
                    .inner_join(test_case::dsl::test_case),
            )
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select((test_case::dsl::id, test_case::dsl::test_identifier))
            .get_results::<(String, String)>(conn)
            .context("loading test cases from denormalized_coverage_map for commit_sha")?;

        let mut coverage_data = FullCoverageData::new();

        if all_test_cases.is_empty() {
            // The denormalized coverage data was saved but was empty -- there were no test cases at all.
            return Ok(Some(coverage_data));
        }

        let mut test_case_id_to_test_identifier_map = HashMap::new();
        for (test_case_id, test_identifier) in all_test_cases {
            let test_identifier: RustTestIdentifier = serde_json::from_str(&test_identifier)?;
            test_case_id_to_test_identifier_map.insert(test_case_id, test_identifier.clone());
            coverage_data.add_existing_test(test_identifier);
        }

        // FIXME: typing isn't helping us; this type is (test_case_id, file_identifier)
        let all_files_by_test_case = denormalized_coverage_map_test_case_file_covered::dsl::denormalized_coverage_map_test_case_file_covered
            .inner_join(
                denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case
                .inner_join(
                    denormalized_coverage_map::dsl::denormalized_coverage_map
                    .inner_join(scm_commit::dsl::scm_commit)
                )
            )
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select((denormalized_coverage_map_test_case::dsl::test_case_id, denormalized_coverage_map_test_case_file_covered::dsl::file_identifier))
            .get_results::<(String, String)>(conn)
            .context("loading from denormalized_coverage_map_test_case_file_covered for commit_sha")?;
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
        let all_files_by_test_case = denormalized_coverage_map_test_case_function_covered::dsl::denormalized_coverage_map_test_case_function_covered
            .inner_join(
                denormalized_coverage_map_test_case::dsl::denormalized_coverage_map_test_case
                .inner_join(
                    denormalized_coverage_map::dsl::denormalized_coverage_map
                    .inner_join(scm_commit::dsl::scm_commit)
                )
            )
            .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
            .filter(scm_commit::dsl::scm_identifier.eq(&commit_sha))
            .select((denormalized_coverage_map_test_case::dsl::test_case_id, denormalized_coverage_map_test_case_function_covered::dsl::function_identifier))
            .get_results::<(String, String)>(conn)
            .context("loading from denormalized_coverage_map_test_case_function_covered for commit_sha")?;
        for (test_case_id, function_identifier) in all_files_by_test_case {
            coverage_data.add_function_to_test(FunctionCoverage {
                test_identifier: test_case_id_to_test_identifier_map
                    .get(&test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                function_name: function_identifier,
            });
        }

        Ok(Some(coverage_data))
    }

    fn has_any_coverage_data(&mut self) -> Result<bool> {
        use crate::schema::*;

        let conn = self.get_connection()?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("failed to run pending migrations: {}", e))?;

        let project_id = DEFAULT_PROJECT_ID;
        let denormalized_coverage_map_id =
            denormalized_coverage_map::dsl::denormalized_coverage_map
                .inner_join(scm_commit::dsl::scm_commit)
                .filter(scm_commit::dsl::project_id.eq(project_id.to_string()))
                .select(denormalized_coverage_map::dsl::id)
                .limit(1)
                .first::<String>(conn)
                .optional()
                .context("loading denormalized_coverage_map_id")?;

        Ok(denormalized_coverage_map_id.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit_coverage_data::CommitCoverageData;
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
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");
        let result = db.has_any_coverage_data();
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn save_empty() {
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");
        let data1 = CommitCoverageData::new();
        let result = db.save_coverage_data(&data1, "c1", None);
        assert!(result.is_ok());
    }

    #[test]
    fn has_any_coverage_data_true() {
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");
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
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");
        let result = db.read_coverage_data("c1");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_updates_last_read_timestamp() {
        use crate::schema::*;

        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");

        let saved_data = CommitCoverageData::new();
        let result = db.save_coverage_data(&saved_data, "c1", None);
        assert!(result.is_ok());

        {
            let conn = db.get_connection().unwrap();

            let data = denormalized_coverage_map::dsl::denormalized_coverage_map
                .inner_join(scm_commit::dsl::scm_commit)
                .select((
                    denormalized_coverage_map::dsl::id,
                    denormalized_coverage_map::dsl::last_read_timestamp,
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

            let data = denormalized_coverage_map::dsl::denormalized_coverage_map
                .inner_join(scm_commit::dsl::scm_commit)
                .select((
                    denormalized_coverage_map::dsl::id,
                    denormalized_coverage_map::dsl::last_read_timestamp,
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
        saved_data.add_executed_test(test1.clone());
        saved_data.add_executed_test(test2.clone());
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
    }

    /// Test an additive-only child coverage data set -- no overwrite/replacement of the ancestor
    #[test]
    fn save_and_load_new_case_in_child() {
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");

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
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");

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
        let mut db = DieselCoverageDatabase::new_sqlite(":memory:");

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
