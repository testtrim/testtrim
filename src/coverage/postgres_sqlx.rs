// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use async_std::task;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, Executor, Pool, Postgres, Transaction};
use std::{collections::HashMap, marker::PhantomData, path::PathBuf};
use uuid::Uuid;

use crate::platform::TestIdentifier;

use super::{
    commit_coverage_data::{
        CommitCoverageData, CoverageIdentifier, FileCoverage, FileReference, FunctionCoverage,
    },
    full_coverage_data::FullCoverageData,
    CoverageDatabase,
};

pub struct PostgresCoverageDatabase<TI: TestIdentifier, CI: CoverageIdentifier> {
    database_url: String,
    project_name: String,
    connection: Option<Pool<Postgres>>,
    test_identifier_type: PhantomData<TI>,
    coverage_identifier_type: PhantomData<CI>,
}

type TestCaseToIdMap<'a, TI> = HashMap<&'a TI, Uuid>;
type IdToTestCaseMap<'a, TI> = HashMap<Uuid, &'a TI>;

impl<TI, CI> PostgresCoverageDatabase<TI, CI>
where
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
{
    pub fn new(database_url: String, project_name: String) -> PostgresCoverageDatabase<TI, CI> {
        PostgresCoverageDatabase {
            database_url,
            project_name,
            connection: None,
            test_identifier_type: PhantomData,
            coverage_identifier_type: PhantomData,
        }
    }

    fn get_pool(&mut self) -> Result<&Pool<Postgres>> {
        // Check if the connection already exists
        if self.connection.is_none() {
            let pool = task::block_on(async {
                PgPoolOptions::new()
                    .max_connections(5)
                    .connect(&self.database_url)
                    .await
            })?;
            task::block_on(async { sqlx::migrate!("./db/postgres/migrations").run(&pool).await })?;

            self.connection = Some(pool);
        }

        // Unwrap is safe here because we've ensured it's `Some`
        Ok(self.connection.as_mut().unwrap())
    }

    fn upsert_project<'e, E>(executor: E, project_name: &str) -> Result<Uuid>
    where
        E: Executor<'e, Database = Postgres> + Send,
    {
        let record = task::block_on(async {
            sqlx::query!(
                r"
                    INSERT INTO project (id, name)
                    VALUES (uuid_generate_v4(), $1)
                    ON CONFLICT (name)
                        -- 'do nothing' but returning the record's id rather than omiting row
                        DO UPDATE SET name = EXCLUDED.name
                    RETURNING id
                ",
                project_name
            )
            .fetch_one(executor)
            .await
        })
        .context("upsert into project")?;
        Ok(record.id)
    }

    fn delete_old_commit_data(
        tx: &mut Transaction<'static, Postgres>,
        project_id: &Uuid,
        commit_sha: &str,
    ) -> Result<()> {
        task::block_on(async {
            sqlx::query!(
                r"DELETE FROM scm_commit WHERE scm_identifier = $1 AND project_id = $2",
                Value::String(String::from(commit_sha)),
                project_id,
            )
            .execute(&mut **tx)
            .await
        })
        .context("delete from scm_commit")?;
        Ok(())
    }

    fn load_ancestor_scm_commit_id(
        tx: &mut Transaction<'static, Postgres>,
        project_id: &Uuid,
        ancestor_commit_sha: Option<&str>,
    ) -> Result<Option<Uuid>> {
        match ancestor_commit_sha {
            Some(ancestor_commit_sha) => {
                let scm_commit_id = task::block_on(async {
                    sqlx::query!(
                        r"SELECT id FROM scm_commit WHERE scm_identifier = $1 AND project_id = $2",
                        Value::String(String::from(ancestor_commit_sha)),
                        project_id,
                    )
                    .fetch_one(&mut **tx)
                    .await
                })
                .context("loading scm_commit from ancestor_commit_sha")?;

                Ok(Some(scm_commit_id.id))
            }
            None => Ok(None),
        }
    }

    fn create_scm_commit(
        tx: &mut Transaction<'static, Postgres>,
        project_id: &Uuid,
        ancestor_scm_commit_id: Option<Uuid>,
        commit_sha: &str,
    ) -> Result<Uuid> {
        Ok(task::block_on(async {
            sqlx::query!(
                r"
                    INSERT INTO scm_commit
                        (id, project_id, ancestor_scm_commit_id, scm_identifier)
                    VALUES
                        (uuid_generate_v4(), $1, $2, $3)
                    RETURNING id
                    ",
                project_id,
                ancestor_scm_commit_id,
                Value::String(String::from(commit_sha)),
            )
            .fetch_one(&mut **tx)
            .await
        })
        .context("insert into scm_commit")?
        .id)
    }

    fn load_relevant_test_case_ids<'a>(
        tx: &mut Transaction<'static, Postgres>,
        project_id: &Uuid,
        coverage_data: &'a CommitCoverageData<TI, CI>,
    ) -> Result<(TestCaseToIdMap<'a, TI>, IdToTestCaseMap<'a, TI>)> {
        let mut test_case_to_test_case_id_map = HashMap::new();
        let mut test_case_id_to_test_case_map = HashMap::new();

        let project_test_cases = task::block_on(async {
            sqlx::query!(
                r"
                SELECT test_case.id, test_case.test_identifier
                FROM test_case
                WHERE project_id = $1
                ",
                project_id,
            )
            .fetch_all(&mut **tx)
            .await
        })
        .context("loading project_test_cases")?;
        for project_test_case in project_test_cases {
            let test_identifier: TI = serde_json::from_value(project_test_case.test_identifier)?;
            if let Some(stored_ti) = coverage_data.existing_test_set().get(&test_identifier) {
                let test_case_id = project_test_case.id;
                test_case_to_test_case_id_map.insert(stored_ti, test_case_id);
                test_case_id_to_test_case_map.insert(test_case_id, stored_ti);
            }
        }

        Ok((test_case_to_test_case_id_map, test_case_id_to_test_case_map))
    }

    fn insert_missing_test_cases<'a>(
        tx: &mut Transaction<'static, Postgres>,
        project_id: &Uuid,
        test_case_to_test_case_id_map: &mut HashMap<&'a TI, Uuid>,
        test_case_id_to_test_case_map: &mut HashMap<Uuid, &'a TI>,
        coverage_data: &'a CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        let mut test_case_id_vec = vec![];
        let mut test_case_identifiers_vec = vec![];
        for tc in coverage_data.existing_test_set() {
            if !test_case_to_test_case_id_map.contains_key(tc) {
                // New test identifier...
                let test_case_id = Uuid::new_v4(); // would be neat to move to server-side gen, but, no reason
                test_case_id_vec.push(test_case_id);
                test_case_identifiers_vec.push(serde_json::to_value(tc)?);
                test_case_to_test_case_id_map.insert(tc, test_case_id);
                test_case_id_to_test_case_map.insert(test_case_id, tc);
            }
        }
        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO test_case
                    (id, test_identifier, project_id)
                SELECT
                    *, $1
                FROM
                    UNNEST($2::uuid[], $3::jsonb[])
                ",
                project_id,
                &test_case_id_vec,
                &test_case_identifiers_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into test_case")?;

        Ok(())
    }

    fn insert_commit_test_cases<'a>(
        tx: &mut Transaction<'static, Postgres>,
        scm_commit_id: &Uuid,
        test_case_to_test_case_id_map: &HashMap<&'a TI, Uuid>,
        coverage_data: &'a CommitCoverageData<TI, CI>,
    ) -> Result<()> {
        // Batch insert into commit_test_case...
        let mut test_case_id_vec = vec![];
        for tc in coverage_data.existing_test_set() {
            let test_case_id = test_case_to_test_case_id_map
                .get(tc)
                .expect("populated earlier");
            test_case_id_vec.push(*test_case_id);
        }
        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO commit_test_case
                    (scm_commit_id, test_case_id)
                SELECT
                    $1, *
                FROM
                    UNNEST($2::uuid[])
                ",
                scm_commit_id,
                &test_case_id_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into commit_test_case")?;

        Ok(())
    }

    fn save_normalized_coverage_data<'a>(
        tx: &mut Transaction<'static, Postgres>,
        scm_commit_id: &Uuid,
        test_case_to_test_case_id_map: &HashMap<&'a TI, Uuid>,
        coverage_data: &'a CommitCoverageData<TI, CI>,
    ) -> Result<HashMap<&'a TI, Uuid>> {
        let mut test_case_to_test_case_execution_id_map = HashMap::new();

        let mut insert_test_case_execution_id_vec = vec![];
        let mut insert_test_case_execution_test_case_id_vec = vec![];

        let mut insert_commit_test_case_execution_id_vec = vec![];

        let mut insert_test_case_file_covered_id_vec = vec![];
        let mut insert_test_case_file_covered_file_identifier_vec = vec![];

        let mut insert_test_case_func_covered_id_vec = vec![];
        let mut insert_test_case_func_covered_func_identifier_vec = vec![];

        let mut insert_test_case_ci_covered_id_vec = vec![];
        let mut insert_test_case_ci_covered_cis_vec = vec![];

        for tc in coverage_data.executed_test_set() {
            let test_case_id = test_case_to_test_case_id_map
                .get(tc)
                .expect("populated earlier");

            let test_case_execution_id = Uuid::new_v4();
            test_case_to_test_case_execution_id_map.insert(tc, test_case_execution_id);

            insert_test_case_execution_id_vec.push(test_case_execution_id);
            insert_test_case_execution_test_case_id_vec.push(*test_case_id);
            insert_commit_test_case_execution_id_vec.push(test_case_execution_id);

            if let Some(files_covered) = coverage_data.executed_test_to_files_map().get(tc) {
                for path in files_covered {
                    insert_test_case_file_covered_id_vec.push(test_case_execution_id);
                    insert_test_case_file_covered_file_identifier_vec
                        .push(serde_json::to_value(path.to_string_lossy())?);
                }
            }

            if let Some(funcs_covered) = coverage_data.executed_test_to_functions_map().get(tc) {
                for path in funcs_covered {
                    insert_test_case_func_covered_id_vec.push(test_case_execution_id);
                    insert_test_case_func_covered_func_identifier_vec
                        .push(serde_json::to_value(path)?);
                }
            }

            if let Some(cis_covered) = coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(tc)
            {
                for ci in cis_covered {
                    insert_test_case_ci_covered_id_vec.push(test_case_execution_id);
                    insert_test_case_ci_covered_cis_vec.push(serde_json::to_value(ci)?);
                }
            }
        }

        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO test_case_execution
                    (id, test_case_id)
                SELECT
                    *
                FROM
                    UNNEST($1::uuid[], $2::uuid[])
                ",
                &insert_test_case_execution_id_vec,
                &insert_test_case_execution_test_case_id_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into test_case_execution")?;
        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO commit_test_case_executed
                    (scm_commit_id, test_case_execution_id)
                SELECT
                    $1, *
                FROM
                    UNNEST($2::uuid[])
                ",
                scm_commit_id,
                &insert_commit_test_case_execution_id_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into commit_test_case_executed")?;
        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO test_case_file_covered
                    (test_case_execution_id, file_identifier)
                SELECT
                    *
                FROM
                    UNNEST($1::uuid[], $2::jsonb[])
                ",
                &insert_test_case_file_covered_id_vec,
                &insert_test_case_file_covered_file_identifier_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into test_case_file_covered")?;
        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO test_case_function_covered
                    (test_case_execution_id, function_identifier)
                SELECT
                    *
                FROM
                    UNNEST($1::uuid[], $2::jsonb[])
                ",
                &insert_test_case_func_covered_id_vec,
                &insert_test_case_func_covered_func_identifier_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into test_case_function_covered")?;
        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO test_case_coverage_identifier_covered
                    (test_case_execution_id, coverage_identifier)
                SELECT
                    *
                FROM
                    UNNEST($1::uuid[], $2::jsonb[])
                ",
                &insert_test_case_ci_covered_id_vec,
                &insert_test_case_ci_covered_cis_vec,
            )
            .execute(&mut **tx)
            .await
        })
        .context("insert into test_case_coverage_identifier_covered")?;

        Ok(test_case_to_test_case_execution_id_map)
    }

    fn save_denormalized_coverage_data(
        tx: &mut Transaction<'static, Postgres>,
        scm_commit_id: &Uuid,
        test_case_to_test_case_execution_id_map: &HashMap<&TI, Uuid>,
        ancestor_scm_commit_id: Option<Uuid>,
    ) -> Result<()> {
        let coverage_map_id = task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO coverage_map (id, scm_commit_id)
                VALUES (uuid_generate_v4(), $1)
                RETURNING id
                ",
                scm_commit_id,
            )
            .fetch_one(&mut **tx)
            .await
        })
        .context("insert into coverage_map")?
        .id;

        let mut test_case_execution_id_vec = vec![];
        for tc_id in test_case_to_test_case_execution_id_map.values() {
            test_case_execution_id_vec.push(*tc_id);
        }

        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO coverage_map_test_case_executed
                    (test_case_execution_id, coverage_map_id)
                SELECT
                    *, $1
                FROM
                    UNNEST($2::uuid[])
                ",
                coverage_map_id,
                &test_case_execution_id_vec,
            )
            .execute(&mut **tx)
            .await
        })?;

        if ancestor_scm_commit_id.is_some() {
            task::block_on(async {
                sqlx::query!(
                    r"
                    INSERT INTO coverage_map_test_case_executed
                        (test_case_execution_id, coverage_map_id)
                    SELECT
                        test_case_execution_id, $2
                    FROM
                        coverage_map_test_case_executed
                        INNER JOIN coverage_map ON (coverage_map_test_case_executed.coverage_map_id = coverage_map.id)
                        INNER JOIN test_case_execution ON (coverage_map_test_case_executed.test_case_execution_id = test_case_execution.id)
                    WHERE
                        -- Copy-forward everything from the ancestor commit...
                        coverage_map.scm_commit_id = $1 AND

                        -- Unless the same test_case_id is present on the new coverage map already.
                        NOT EXISTS (
                            SELECT 1 FROM
                                coverage_map_test_case_executed inner_executed
                                INNER JOIN test_case_execution inner_execution ON (inner_executed.test_case_execution_id = inner_execution.id)
                            WHERE
                                inner_executed.coverage_map_id = $2 AND
                                inner_execution.test_case_id = test_case_execution.test_case_id
                        ) AND

                        -- And the test case must be a part of the new commit
                        EXISTS (
                            SELECT 1 FROM
                                commit_test_case ctc
                            WHERE
                                ctc.scm_commit_id = $3
                                AND ctc.test_case_id = test_case_execution.test_case_id
                        )
                    ",
                    ancestor_scm_commit_id,
                    coverage_map_id,
                    scm_commit_id,
                )
                .execute(&mut **tx)
                .await
            })?;
        }

        Ok(())
    }

    fn save_denormalized_file_references(
        tx: &mut Transaction<'static, Postgres>,
        scm_commit_id: &Uuid,
        coverage_data: &CommitCoverageData<TI, CI>,
        ancestor_scm_commit_id: Option<Uuid>,
    ) -> Result<()> {
        let mut referencing_filepath_vec = vec![];
        let mut target_filepath_vec = vec![];
        let mut exclude_ancestor_referencing_files = vec![];
        for (referencing_file, target_files) in coverage_data.file_references_files_map() {
            if target_files.is_empty() && ancestor_scm_commit_id.is_some() {
                // This coverage data parsed `referencing_file` and explicitly found that it has no references -- a very
                // common scenario.  If it previously had references in the ancestor commit, we need to make sure we
                // don't copy those forward because of an absence of overwriting data in this commit.
                exclude_ancestor_referencing_files
                    .push(referencing_file.to_string_lossy().to_string());
            } else {
                for target_file in target_files {
                    referencing_filepath_vec.push(referencing_file.to_string_lossy().to_string());
                    target_filepath_vec.push(target_file.to_string_lossy().to_string());
                }
            }
        }

        task::block_on(async {
            sqlx::query!(
                r"
                INSERT INTO commit_file_reference
                    (referencing_filepath, target_filepath, id, scm_commit_id)
                SELECT
                    *, uuid_generate_v4(), $1
                FROM
                    UNNEST($2::text[], $3::text[])
                ",
                &scm_commit_id,
                &referencing_filepath_vec,
                &target_filepath_vec
            )
            .execute(&mut **tx)
            .await
        })?;

        if ancestor_scm_commit_id.is_some() {
            task::block_on(async {
                sqlx::query!(
                    r"
                    INSERT INTO commit_file_reference
                        (id, scm_commit_id, referencing_filepath, target_filepath)
                    SELECT
                        uuid_generate_v4(), $1, referencing_filepath, target_filepath
                    FROM
                        commit_file_reference
                    WHERE
                        -- Copy-forward everything from the ancestor commit...
                        commit_file_reference.scm_commit_id = $2 AND

                        -- Unless the same referencing_filepath is present on the new commit already.
                        NOT EXISTS (
                            SELECT 1 FROM
                                commit_file_reference inner_reference
                            WHERE
                                inner_reference.scm_commit_id = $1 AND
                                inner_reference.referencing_filepath = commit_file_reference.referencing_filepath
                        ) AND

                         -- Exclude files that are known to have no references in the new commit
                         NOT (referencing_filepath = ANY ($3::text[]))
                    ",
                    scm_commit_id,
                    ancestor_scm_commit_id,
                    &exclude_ancestor_referencing_files,
                )
                .execute(&mut **tx)
                .await
            })?;
        }

        Ok(())
    }

    fn touch_coverage_map(pool: &Pool<Postgres>, coverage_map_id: &Uuid) -> Result<()> {
        task::block_on(async {
            sqlx::query!(
                r"
                UPDATE coverage_map
                SET last_read_timestamp = NOW()
                WHERE id = $1
                ",
                coverage_map_id
            )
            .execute(pool)
            .await
        })
        .context("UPDATE coverage_map")?;
        Ok(())
    }

    fn read_coverage_test_cases(
        pool: &Pool<Postgres>,
        coverage_map_id: &Uuid,
        coverage_data: &mut FullCoverageData<TI, CI>,
        test_case_id_to_test_identifier_map: &mut HashMap<Uuid, TI>,
    ) -> Result<()> {
        let all_test_cases = task::block_on(async {
            sqlx::query!(
                r"
                SELECT
                    test_case.id, test_case.test_identifier
                FROM
                    coverage_map
                    INNER JOIN coverage_map_test_case_executed ON (coverage_map_test_case_executed.coverage_map_id = coverage_map.id)
                    INNER JOIN test_case_execution ON (test_case_execution.id = coverage_map_test_case_executed.test_case_execution_id)
                    INNER JOIN test_case ON (test_case.id = test_case_execution.test_case_id)
                WHERE
                    coverage_map.id = $1
                ",
                coverage_map_id
            )
            .fetch_all(pool)
            .await
        })
        .context("loading test cases from coverage_map")?;

        for record in all_test_cases {
            let test_identifier: TI = serde_json::from_value(record.test_identifier)?;
            test_case_id_to_test_identifier_map.insert(record.id, test_identifier.clone());
            coverage_data.add_existing_test(test_identifier);
        }

        Ok(())
    }

    fn read_file_coverage_data(
        pool: &Pool<Postgres>,
        coverage_map_id: &Uuid,
        coverage_data: &mut FullCoverageData<TI, CI>,
        test_case_id_to_test_identifier_map: &HashMap<Uuid, TI>,
    ) -> Result<()> {
        let all_files_by_test_case = task::block_on(async {
            sqlx::query!(
                r"
                SELECT
                    test_case_execution.test_case_id, test_case_file_covered.file_identifier
                FROM
                    coverage_map
                    INNER JOIN coverage_map_test_case_executed ON (coverage_map_test_case_executed.coverage_map_id = coverage_map.id)
                    INNER JOIN test_case_execution ON (test_case_execution.id = coverage_map_test_case_executed.test_case_execution_id)
                    INNER JOIN test_case_file_covered ON (test_case_file_covered.test_case_execution_id = test_case_execution.id)
                WHERE
                    coverage_map.id = $1
                ",
                coverage_map_id
            )
            .fetch_all(pool)
            .await
        })
        .context("loading from test_case_file_covered for coverage_map")?;
        for record in all_files_by_test_case {
            coverage_data.add_file_to_test(FileCoverage {
                test_identifier: test_case_id_to_test_identifier_map
                    .get(&record.test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                file_name: PathBuf::from(
                    record
                        .file_identifier
                        .as_str()
                        .expect("file_identifier must be json str"),
                ),
            });
        }
        Ok(())
    }

    fn read_function_coverage_data(
        pool: &Pool<Postgres>,
        coverage_map_id: &Uuid,
        coverage_data: &mut FullCoverageData<TI, CI>,
        test_case_id_to_test_identifier_map: &HashMap<Uuid, TI>,
    ) -> Result<()> {
        let all_functions_by_test_case = task::block_on(async {
            sqlx::query!(
                r"
                SELECT
                    test_case_execution.test_case_id, test_case_function_covered.function_identifier
                FROM
                    coverage_map
                    INNER JOIN coverage_map_test_case_executed ON (coverage_map_test_case_executed.coverage_map_id = coverage_map.id)
                    INNER JOIN test_case_execution ON (test_case_execution.id = coverage_map_test_case_executed.test_case_execution_id)
                    INNER JOIN test_case_function_covered ON (test_case_function_covered.test_case_execution_id = test_case_execution.id)
                WHERE
                    coverage_map.id = $1
                ",
                coverage_map_id
            )
            .fetch_all(pool)
            .await
        })
        .context("loading from test_case_function_covered for coverage_map")?;
        for record in all_functions_by_test_case {
            coverage_data.add_function_to_test(FunctionCoverage {
                test_identifier: test_case_id_to_test_identifier_map
                    .get(&record.test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                function_name: String::from(
                    record
                        .function_identifier
                        .as_str()
                        .expect("file_identifier must be json str"),
                ),
            });
        }
        Ok(())
    }

    fn read_coverage_identifier_data(
        pool: &Pool<Postgres>,
        coverage_map_id: &Uuid,
        coverage_data: &mut FullCoverageData<TI, CI>,
        test_case_id_to_test_identifier_map: &HashMap<Uuid, TI>,
    ) -> Result<()> {
        let all_cis_by_test_case = task::block_on(async {
            sqlx::query!(
                r"
                SELECT
                    test_case_execution.test_case_id, test_case_coverage_identifier_covered.coverage_identifier
                FROM
                    coverage_map
                    INNER JOIN coverage_map_test_case_executed ON (coverage_map_test_case_executed.coverage_map_id = coverage_map.id)
                    INNER JOIN test_case_execution ON (test_case_execution.id = coverage_map_test_case_executed.test_case_execution_id)
                    INNER JOIN test_case_coverage_identifier_covered ON (test_case_coverage_identifier_covered.test_case_execution_id = test_case_execution.id)
                WHERE
                    coverage_map.id = $1
                ",
                coverage_map_id
            )
            .fetch_all(pool)
            .await
        })
        .context("loading from test_case_coverage_identifier_covered for coverage_map")?;
        for record in all_cis_by_test_case {
            coverage_data.add_heuristic_coverage_to_test(
                test_case_id_to_test_identifier_map
                    .get(&record.test_case_id)
                    .expect("test_case_id_to_test_identifier_map lookup")
                    .clone(),
                serde_json::from_value(record.coverage_identifier)?,
            );
        }
        Ok(())
    }

    fn read_referenced_file_data(
        pool: &Pool<Postgres>,
        project_id: &Uuid,
        commit_sha: &str,
        coverage_data: &mut FullCoverageData<TI, CI>,
    ) -> Result<()> {
        let all_referenced_files = task::block_on(async {
            sqlx::query!(
                r"
                SELECT
                    referencing_filepath, target_filepath
                FROM
                    commit_file_reference
                    INNER JOIN scm_commit ON (commit_file_reference.scm_commit_id = scm_commit.id)
                WHERE
                    scm_commit.project_id = $1 AND
                    scm_commit.scm_identifier = $2
                ",
                project_id,
                Value::String(String::from(commit_sha)),
            )
            .fetch_all(pool)
            .await
        })
        .context("loading from test_case_coverage_identifier_covered for coverage_map")?;
        for record in all_referenced_files {
            coverage_data.add_file_reference(FileReference {
                referencing_file: record.referencing_filepath.into(),
                target_file: record.target_filepath.into(),
            });
        }
        Ok(())
    }
}

impl<TI, CI> CoverageDatabase<TI, CI> for PostgresCoverageDatabase<TI, CI>
where
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
{
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData<TI, CI>,
        commit_sha: &str,
        ancestor_commit_sha: Option<&str>,
    ) -> anyhow::Result<()> {
        let tx = self.get_pool()?;
        let mut tx = task::block_on(async { tx.begin().await })?;

        let project_id = Self::upsert_project(&mut *tx, &self.project_name)?;
        Self::delete_old_commit_data(&mut tx, &project_id, commit_sha)?;
        let ancestor_scm_commit_id =
            Self::load_ancestor_scm_commit_id(&mut tx, &project_id, ancestor_commit_sha)?;
        let scm_commit_id =
            Self::create_scm_commit(&mut tx, &project_id, ancestor_scm_commit_id, commit_sha)?;

        let (mut test_case_to_test_case_id_map, mut test_case_id_to_test_case_map) =
            Self::load_relevant_test_case_ids(&mut tx, &project_id, coverage_data)?;

        Self::insert_missing_test_cases(
            &mut tx,
            &project_id,
            &mut test_case_to_test_case_id_map,
            &mut test_case_id_to_test_case_map,
            coverage_data,
        )?;

        Self::insert_commit_test_cases(
            &mut tx,
            &scm_commit_id,
            &test_case_to_test_case_id_map,
            coverage_data,
        )?;

        let test_case_to_test_case_execution_id_map = Self::save_normalized_coverage_data(
            &mut tx,
            &scm_commit_id,
            &test_case_to_test_case_id_map,
            coverage_data,
        )?;

        Self::save_denormalized_coverage_data(
            &mut tx,
            &scm_commit_id,
            &test_case_to_test_case_execution_id_map,
            ancestor_scm_commit_id,
        )?;

        Self::save_denormalized_file_references(
            &mut tx,
            &scm_commit_id,
            coverage_data,
            ancestor_scm_commit_id,
        )?;

        task::block_on(async { tx.commit().await })?;

        Ok(())
    }

    fn read_coverage_data(
        &mut self,
        commit_sha: &str,
    ) -> anyhow::Result<Option<FullCoverageData<TI, CI>>> {
        let project_name = self.project_name.clone(); // since pool is a quiet &mut borrow of self for the scope of this func
        let pool = self.get_pool()?;

        let project_id = Self::upsert_project(pool, &project_name)?;

        let coverage_map_id = task::block_on(async {
            sqlx::query!(
                r"
                SELECT coverage_map.id
                FROM
                    coverage_map
                    INNER JOIN scm_commit ON (scm_commit.id = coverage_map.scm_commit_id)
                WHERE
                    scm_commit.project_id = $1 AND
                    scm_commit.scm_identifier = $2
                ",
                project_id,
                Value::String(String::from(commit_sha)),
            )
            .fetch_optional(pool)
            .await
        })
        .context("loading coverage_map_id")?;
        let Some(coverage_map_id) = coverage_map_id else {
            // This commit doesn't have any data.
            return Ok(None);
        };

        Self::touch_coverage_map(pool, &coverage_map_id.id)?;

        let mut coverage_data = FullCoverageData::new();
        let mut test_case_id_to_test_identifier_map = HashMap::new();

        Self::read_coverage_test_cases(
            pool,
            &coverage_map_id.id,
            &mut coverage_data,
            &mut test_case_id_to_test_identifier_map,
        )?;

        if coverage_data.all_tests().is_empty() {
            // The denormalized coverage data was saved but was empty -- there were no test cases at all.
            return Ok(Some(coverage_data));
        }

        Self::read_file_coverage_data(
            pool,
            &coverage_map_id.id,
            &mut coverage_data,
            &test_case_id_to_test_identifier_map,
        )?;

        Self::read_function_coverage_data(
            pool,
            &coverage_map_id.id,
            &mut coverage_data,
            &test_case_id_to_test_identifier_map,
        )?;

        Self::read_coverage_identifier_data(
            pool,
            &coverage_map_id.id,
            &mut coverage_data,
            &test_case_id_to_test_identifier_map,
        )?;

        Self::read_referenced_file_data(pool, &project_id, commit_sha, &mut coverage_data)?;

        Ok(Some(coverage_data))
    }

    fn has_any_coverage_data(&mut self) -> anyhow::Result<bool> {
        let project_name = self.project_name.clone(); // since pool is a quiet &mut borrow of self for the scope of this func
        let pool = self.get_pool()?;

        let project_id = Self::upsert_project(pool, &project_name)?;
        let coverage_map_id = task::block_on(async {
            sqlx::query!(
                r"
                SELECT
                    coverage_map.id
                FROM
                    coverage_map
                    INNER JOIN scm_commit ON (scm_commit.id = coverage_map.scm_commit_id)
                WHERE
                    scm_commit.project_id = $1
                LIMIT 1
                ",
                project_id
            )
            .fetch_optional(pool)
            .await
        })?;

        Ok(coverage_map_id.is_some())
    }

    fn clear_project_data(&mut self) -> anyhow::Result<()> {
        let project_name = self.project_name.clone(); // since pool is a quiet &mut borrow of self for the scope of this func
        let pool = self.get_pool()?;
        task::block_on(async {
            sqlx::query!("DELETE FROM project WHERE name = $1", project_name)
                .execute(pool)
                .await
        })
        .expect("delete in clear_project_data");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_std::task;
    use lazy_static::lazy_static;
    use std::{env, sync::Mutex};

    use crate::{
        coverage::{
            commit_coverage_data::CommitCoverageData, db_tests,
            postgres_sqlx::PostgresCoverageDatabase, CoverageDatabase,
        },
        platform::rust::{RustCoverageIdentifier, RustTestIdentifier},
    };

    lazy_static! {
        // Avoid running multiple concurrent tests that use the external DB.  Note that a Mutex is ineffective when
        // tests are run in multiple processes; eg. with testtrim, or cargo-nextest; so this is kinda an interim
        // solution.
        static ref DB_MUTEX: Mutex<i32> = Mutex::new(0);
    }
    fn create_test_db() -> PostgresCoverageDatabase<RustTestIdentifier, RustCoverageIdentifier> {
        PostgresCoverageDatabase::new(
            env::var("TESTTRIM_DATABASE_URL").unwrap(),
            String::from("testtrim-tests"),
        )
    }

    fn cleanup() {
        task::block_on(async {
            sqlx::query!("DELETE FROM project")
                .execute(create_test_db().get_pool().unwrap())
                .await
        })
        .expect("delete stmt failed");
    }

    #[test]
    fn has_any_coverage_data_false() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::has_any_coverage_data_false(db);
    }

    #[test]
    fn save_empty() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::save_empty(db);
    }

    #[test]
    fn has_any_coverage_data_true() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::has_any_coverage_data_true(db);
    }

    #[test]
    fn load_empty() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::load_empty(db);
    }

    #[test]
    fn load_updates_last_read_timestamp() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();

        let ts_fetcher = |db: &mut PostgresCoverageDatabase<_, _>| {
            let pool = db.get_pool().unwrap();

            let coverage_map = task::block_on(async {
                sqlx::query!(
                    r"
                    SELECT
                        coverage_map.id, coverage_map.last_read_timestamp
                    FROM
                        coverage_map
                        INNER JOIN scm_commit ON (scm_commit.id = coverage_map.scm_commit_id)
                    "
                )
                .fetch_optional(pool)
                .await
            });

            assert!(coverage_map.is_ok());
            let coverage_map = coverage_map.unwrap();
            assert!(coverage_map.is_some());
            let coverage_map = coverage_map.unwrap();
            coverage_map.last_read_timestamp
        };

        let mut db = create_test_db();

        let saved_data = CommitCoverageData::new();
        let result = db.save_coverage_data(&saved_data, "c1", None);
        assert!(result.is_ok());

        let ts = ts_fetcher(&mut db);
        assert!(ts.is_none());

        let result = db.read_coverage_data("c1");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());

        let ts = ts_fetcher(&mut db);
        assert!(ts.is_some());
    }

    #[test]
    fn save_and_load_no_ancestor() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::save_and_load_no_ancestor(db);
    }

    /// Test an additive-only child coverage data set -- no overwrite/replacement of the ancestor
    #[test]
    fn save_and_load_new_case_in_child() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::save_and_load_new_case_in_child(db);
    }

    /// Test a replacement-only child coverage data set -- the same test was run with new coverage data in the child
    #[test]
    fn save_and_load_replacement_case_in_child() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::save_and_load_replacement_case_in_child(db);
    }

    /// Test a child coverage set which indicates a test was removed and no longer present
    #[test]
    fn save_and_load_removed_case_in_child() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::save_and_load_removed_case_in_child(db);
    }

    /// Test that we can remove file references from an ancestor
    #[test]
    fn remove_file_references_in_child() {
        let _db_mutex = DB_MUTEX.lock();
        cleanup();
        let db = create_test_db();
        db_tests::remove_file_references_in_child(db);
    }
}
