// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_std::task;
use log::debug;
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;
use url::Url;

use crate::{
    coverage::ResultWithContext as _, platform::TestIdentifier,
    server::coverage_data::PostCoverageDataRequest,
};

use super::{
    commit_coverage_data::{CommitCoverageData, CoverageIdentifier},
    full_coverage_data::FullCoverageData,
    CoverageDatabase, CoverageDatabaseDetailedError, CoverageDatabaseError, CreateDatabaseError,
    Tag,
};

pub struct TesttrimApiCoverageDatabase<TI: TestIdentifier, CI: CoverageIdentifier> {
    api_url: Url,
    project_name: String,
    test_identifier_type: PhantomData<TI>,
    coverage_identifier_type: PhantomData<CI>,
}

impl From<surf::Error> for CoverageDatabaseError {
    fn from(value: surf::Error) -> Self {
        CoverageDatabaseError::DatabaseError(value.to_string())
    }
}

impl From<url::ParseError> for CoverageDatabaseError {
    fn from(value: url::ParseError) -> Self {
        CoverageDatabaseError::DatabaseError(value.to_string())
    }
}

impl<TI, CI> TesttrimApiCoverageDatabase<TI, CI>
where
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
{
    pub fn new(
        api_url: &str,
        project_name: String,
        platform_identifier: &str,
    ) -> Result<TesttrimApiCoverageDatabase<TI, CI>, CreateDatabaseError> {
        let mut url = Url::parse(api_url)
            .context("parse configured API URL")
            .map_err(|e| {
                CreateDatabaseError::InvalidConfiguration(format!(
                    "testtrim API URL parse error: {e}",
                ))
            })?;
        url.path_segments_mut()
            .map_err(|()| {
                CreateDatabaseError::InvalidConfiguration(String::from(
                    "testtrim API URL is bad; cannot append segments",
                ))
            })?
            .push("api")
            .push("v0")
            .push(platform_identifier)
            .push("coverage-data");

        Ok(TesttrimApiCoverageDatabase {
            api_url: url,
            project_name,
            test_identifier_type: PhantomData,
            coverage_identifier_type: PhantomData,
        })
    }
}

impl<TI, CI> CoverageDatabase<TI, CI> for TesttrimApiCoverageDatabase<TI, CI>
where
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
{
    fn save_coverage_data(
        &mut self,
        coverage_data: &CommitCoverageData<TI, CI>,
        commit_identifier: &str,
        ancestor_commit_identifier: Option<&str>,
        tags: &[Tag],
    ) -> Result<(), CoverageDatabaseDetailedError> {
        // FIXME: use zstd request body compression

        task::block_on(async {
            let mut url = self.api_url.clone();
            url.path_segments_mut()
                .map_err(|()| {
                    CoverageDatabaseError::ParsingError(String::from(
                        "testtrim API URL is bad; cannot append segments",
                    ))
                })
                .context("parse configured API URL")?
                .push(&self.project_name)
                .push(commit_identifier);

            debug!("HTTP request POST {url}");
            let mut response = surf::post(url)
                .body_json(&PostCoverageDataRequest {
                    ancestor_commit_identifier: ancestor_commit_identifier.map(String::from),
                    tags: tags.to_vec(),
                    all_existing_test_set: coverage_data.existing_test_set().clone(),
                    executed_test_set: coverage_data.executed_test_set().clone(),
                    executed_test_to_files_map: coverage_data.executed_test_to_files_map().clone(),
                    executed_test_to_functions_map: coverage_data
                        .executed_test_to_functions_map()
                        .clone(),
                    executed_test_to_coverage_identifier_map: coverage_data
                        .executed_test_to_coverage_identifier_map()
                        .clone(),
                    file_references_files_map: coverage_data.file_references_files_map().clone(),
                })
                .context("serializing body for coverage data POST")?
                .await
                .context("sending request for coverage data POST")?;

            debug!("HTTP response: {response:?}");
            if response.status() != 200 {
                return Err(CoverageDatabaseError::DatabaseError(format!(
                    "remote server returned unexpected status {}",
                    response.status()
                )))
                .context("reading response for coverage data POST");
            }

            let body = response
                .body_json::<Option<String>>()
                .await
                .context("parsing response body for coverage data POST")?;

            Ok::<_, CoverageDatabaseDetailedError>(body)
        })?;

        Ok(())
    }

    fn read_coverage_data(
        &mut self,
        commit_identifier: &str,
        tags: &[Tag],
    ) -> Result<Option<FullCoverageData<TI, CI>>, CoverageDatabaseDetailedError> {
        // FIXME: use zstd response body compression

        let resp = task::block_on(async {
            let mut url = self.api_url.clone();
            url.path_segments_mut()
                .map_err(|()| {
                    CoverageDatabaseError::ParsingError(String::from(
                        "testtrim API URL is bad; cannot append segments",
                    ))
                })
                .context("parse configured API URL")?
                .push(&self.project_name)
                .push(commit_identifier);
            {
                let mut mutator = url.query_pairs_mut();
                mutator.clear();
                for tag in tags {
                    mutator.append_pair(&tag.key, &tag.value);
                }
            }
            debug!("HTTP request GET {url}");
            let mut response = surf::get(url)
                .await
                .context("sending request for coverage data GET")?;

            debug!("HTTP response: {response:?}");
            if response.status() != 200 {
                return Err(CoverageDatabaseError::DatabaseError(format!(
                    "remote server returned unexpected status {}",
                    response.status()
                )))
                .context("reading response for coverage data GET");
            }

            let body = response
                .body_json::<Option<FullCoverageData<TI, CI>>>()
                .await
                .context("parsing response body for coverage data GET")?;

            debug!("HTTP response deserialized: {body:?}");
            Ok::<_, CoverageDatabaseDetailedError>(body)
        })?;

        Ok(resp)
    }

    fn has_any_coverage_data(&mut self) -> Result<bool, CoverageDatabaseDetailedError> {
        let resp = task::block_on(async {
            let mut url = self.api_url.clone();
            url.path_segments_mut()
                .map_err(|()| {
                    CoverageDatabaseError::ParsingError(String::from(
                        "testtrim API URL is bad; cannot append segments",
                    ))
                })
                .context("parse configured API URL")?
                .push(&self.project_name);
            debug!("HTTP request GET {url}");
            let mut response = surf::get(url)
                .await
                .context("sending request for coverage data GET")?;

            debug!("HTTP response: {response:?}");
            if response.status() != 200 {
                return Err(CoverageDatabaseError::DatabaseError(format!(
                    "remote server returned unexpected status {}",
                    response.status()
                )))
                .context("reading response for coverage data GET");
            }

            let body = response
                .body_json::<bool>()
                .await
                .context("parsing response body for coverage data GET")?;

            debug!("HTTP response deserialized: {body:?}");

            Ok::<_, CoverageDatabaseDetailedError>(body)
        })?;
        Ok(resp)
    }

    fn clear_project_data(&mut self) -> Result<(), CoverageDatabaseDetailedError> {
        task::block_on(async {
            let mut url = self.api_url.clone();
            url.path_segments_mut()
                .map_err(|()| {
                    CoverageDatabaseError::ParsingError(String::from(
                        "testtrim API URL is bad; cannot append segments",
                    ))
                })
                .context("parse configured API URL")?
                .push(&self.project_name);
            debug!("HTTP request DELETE {url}");
            let mut response = surf::delete(url)
                .await
                .context("sending request for coverage data DELETE")?;

            debug!("HTTP response: {response:?}");
            if response.status() != 200 {
                return Err(CoverageDatabaseError::DatabaseError(format!(
                    "remote server returned unexpected status {}",
                    response.status()
                )))
                .context("reading response for coverage data DELETE");
            }

            let body = response
                .body_json::<Option<String>>()
                .await
                .context("parsing response body for coverage data DELETE")?;

            Ok::<_, CoverageDatabaseDetailedError>(body)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use actix_test::TestServer;
    use actix_web::{web, App};
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    use crate::{
        coverage::{db_tests, CoverageDatabase},
        platform::{
            rust::{RustCoverageIdentifier, RustTestIdentifier, RustTestPlatform},
            TestPlatform,
        },
        server::InstallTestPlatform as _,
    };

    use super::TesttrimApiCoverageDatabase;

    lazy_static! {
        // Avoid running multiple concurrent tests; assuming they're working well they would conflict on each other with
        // the data being stored and retrieved.  NOTE: The Mutex is ineffective when tests are run in multiple
        // processes; eg. with testtrim, or cargo-nextest -- for nextest they also have to be configured in
        // nextest.toml.
        static ref TEST_MUTEX: Mutex<i32> = Mutex::new(0);
    }

    fn create_test_server() -> TestServer {
        actix_test::start(|| {
            App::new().service(
                web::scope(&format!(
                    "/api/v0/{}",
                    RustTestPlatform::platform_identifier()
                ))
                .platform::<RustTestPlatform>(),
            )
        })
    }

    fn create_test_db() -> (
        TestServer,
        TesttrimApiCoverageDatabase<RustTestIdentifier, RustCoverageIdentifier>,
    ) {
        let srv = create_test_server();
        let url = srv.url("/");
        (
            srv,
            TesttrimApiCoverageDatabase::new(
                &url,
                String::from("testtrim-tests-apibased"),
                RustTestPlatform::platform_identifier(),
            )
            .expect("init must succeed"),
        )
    }

    fn cleanup() {
        let (_srv, mut db) = create_test_db();
        db.clear_project_data()
            .expect("clear_project_data must succeed for test consistency");
    }

    #[test]
    fn has_any_coverage_data_false() {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
            .expect("must config logging");
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::has_any_coverage_data_false(db);
    }

    #[test]
    fn save_empty() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::save_empty(db);
    }

    #[test]
    fn has_any_coverage_data_true() {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
            .expect("must config logging");
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::has_any_coverage_data_true(db);
    }

    #[test]
    fn load_empty() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::load_empty(db);
    }

    #[test]
    fn save_and_load_no_ancestor() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_no_ancestor(db);
    }

    #[test]
    fn save_and_load_new_case_in_child() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_new_case_in_child(db);
    }

    #[test]
    fn save_and_load_replacement_case_in_child() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_replacement_case_in_child(db);
    }

    #[test]
    fn save_and_load_removed_case_in_child() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_removed_case_in_child(db);
    }

    #[test]
    fn remove_file_references_in_child() {
        // simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
        //     .expect("must config logging");
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::remove_file_references_in_child(db);
    }

    #[test]
    fn independent_tags() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup();
        let (_srv, db) = create_test_db();
        db_tests::independent_tags(db);
    }
}
