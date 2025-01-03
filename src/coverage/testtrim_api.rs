// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_compression::tokio::bufread::ZstdEncoder;
use log::{debug, warn};
use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use url::Url;

use crate::{
    coverage::ResultWithContext as _,
    platform::{TestIdentifier, TestPlatform},
    server::coverage_data::PostCoverageDataRequest,
};

use super::{
    CoverageDatabase, CoverageDatabaseDetailedError, CoverageDatabaseError, CreateDatabaseError,
    Tag,
    commit_coverage_data::{CommitCoverageData, CoverageIdentifier},
    full_coverage_data::FullCoverageData,
};

pub struct TesttrimApiCoverageDatabase {
    api_url: Url,
    client: OnceLock<Client>,
}

impl From<reqwest::Error> for CoverageDatabaseError {
    fn from(value: reqwest::Error) -> Self {
        CoverageDatabaseError::DatabaseError(value.to_string())
    }
}

impl From<url::ParseError> for CoverageDatabaseError {
    fn from(value: url::ParseError) -> Self {
        CoverageDatabaseError::DatabaseError(value.to_string())
    }
}

impl TesttrimApiCoverageDatabase {
    pub fn new(api_url: &str) -> Result<TesttrimApiCoverageDatabase, CreateDatabaseError> {
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
            .push("v0");
        // .push(platform_identifier)
        // .push("coverage-data");

        Ok(TesttrimApiCoverageDatabase {
            api_url: url,
            client: OnceLock::new(),
        })
    }

    fn client(&self) -> Result<&Client, CoverageDatabaseDetailedError> {
        self.client.get_or_try_init(|| {
            reqwest::ClientBuilder::new()
                .zstd(true)
                .gzip(true)
                .user_agent(format!("testtrim ({})", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("creating reqwest client for TesttrimApiCoverageDatabase")
        })
    }
}

impl CoverageDatabase for TesttrimApiCoverageDatabase {
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
        TP::CI: CoverageIdentifier + Serialize + DeserializeOwned,
    {
        let mut url = self.api_url.clone();
        url.path_segments_mut()
            .map_err(|()| {
                CoverageDatabaseError::ParsingError(String::from(
                    "testtrim API URL is bad; cannot append segments",
                ))
            })
            .context("parse configured API URL")?
            .push(TP::platform_identifier())
            .push("coverage-data")
            .push(project_name)
            .push(commit_identifier);

        let post_request = PostCoverageDataRequest {
            ancestor_commit_identifier: ancestor_commit_identifier.map(String::from),
            tags: tags.to_vec(),
            all_existing_test_set: coverage_data.existing_test_set().clone(),
            executed_test_set: coverage_data.executed_test_set().clone(),
            executed_test_to_files_map: coverage_data.executed_test_to_files_map().clone(),
            executed_test_to_functions_map: coverage_data.executed_test_to_functions_map().clone(),
            executed_test_to_coverage_identifier_map: coverage_data
                .executed_test_to_coverage_identifier_map()
                .clone(),
            file_references_files_map: coverage_data.file_references_files_map().clone(),
        };
        let post_request = serde_json::to_string(&post_request)?;
        let post_request = post_request.as_bytes();
        debug!("POST request size (uncompressed): {}", post_request.len());

        let start = Instant::now();
        let mut zstd = ZstdEncoder::new(post_request);
        let mut buf = Vec::with_capacity(post_request.len() / 10); // about 1/10 compression ratio expected
        zstd.read_to_end(&mut buf).await.expect("zstd fail");
        let duration = Instant::now().duration_since(start);
        debug!(
            "POST request size (compressed): {} (compressed in {} ms)",
            buf.len(),
            duration.as_millis()
        );

        let client = self.client()?;
        let request = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "zstd")
            .body(buf)
            .build()
            .context("building request for coverage data POST")?;
        let response = client
            .execute(request)
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

        response
            .json::<Option<String>>()
            .await
            .context("parsing response body for coverage data POST")?;

        Ok(())
    }

    async fn read_coverage_data<TP>(
        &self,
        project_name: &str,
        commit_identifier: &str,
        tags: &[Tag],
    ) -> Result<Option<FullCoverageData<TP::TI, TP::CI>>, CoverageDatabaseDetailedError>
    where
        TP: TestPlatform,
        TP::TI: TestIdentifier + Serialize + DeserializeOwned,
        TP::CI: CoverageIdentifier + Serialize + DeserializeOwned,
    {
        let mut url = self.api_url.clone();
        url.path_segments_mut()
            .map_err(|()| {
                CoverageDatabaseError::ParsingError(String::from(
                    "testtrim API URL is bad; cannot append segments",
                ))
            })
            .context("parse configured API URL")?
            .push(TP::platform_identifier())
            .push("coverage-data")
            .push(project_name)
            .push(commit_identifier);
        {
            let mut mutator = url.query_pairs_mut();
            mutator.clear();
            for tag in tags {
                mutator.append_pair(&tag.key, &tag.value);
            }
        }
        debug!("HTTP request GET {url}");
        let client = self.client()?;
        let request = client
            .get(url)
            .build()
            .context("building request for coverage data GET")?;
        let response = client
            .execute(request)
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
            .json::<Option<FullCoverageData<TP::TI, TP::CI>>>()
            .await
            .context("parsing response body for coverage data GET")?;

        debug!("HTTP response deserialized: {body:?}");
        Ok(body)
    }

    async fn has_any_coverage_data<TP: TestPlatform>(
        &self,
        project_name: &str,
    ) -> Result<bool, CoverageDatabaseDetailedError> {
        let mut url = self.api_url.clone();
        url.path_segments_mut()
            .map_err(|()| {
                CoverageDatabaseError::ParsingError(String::from(
                    "testtrim API URL is bad; cannot append segments",
                ))
            })
            .context("parse configured API URL")?
            .push(TP::platform_identifier())
            .push("coverage-data")
            .push(project_name);
        debug!("HTTP request GET {url}");
        let client = self.client()?;
        let request = client
            .get(url)
            .build()
            .context("building request for coverage data GET")?;
        let response = client
            .execute(request)
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
            .json::<bool>()
            .await
            .context("parsing response body for coverage data GET")?;

        debug!("HTTP response deserialized: {body:?}");

        Ok(body)
    }

    async fn clear_project_data<TP: TestPlatform>(
        &self,
        project_name: &str,
    ) -> Result<(), CoverageDatabaseDetailedError> {
        let mut url = self.api_url.clone();
        url.path_segments_mut()
            .map_err(|()| {
                CoverageDatabaseError::ParsingError(String::from(
                    "testtrim API URL is bad; cannot append segments",
                ))
            })
            .context("parse configured API URL")?
            .push(TP::platform_identifier())
            .push("coverage-data")
            .push(project_name);
        debug!("HTTP request DELETE {url}");
        let client = self.client()?;
        let request = client
            .delete(url)
            .build()
            .context("building request for coverage data DELETE")?;
        let response = client
            .execute(request)
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

        response
            .json::<Option<String>>()
            .await
            .context("parsing response body for coverage data DELETE")?;

        Ok(())
    }

    async fn intermittent_clean(
        &self,
        _older_than: &Duration,
    ) -> Result<(), CoverageDatabaseDetailedError> {
        warn!(
            "intermittent_clean is not supported when TESTTRIM_DATABASE_URL is a remote HTTP server"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use actix_test::TestServer;
    use actix_web::{
        App, Error, HttpResponse, Responder,
        body::MessageBody,
        dev::{ServiceRequest, ServiceResponse},
        middleware::{self, Next, from_fn},
        web,
    };
    use anyhow::Result;
    use lazy_static::lazy_static;
    use std::{collections::HashMap, sync::Mutex};

    use crate::{
        coverage::{
            CoverageDatabase, ResultWithContext as _, commit_coverage_data::CommitCoverageData,
            db_tests,
        },
        platform::{
            TestPlatform,
            rust::{RustCoverageIdentifier, RustTestIdentifier, RustTestPlatform},
        },
        server::InstallTestPlatform as _,
    };

    use super::TesttrimApiCoverageDatabase;

    lazy_static! {
        // Avoid running multiple concurrent tests; assuming they're working well they would conflict on each other with
        // the data being stored and retrieved.  Even though tests are often run in multiple processes (eg. w/ testtrim,
        // cargo-nextest), this in-process Mutex is sufficient because the database used during the tests is an
        // in-memory SQLite database.
        static ref TEST_MUTEX: Mutex<i32> = Mutex::new(0);
    }

    struct TestInterceptState {
        last_req_headers: Mutex<Option<HashMap<String, String>>>,
        last_resp_headers: Mutex<Option<HashMap<String, String>>>,
    }

    async fn testing_intercept_middleware(
        data: web::Data<TestInterceptState>,
        req: ServiceRequest,
        next: Next<impl MessageBody>,
    ) -> Result<ServiceResponse<impl MessageBody>, Error> {
        {
            let mut header_map = HashMap::new();
            for (key, value) in req.headers() {
                header_map.insert(
                    key.to_string(),
                    String::from(value.to_str().expect("decoding HTTP header as string")),
                );
            }
            let mut last_req_headers = data.last_req_headers.lock().unwrap();
            *last_req_headers = Some(header_map);
        }
        let resp = next.call(req).await;
        if let Ok(ref resp) = resp {
            let mut header_map = HashMap::new();
            for (key, value) in resp.headers() {
                header_map.insert(
                    key.to_string(),
                    String::from(value.to_str().expect("decoding HTTP header as string")),
                );
            }
            let mut last_resp_headers = data.last_resp_headers.lock().unwrap();
            *last_resp_headers = Some(header_map);
        }
        resp
    }

    async fn get_last_request_headers(data: web::Data<TestInterceptState>) -> impl Responder {
        let lock = data.last_req_headers.lock().unwrap();
        let value = lock.clone();
        HttpResponse::Ok().json(value)
    }

    async fn get_last_response_headers(data: web::Data<TestInterceptState>) -> impl Responder {
        let lock = data.last_resp_headers.lock().unwrap();
        let value = lock.clone();
        HttpResponse::Ok().json(value)
    }

    fn create_test_server() -> TestServer {
        let coverage_db = crate::coverage::create_test_db().unwrap();
        let factory = web::Data::new(coverage_db);

        let test_state = web::Data::new(TestInterceptState {
            last_req_headers: Mutex::new(None),
            last_resp_headers: Mutex::new(None),
        });
        actix_test::start(move || {
            App::new()
                .app_data(test_state.clone())
                .service(
                    web::scope(&format!(
                        "/api/v0/{}",
                        RustTestPlatform::platform_identifier()
                    ))
                    .wrap(middleware::Compress::default())
                    .wrap(from_fn(testing_intercept_middleware))
                    .platform_with_db_factory::<RustTestPlatform>(factory.clone()),
                )
                .route(
                    "/last-request-headers",
                    web::get().to(get_last_request_headers),
                )
                .route(
                    "/last-response-headers",
                    web::get().to(get_last_response_headers),
                )
        })
    }

    fn create_test_db() -> (TestServer, TesttrimApiCoverageDatabase) {
        let srv = create_test_server();
        let url = srv.url("/");
        (
            srv,
            TesttrimApiCoverageDatabase::new(&url).expect("init must succeed"),
        )
    }

    async fn cleanup() {
        let (_srv, db) = create_test_db();
        db.clear_project_data::<RustTestPlatform>("testtrim-tests")
            .await
            .expect("clear_project_data must succeed for test consistency");
    }

    #[tokio::test]
    async fn has_any_coverage_data_false() {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
            .expect("must config logging");
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::has_any_coverage_data_false(db).await;
    }

    #[tokio::test]
    async fn save_empty() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::save_empty(db).await;
    }

    #[tokio::test]
    async fn has_any_coverage_data_true() {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
            .expect("must config logging");
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::has_any_coverage_data_true(db).await;
    }

    #[tokio::test]
    async fn load_empty() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::load_empty(db).await;
    }

    #[tokio::test]
    async fn save_and_load_no_ancestor() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_no_ancestor(db).await;
    }

    #[tokio::test]
    async fn save_and_load_new_case_in_child() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_new_case_in_child(db).await;
    }

    #[tokio::test]
    async fn save_and_load_replacement_case_in_child() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_replacement_case_in_child(db).await;
    }

    #[tokio::test]
    async fn save_and_load_removed_case_in_child() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::save_and_load_removed_case_in_child(db).await;
    }

    #[tokio::test]
    async fn remove_file_references_in_child() {
        // simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
        //     .expect("must config logging");
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::remove_file_references_in_child(db).await;
    }

    #[tokio::test]
    async fn independent_tags() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::independent_tags(db).await;
    }

    #[tokio::test]
    async fn http_post_body_compression() -> Result<()> {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (srv, db) = create_test_db();

        // Make a POST...
        let data1 = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        let result = db
            .save_coverage_data::<RustTestPlatform>("testtrim-tests", &data1, "c1", None, &[])
            .await;
        assert!(result.is_ok(), "result = {result:?}");

        // Check what HTTP headers were sent:
        let http_headers = reqwest::get(srv.url("/last-request-headers"))
            .await
            .context("GET /last-request-headers")?
            .json::<Option<HashMap<String, String>>>()
            .await
            .context("parsing response body for GET /last-request-headers")?;
        assert!(
            http_headers.is_some(),
            "must have saved/returned http headers"
        );
        let http_headers = http_headers.unwrap();
        // We don't need to assert much here -- if the Content-Encoding header was sent and every other test passed, we
        // can be pretty confident that compression & decompression was done correctly.
        assert_eq!(
            http_headers.get("content-encoding"),
            Some(&String::from("zstd"))
        );

        Ok(())
    }

    #[tokio::test]
    async fn http_get_body_compression() -> Result<()> {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (srv, db) = create_test_db();

        // Make a GET...
        let result = db
            .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c1", &[])
            .await;
        assert!(result.is_ok(), "result = {result:?}");

        // Check what HTTP headers were sent:
        let request_headers = reqwest::get(srv.url("/last-request-headers"))
            .await
            .context("GET /last-request-headers")?
            .json::<Option<HashMap<String, String>>>()
            .await
            .context("parsing response body for GET /last-request-headers")?;
        assert!(
            request_headers.is_some(),
            "must have saved/returned http headers"
        );
        let request_headers = request_headers.unwrap();
        println!("request_headers: {request_headers:?}");

        let response_headers = reqwest::get(srv.url("/last-response-headers"))
            .await
            .context("GET /last-response-headers")?
            .json::<Option<HashMap<String, String>>>()
            .await
            .context("parsing response body for GET /last-response-headers")?;
        assert!(
            response_headers.is_some(),
            "must have saved/returned http headers"
        );
        let response_headers = response_headers.unwrap();
        println!("response_headers: {response_headers:?}");

        // We don't need to assert too much here -- just inspect the request & response headers to ensure that
        // compression was requested and provided, and it seems safe to assume that any failure to actually perform the
        // compression/decompression would cause other assertion failures.
        //
        // Ideally we'd use zstd based upon the testing we did in https://codeberg.org/testtrim/testtrim/issues/112, but
        // the key point of this test is to make sure that *some useful* compression is being requested, and when
        // responded with, it works, *AND then if it changes* due to any library upgrades, it really should be
        // cross-checked with the run-server impl to make sure it's supported but that's basically the same
        // implementation we'll be using to test here.
        assert_eq!(
            request_headers.get("accept-encoding"),
            Some(&String::from("gzip, zstd"))
        );
        assert_eq!(
            response_headers.get("content-encoding"),
            Some(&String::from("zstd"))
        );

        Ok(())
    }
}
