// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_compression::tokio::bufread::ZstdEncoder;
use log::{debug, warn};
use reqwest::{Client, Method};
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
    server::coverage_data::{GetFirstCoverageDataRequest, PostCoverageDataRequest},
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
    features: tokio::sync::OnceCell<Vec<String>>,
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

        Ok(TesttrimApiCoverageDatabase {
            api_url: url,
            client: OnceLock::new(),
            features: tokio::sync::OnceCell::new(),
        })
    }

    fn client(&self) -> &Client {
        self.client.get_or_init(|| {
            reqwest::ClientBuilder::new()
                .zstd(true)
                .gzip(true)
                .user_agent(format!("testtrim ({})", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap()
        })
    }

    async fn features(&self) -> Result<&Vec<String>, CoverageDatabaseDetailedError> {
        self.features
            .get_or_try_init(async || {
                let url = &self.api_url;
                debug!("HTTP request OPTIONS {url}");
                let client = self.client();
                let request = client
                    .request(Method::OPTIONS, url.clone())
                    .build()
                    .context("building request for coverage data OPTIONS")?;
                let response = client
                    .execute(request)
                    .await
                    .context("sending request for coverage data OPTIONS")?;

                debug!("HTTP response: {response:?}");
                if response.status() == 404 {
                    // Features not supported by upstream server.
                    debug!("remote server didn't support OPTIONS and gave 404 -- assuming no features are supported");
                    return Ok(Vec::new());
                } else if response.status() != 200 {
                    return Err(CoverageDatabaseError::DatabaseError(format!(
                        "remote server returned unexpected status {}",
                        response.status()
                    )))
                    .context("reading response for coverage data OPTIONS");
                }

                let body = response
                    .json::<Vec<String>>()
                    .await
                    .context("parsing response body for coverage data OPTIONS")?;

                debug!("HTTP response deserialized: {body:?}");
                Ok(body)
            })
            .await
    }

    async fn internal_save_coverage_data<TP>(
        &self,
        project_name: &str,
        coverage_data: &CommitCoverageData<TP::TI, TP::CI>,
        commit_identifier: &str,
        ancestor_commit_identifier: Option<&str>,
        tags: &[Tag],
        retries_available: u8,
    ) -> Result<(), CoverageDatabaseDetailedError>
    where
        TP: TestPlatform,
        TP::TI: TestIdentifier + Serialize + DeserializeOwned,
        TP::CI: CoverageIdentifier + Serialize + DeserializeOwned,
    {
        Box::pin(async move {
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
                executed_test_to_functions_map: coverage_data
                    .executed_test_to_functions_map()
                    .clone(),
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

            let client = self.client();
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
            if response.status().is_server_error() && retries_available > 0 {
                // slight wait... this is pretty unsophisticated retry but it's better than nothing
                warn!(
                    "HTTP response {} received from remote server; retrying in 2 seconds",
                    response.status()
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                return self
                    .internal_save_coverage_data::<TP>(
                        project_name,
                        coverage_data,
                        commit_identifier,
                        ancestor_commit_identifier,
                        tags,
                        retries_available - 1,
                    )
                    .await;
            } else if response.status() != 200 {
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
        })
        .await
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
        self.internal_save_coverage_data::<TP>(
            project_name,
            coverage_data,
            commit_identifier,
            ancestor_commit_identifier,
            tags,
            3, // retry if required
        )
        .await
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
        let client = self.client();
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
        let features = self.features().await?;

        if features.contains(&String::from("read_first_available_coverage_data")) {
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
                .push("first");
            {
                let mut mutator = url.query_pairs_mut();
                mutator.clear();
                for tag in tags {
                    mutator.append_pair(&tag.key, &tag.value);
                }
            }
            debug!("HTTP request GET {url}");
            let client = self.client();
            let request = client
                .get(url)
                .json(&GetFirstCoverageDataRequest {
                    commit_identifiers: commit_identifiers
                        .iter()
                        .map(|&s| String::from(s))
                        .collect::<Vec<String>>(),
                })
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
                .json::<Option<(String, FullCoverageData<TP::TI, TP::CI>)>>()
                .await
                .context("parsing response body for coverage data GET")?;
            debug!("HTTP response deserialized: {body:?}");

            if let Some((commit_id, coverage_data)) = body {
                // retval is expected to be `&str` from commit_identifiers -- so find it.  Kinda weird, maybe I should
                // change the retval to `String`.
                for r in commit_identifiers {
                    if *r == commit_id {
                        return Ok(Some((*r, coverage_data)));
                    }
                }
                return Err(CoverageDatabaseError::DatabaseError(format!(
                    "commit ID {commit_id} returned by remote was not one provided by client"
                ))
                .into());
            }
            Ok(None)
        } else {
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
        let client = self.client();
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
        let client = self.client();
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
        body::{BoxBody, MessageBody},
        dev::{ServiceRequest, ServiceResponse},
        http::{Method, StatusCode},
        middleware::{self, Next, from_fn},
        web,
    };
    use anyhow::Result;
    use lazy_static::lazy_static;
    use log::debug;
    use std::str::FromStr;
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
        last_req_url: Mutex<Option<String>>,
        last_req_headers: Mutex<Option<HashMap<String, String>>>,
        last_resp_headers: Mutex<Option<HashMap<String, String>>>,
        next_request_fail: Mutex<Option<StatusCode>>,
    }

    async fn testing_intercept_middleware(
        data: web::Data<TestInterceptState>,
        req: ServiceRequest,
        next: Next<impl MessageBody + 'static>,
    ) -> Result<ServiceResponse<impl MessageBody + 'static>, Error> {
        {
            let mut lock = data.next_request_fail.lock().unwrap();
            if let Some(status_code) = *lock {
                // reset next_request_fail
                *lock = None;
                // don't call the `next`; override the response
                let (req, _payload) = req.into_parts();
                return Ok(ServiceResponse::new(
                    req,
                    HttpResponse::with_body(status_code, BoxBody::new("abc")),
                ));
            }
        }
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
        {
            let mut last_req_url = data.last_req_url.lock().unwrap();
            *last_req_url = Some(req.uri().to_string());
            debug!("saved last_req_url as {last_req_url:?}");
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
        resp.map(|resp| resp.map_body(|_head, body| BoxBody::new(body)))
    }

    async fn get_last_request_url(data: web::Data<TestInterceptState>) -> impl Responder {
        let lock = data.last_req_url.lock().unwrap();
        let value = lock.clone();
        HttpResponse::Ok().json(value)
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

    async fn make_next_request_fail(
        data: web::Data<TestInterceptState>,
        path: web::Path<String>,
    ) -> impl Responder {
        let status_code = path.into_inner();
        let status_code = StatusCode::from_u16(u16::from_str(&status_code).unwrap()).unwrap();

        let mut lock = data.next_request_fail.lock().unwrap();
        (*lock) = Some(status_code);
        HttpResponse::Ok().json("woot!")
    }

    fn create_test_server(features: Vec<String>) -> TestServer {
        let coverage_db = crate::coverage::create_test_db().unwrap();
        let factory = web::Data::new(coverage_db);
        let has_features = !features.is_empty();
        let features = web::Data::new(features);

        let options_api_v0 =
            async |features: web::Data<Vec<String>>| HttpResponse::Ok().json(features);

        let test_state = web::Data::new(TestInterceptState {
            last_req_url: Mutex::new(None),
            last_req_headers: Mutex::new(None),
            last_resp_headers: Mutex::new(None),
            next_request_fail: Mutex::new(None),
        });
        actix_test::start(move || {
            App::new()
                .app_data(test_state.clone())
                .app_data(features.clone())
                .service(
                    web::scope("/api/v0")
                        .configure(|scope| {
                            if has_features {
                                scope.route("", web::method(Method::OPTIONS).to(options_api_v0));
                            }
                        })
                        .service(
                            web::scope(RustTestPlatform::platform_identifier())
                                .wrap(middleware::Compress::default())
                                .wrap(from_fn(testing_intercept_middleware))
                                .platform_with_db_factory::<RustTestPlatform>(factory.clone()),
                        ),
                )
                .route("/last-request-url", web::get().to(get_last_request_url))
                .route(
                    "/last-request-headers",
                    web::get().to(get_last_request_headers),
                )
                .route(
                    "/last-response-headers",
                    web::get().to(get_last_response_headers),
                )
                .route(
                    "/make-next-request-fail/{status_code}",
                    web::get().to(make_next_request_fail),
                )
        })
    }

    fn create_test_db() -> (TestServer, TesttrimApiCoverageDatabase) {
        let srv = create_test_server(vec![]);
        let url = srv.url("/");
        (
            srv,
            TesttrimApiCoverageDatabase::new(&url).expect("init must succeed"),
        )
    }

    fn create_test_db_w_features(
        features: Vec<String>,
    ) -> (TestServer, TesttrimApiCoverageDatabase) {
        let srv = create_test_server(features);
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

    #[tokio::test]
    async fn http_resilient() -> Result<()> {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (srv, db) = create_test_db();

        // Set the next request to generate a 404 error; as a 4xx class we expect that the API client will just try it
        // once and then understand that its request is bad and not retry.
        reqwest::get(srv.url("/make-next-request-fail/404"))
            .await
            .context("GET /make-next-request-fail/404")?
            .json::<String>()
            .await
            .context("parsing response body for GET /make-next-request-fail/404")?;

        // Make a save_coverage_data; expect failure.
        let data1 = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        let result = db
            .save_coverage_data::<RustTestPlatform>("testtrim-tests", &data1, "c1", None, &[])
            .await;
        assert!(result.is_err(), "result = {result:?}");
        let result = result.unwrap_err();
        assert_eq!(
            "database error: `remote server returned unexpected status 404 Not Found` (reading response for coverage data POST)",
            format!("{result}")
        );

        // Set the next request to generate a 500 error; we expect this class of error to be retried transparently by
        // the API client.
        reqwest::get(srv.url("/make-next-request-fail/500"))
            .await
            .context("GET /make-next-request-fail/500")?
            .json::<String>()
            .await
            .context("parsing response body for GET /make-next-request-fail/500")?;

        // Make a save_coverage_data; expect failure.
        let data1 = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        let result = db
            .save_coverage_data::<RustTestPlatform>("testtrim-tests", &data1, "c1", None, &[])
            .await;
        assert!(result.is_ok(), "result = {result:?}");

        // FIXME: create a network-level error as well for retry

        Ok(())
    }

    #[tokio::test]
    async fn features_not_available() -> Result<()> {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Trace, simplelog::Config::default())
            .expect("must config logging");

        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();

        assert!(!db.features.initialized());

        // Make a request that uses features...
        let result = db
            .read_first_available_coverage_data::<RustTestPlatform>("testtrim-tests", &[], &[])
            .await;
        assert!(result.is_ok(), "result = {result:?}");

        // Should be initialized but empty if the upstream server didn't support features.
        assert!(db.features.initialized());
        assert_eq!(db.features.get().unwrap(), &Vec::<String>::new());

        Ok(())
    }

    #[tokio::test]
    async fn fetch_features() -> Result<()> {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Trace, simplelog::Config::default())
            .expect("must config logging");

        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db_w_features(vec![String::from("fake-feature")]);

        assert!(!db.features.initialized());

        // Make a GET...
        let result = db
            .read_first_available_coverage_data::<RustTestPlatform>("testtrim-tests", &[], &[])
            .await;
        assert!(result.is_ok(), "result = {result:?}");

        assert!(db.features.initialized());
        assert_eq!(
            db.features.get().unwrap(),
            &vec![String::from("fake-feature")]
        );

        Ok(())
    }

    #[tokio::test]
    async fn read_first_available_coverage_data() -> Result<()> {
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())
            .expect("must config logging");

        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (srv, db) =
            create_test_db_w_features(vec![String::from("read_first_available_coverage_data")]);

        // Make a GET...
        let result = db
            .read_first_available_coverage_data::<RustTestPlatform>(
                "testtrim-tests",
                &["abc", "def"],
                &[],
            )
            .await;
        assert!(result.is_ok(), "result = {result:?}");

        // Check which HTTP endpoint was used:
        let request_url = reqwest::get(srv.url("/last-request-url"))
            .await
            .context("GET /last-request-url")?
            .json::<Option<String>>()
            .await
            .context("parsing response body for GET /last-request-url")?;
        assert!(request_url.is_some(), "must have saved/returned http url");
        let request_url = request_url.unwrap();
        assert_eq!(
            request_url,
            "/api/v0/rust/coverage-data/testtrim-tests/first?"
        );

        Ok(())
    }

    #[tokio::test]
    async fn load_first_case_obsolete() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) = create_test_db();
        db_tests::load_first_case(db).await;
    }

    #[tokio::test]
    async fn load_first_case() {
        let _test_mutex = TEST_MUTEX.lock();
        cleanup().await;
        let (_srv, db) =
            create_test_db_w_features(vec![String::from("read_first_available_coverage_data")]);
        db_tests::load_first_case(db).await;
    }
}
