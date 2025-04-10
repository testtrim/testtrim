// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use actix_web::{
    HttpResponse, Responder, ResponseError, Scope,
    body::BoxBody,
    http::{StatusCode, header::ContentType},
    web::{self, JsonConfig},
};
use anyhow::Result;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_map_to_array::HashMapToArray;
use thiserror::Error;

use crate::{
    coverage::{
        CoverageDatabase as _, CoverageDatabaseDispatch, Tag,
        commit_coverage_data::{
            CommitCoverageData, CoverageIdentifier, FileCoverage, FileReference, FunctionCoverage,
            HeuristicCoverage,
        },
        create_db,
    },
    platform::{TestIdentifier, TestPlatform},
};

pub trait InstallCoverageDataHandlers {
    fn coverage_data_handlers<TP: TestPlatform + 'static>(self) -> Result<Self>
    where
        Self: Sized;
    fn coverage_data_handlers_with_db_factory<TP: TestPlatform + 'static>(
        self,
        factory: web::Data<CoverageDatabaseDispatch>,
    ) -> Self;
}

impl InstallCoverageDataHandlers for Scope {
    fn coverage_data_handlers<TP: TestPlatform + 'static>(self) -> Result<Self> {
        let coverage_db = create_db()?;
        Ok(self.coverage_data_handlers_with_db_factory::<TP>(web::Data::new(coverage_db)))
    }

    fn coverage_data_handlers_with_db_factory<TP: TestPlatform + 'static>(
        self,
        factory: web::Data<CoverageDatabaseDispatch>,
    ) -> Self {
        let size_64_mb = 1 << 26;
        self.app_data(factory)
            // Allow larger content than the default (2MB); a full coverage data upload from an Open Source project
            // (ripgrep) for a "first commit" is about 9MB, so 64MB still gives us some breathing room for larger
            // projects but doesn't go crazy.  Not sure if this is measured before, or after,
            .app_data(JsonConfig::default().limit(size_64_mb))
            .route("/{project}", web::get().to(get_any_coverage_data::<TP>))
            .route(
                "/{project}/first",
                web::get().to(get_first_coverage_data::<TP>),
            )
            .route(
                "/{project}/{commit_identifier}",
                web::get().to(get_coverage_data::<TP>),
            )
            .route(
                "/{project}/{commit_identifier}",
                web::post().to(post_coverage_data::<TP>),
            )
            .route("/{project}", web::delete().to(delete_coverage_data::<TP>))
    }
}

#[derive(Error, Debug)]
pub enum GetCoverageDataError {
    #[error("internal server misconfiguration")]
    CreateDatabase(#[from] crate::coverage::CreateDatabaseError),
    #[error("internal server error accessing coverage databaase")]
    CoverageDatabase(#[from] crate::coverage::CoverageDatabaseDetailedError),
    #[error("internal server error serializing data to JSON")]
    Serialization(#[from] serde_json::Error),
}

impl ResponseError for GetCoverageDataError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::plaintext())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn get_any_coverage_data<TP: TestPlatform>(
    path: web::Path<String>,
    coverage_db: web::Data<CoverageDatabaseDispatch>,
) -> Result<impl Responder, GetCoverageDataError> {
    let project_name = path.into_inner();
    debug!("get_any_coverage_data received: {project_name:?}");

    Ok(HttpResponse::Ok().json(serde_json::to_value(
        coverage_db
            .has_any_coverage_data::<TP>(&project_name)
            .await?,
    )?))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFirstCoverageDataRequest {
    pub commit_identifiers: Vec<String>,
}

async fn get_first_coverage_data<TP: TestPlatform>(
    path: web::Path<String>,
    tags: web::Query<HashMap<String, String>>,
    req: web::Json<GetFirstCoverageDataRequest>,
    coverage_db: web::Data<CoverageDatabaseDispatch>,
) -> Result<impl Responder, GetCoverageDataError> {
    let project_name = path.into_inner();
    let tags = tags.into_inner();
    debug!("get_first_coverage_data received: {project_name:?} {tags:?} {req:?}");

    // hashmap -> vec; can't be done in Query<T> because it's considered ordered when query parameters aren't, even
    // though we don't care about order (arguably we're using the wrong data struct inside)
    let tags = tags
        .into_iter()
        .map(|(key, value)| Tag { key, value })
        .collect::<Vec<Tag>>();

    Ok(HttpResponse::Ok().json(
        coverage_db
            .read_first_available_coverage_data::<TP>(
                &project_name,
                &req.commit_identifiers
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
                &tags,
            )
            .await?,
    ))
}

async fn get_coverage_data<TP: TestPlatform>(
    path: web::Path<(String, String)>,
    tags: web::Query<HashMap<String, String>>,
    coverage_db: web::Data<CoverageDatabaseDispatch>,
) -> Result<impl Responder, GetCoverageDataError> {
    let (project_name, commit_identifier) = path.into_inner();
    let tags = tags.into_inner();
    debug!("get_coverage_data received: {project_name:?} {commit_identifier:?} {tags:?}");

    // hashmap -> vec; can't be done in Query<T> because it's considered ordered when query parameters aren't, even
    // though we don't care about order (arguably we're using the wrong data struct inside)
    let tags = tags
        .into_iter()
        .map(|(key, value)| Tag { key, value })
        .collect::<Vec<Tag>>();

    Ok(HttpResponse::Ok().json(
        coverage_db
            .read_coverage_data::<TP>(&project_name, &commit_identifier, &tags)
            .await?,
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostCoverageDataRequest<TI: TestIdentifier, CI: CoverageIdentifier> {
    pub ancestor_commit_identifier: Option<String>,
    pub tags: Vec<Tag>, // Note: mishmash between internal data structures and web API
    // FIXME:  when using CommitCoverageData, we get:
    // multiple `impl`s or `where` clauses satisfying `CI: server::_::_serde::Deserialize<'_>` found
    // but we can manually flatten the fields from that object here just fine... so I guess we'll do that as a workaround for now.
    // commit_coverage_data: CommitCoverageData<TI, CI>, // Note: mishmash between internal data structures and web API
    pub all_existing_test_set: HashSet<TI>,
    pub executed_test_set: HashSet<TI>,
    #[serde(with = "HashMapToArray::<TI, HashSet<PathBuf>>")]
    pub executed_test_to_files_map: HashMap<TI, HashSet<PathBuf>>,
    #[serde(with = "HashMapToArray::<TI, HashSet<String>>")]
    pub executed_test_to_functions_map: HashMap<TI, HashSet<String>>,
    #[serde(with = "HashMapToArray::<TI, HashSet<CI>>")]
    pub executed_test_to_coverage_identifier_map: HashMap<TI, HashSet<CI>>,
    pub file_references_files_map: HashMap<PathBuf, HashSet<PathBuf>>,
}

#[derive(Error, Debug)]
enum PostCoverageDataError {
    #[error("internal server misconfiguration")]
    CreateDatabase(#[from] crate::coverage::CreateDatabaseError),
    #[error("internal server error accessing coverage databaase")]
    CoverageDatabase(#[from] crate::coverage::CoverageDatabaseDetailedError),
}

impl ResponseError for PostCoverageDataError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::plaintext())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn post_coverage_data<TP: TestPlatform>(
    path: web::Path<(String, String)>,
    req: web::Json<PostCoverageDataRequest<TP::TI, TP::CI>>,
    coverage_db: web::Data<CoverageDatabaseDispatch>,
) -> Result<impl Responder, PostCoverageDataError> {
    let (project_name, commit_identifier) = path.into_inner();
    debug!("post_coverage_data received: {req:?}");

    // manually deserialize CommitCoverageData as workaround for multiple `impl`'s error
    let mut commit_coverage_data = CommitCoverageData::new();
    for ti in &req.all_existing_test_set {
        commit_coverage_data.add_existing_test(ti.clone());
    }
    for ti in &req.executed_test_set {
        commit_coverage_data.add_executed_test(ti.clone());
    }
    for (ti, set) in &req.executed_test_to_files_map {
        for file in set {
            commit_coverage_data.add_file_to_test(FileCoverage {
                test_identifier: ti.clone(),
                file_name: file.clone(),
            });
        }
    }
    for (ti, set) in &req.executed_test_to_functions_map {
        for function in set {
            commit_coverage_data.add_function_to_test(FunctionCoverage {
                test_identifier: ti.clone(),
                function_name: function.clone(),
            });
        }
    }
    for (ti, set) in &req.executed_test_to_coverage_identifier_map {
        for ci in set {
            commit_coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
                test_identifier: ti.clone(),
                coverage_identifier: ci.clone(),
            });
        }
    }
    for (referencing_file, set) in &req.file_references_files_map {
        if set.is_empty() {
            commit_coverage_data.mark_file_makes_no_references(referencing_file.clone());
        } else {
            for target_file in set {
                commit_coverage_data.add_file_reference(FileReference {
                    referencing_file: referencing_file.clone(),
                    target_file: target_file.clone(),
                });
            }
        }
    }

    coverage_db
        .save_coverage_data::<TP>(
            &project_name,
            &commit_coverage_data,
            &commit_identifier,
            req.ancestor_commit_identifier.as_deref(),
            &req.tags,
        )
        .await?;

    Ok(HttpResponse::Ok().json(None::<String>))
}

#[derive(Error, Debug)]
enum DeleteCoverageDataError {
    #[error("internal server misconfiguration")]
    CreateDatabase(#[from] crate::coverage::CreateDatabaseError),
    #[error("internal server error accessing coverage databaase")]
    CoverageDatabase(#[from] crate::coverage::CoverageDatabaseDetailedError),
    #[error("internal server error serializing data to JSON")]
    Serialization(#[from] serde_json::Error),
}

impl ResponseError for DeleteCoverageDataError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::plaintext())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn delete_coverage_data<TP: TestPlatform>(
    path: web::Path<String>,
    coverage_db: web::Data<CoverageDatabaseDispatch>,
) -> Result<impl Responder, DeleteCoverageDataError> {
    let project_name = path.into_inner();
    debug!("delete_coverage_data received: {project_name:?}");

    debug!("web: starting clear_project_data({project_name})");
    coverage_db.clear_project_data::<TP>(&project_name).await?;
    debug!("web: completed clear_project_data({project_name})");

    Ok(HttpResponse::Ok().json(None::<String>))
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::LazyLock};

    use actix_web::{App, test};
    use anyhow::Result;

    use crate::{
        coverage::{
            commit_coverage_data::{CommitCoverageData, FileCoverage, HeuristicCoverage},
            create_test_db,
            full_coverage_data::FullCoverageData,
        },
        platform::{
            dotnet::{
                DotnetCoverageIdentifier, DotnetPackageDependency, DotnetTestIdentifier,
                DotnetTestPlatform,
            },
            rust::{
                RustCoverageIdentifier, RustPackageDependency, RustTestIdentifier, RustTestPlatform,
            },
        },
    };

    use super::*;

    static RUST_TEST_IDENTIFIER: LazyLock<RustTestIdentifier> =
        LazyLock::new(|| RustTestIdentifier {
            test_src_path: PathBuf::from("src/lib.rs"),
            test_name: "test1".to_string(),
        });
    static RUST_COVERAGE_IDENTIFIER: LazyLock<RustCoverageIdentifier> = LazyLock::new(|| {
        RustCoverageIdentifier::PackageDependency(RustPackageDependency {
            package_name: String::from("thiserror"),
            version: String::from("0.1"),
        })
    });
    static DOTNET_TEST_IDENTIFIER: LazyLock<DotnetTestIdentifier> =
        LazyLock::new(|| DotnetTestIdentifier {
            fully_qualified_name: "Namespace.Class.Test".to_string(),
        });
    static DOTNET_COVERAGE_IDENTIFIER: LazyLock<DotnetCoverageIdentifier> = LazyLock::new(|| {
        DotnetCoverageIdentifier::PackageDependency(DotnetPackageDependency {
            package_name: crate::platform::dotnet::PackageName(String::from("Microsoft.Something")),
            version: crate::platform::dotnet::PackageVersion(String::from("0.1")),
        })
    });

    #[actix_web::test]
    async fn test_get_coverage_rust() -> Result<()> {
        let test_project = String::from("testtrim-tests-2");
        let coverage_db = create_test_db()?;

        let mut saved_data =
            CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        saved_data.add_executed_test(RUST_TEST_IDENTIFIER.clone());
        saved_data.add_existing_test(RUST_TEST_IDENTIFIER.clone());
        saved_data.add_file_to_test(FileCoverage {
            test_identifier: RUST_TEST_IDENTIFIER.clone(),
            file_name: PathBuf::from("file1.rs"),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: RUST_TEST_IDENTIFIER.clone(),
            coverage_identifier: RUST_COVERAGE_IDENTIFIER.clone(),
        });
        coverage_db
            .save_coverage_data::<RustTestPlatform>(
                &test_project,
                &saved_data,
                "test-123-correct-identifier",
                None,
                &Vec::new(),
            )
            .await?;

        let factory = web::Data::new(coverage_db);
        let app = test::init_service(App::new().app_data(factory).route(
            "/coverage-data/{project}/{commit_identifier}",
            web::get().to(get_coverage_data::<RustTestPlatform>),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/coverage-data/testtrim-tests-2/test-123-wrong-identifier")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "status not success: {}",
            resp.status()
        );

        let resp_body: Option<FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>> =
            test::read_body_json(resp).await;
        assert!(
            resp_body.is_none(),
            "commit identifier doesn't match saved; expecting null"
        );

        let req = test::TestRequest::get()
            .uri("/coverage-data/testtrim-tests-2/test-123-correct-identifier")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "status not success: {}",
            resp.status()
        );

        let resp_body: Option<FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>> =
            test::read_body_json(resp).await;
        assert!(
            resp_body.is_some(),
            "commit identifier matches saved; expecting not null"
        );

        Ok(())
    }

    #[actix_web::test]
    async fn test_get_coverage_dotnet() -> Result<()> {
        let test_project = String::from("testtrim-tests-3");
        let coverage_db = create_test_db()?;

        let mut saved_data =
            CommitCoverageData::<DotnetTestIdentifier, DotnetCoverageIdentifier>::new();
        saved_data.add_executed_test(DOTNET_TEST_IDENTIFIER.clone());
        saved_data.add_existing_test(DOTNET_TEST_IDENTIFIER.clone());
        saved_data.add_file_to_test(FileCoverage {
            test_identifier: DOTNET_TEST_IDENTIFIER.clone(),
            file_name: PathBuf::from("file1.rs"),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: DOTNET_TEST_IDENTIFIER.clone(),
            coverage_identifier: DOTNET_COVERAGE_IDENTIFIER.clone(),
        });
        coverage_db
            .save_coverage_data::<DotnetTestPlatform>(
                &test_project,
                &saved_data,
                "test-456-correct-identifier",
                None,
                &Vec::new(),
            )
            .await?;

        let factory = web::Data::new(coverage_db);
        let app = test::init_service(App::new().app_data(factory).route(
            "/coverage-data/{project}/{commit_identifier}",
            web::get().to(get_coverage_data::<DotnetTestPlatform>),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/coverage-data/testtrim-tests-3/test-123-wrong-identifier")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "status not success: {}",
            resp.status()
        );

        let resp_body: Option<FullCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>> =
            test::read_body_json(resp).await;
        assert!(
            resp_body.is_none(),
            "commit identifier doesn't match saved; expecting null"
        );

        let req = test::TestRequest::get()
            .uri("/coverage-data/testtrim-tests-3/test-456-correct-identifier")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "status not success: {}",
            resp.status()
        );

        let resp_body: Option<FullCoverageData<DotnetTestIdentifier, DotnetCoverageIdentifier>> =
            test::read_body_json(resp).await;
        assert!(
            resp_body.is_some(),
            "commit identifier matches saved; expecting not null"
        );

        Ok(())
    }

    #[actix_web::test]
    async fn test_get_first_coverage() -> Result<()> {
        let test_project = String::from("testtrim-tests-2");
        let coverage_db = create_test_db()?;

        let mut saved_data =
            CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        saved_data.add_executed_test(RUST_TEST_IDENTIFIER.clone());
        saved_data.add_existing_test(RUST_TEST_IDENTIFIER.clone());
        saved_data.add_file_to_test(FileCoverage {
            test_identifier: RUST_TEST_IDENTIFIER.clone(),
            file_name: PathBuf::from("file1.rs"),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: RUST_TEST_IDENTIFIER.clone(),
            coverage_identifier: RUST_COVERAGE_IDENTIFIER.clone(),
        });
        coverage_db
            .save_coverage_data::<RustTestPlatform>(
                &test_project,
                &saved_data,
                "test-123-correct-identifier",
                None,
                &Vec::new(),
            )
            .await?;

        let factory = web::Data::new(coverage_db);
        let app = test::init_service(App::new().app_data(factory).route(
            "/coverage-data/{project}/first",
            web::get().to(get_first_coverage_data::<RustTestPlatform>),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/coverage-data/testtrim-tests-2/first")
            .set_json(GetFirstCoverageDataRequest {
                commit_identifiers: vec![],
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "status not success: {}",
            resp.status()
        );

        let resp_body: Option<(
            String,
            FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
        )> = test::read_body_json(resp).await;
        assert!(
            resp_body.is_none(),
            "commit identifier doesn't match saved; expecting null"
        );

        let req = test::TestRequest::get()
            .uri("/coverage-data/testtrim-tests-2/first")
            .set_json(GetFirstCoverageDataRequest {
                commit_identifiers: vec![
                    String::from("test-123-bad-identifier-1"),
                    String::from("test-123-bad-identifier-2"),
                    String::from("test-123-correct-identifier"),
                ],
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "status not success: {}",
            resp.status()
        );

        let resp_body: Option<(
            String,
            FullCoverageData<RustTestIdentifier, RustCoverageIdentifier>,
        )> = test::read_body_json(resp).await;
        assert!(
            resp_body.is_some(),
            "commit identifier matches saved; expecting not null"
        );
        let (commit_id, _coverage_data) = resp_body.unwrap();
        assert_eq!(commit_id, "test-123-correct-identifier");

        Ok(())
    }
}
