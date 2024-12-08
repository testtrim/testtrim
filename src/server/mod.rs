// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use actix_web::{
    body::BoxBody,
    get,
    http::{header::ContentType, StatusCode},
    rt, web, App, HttpRequest, HttpResponse, HttpServer, Responder, ResponseError, Scope,
};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_map_to_array::HashMapToArray;
use thiserror::Error;

use crate::{
    coverage::{
        commit_coverage_data::{
            CommitCoverageData, CoverageIdentifier, FileCoverage, FileReference, FunctionCoverage,
            HeuristicCoverage,
        },
        create_db, Tag,
    },
    platform::{dotnet::DotnetTestPlatform, rust::RustTestPlatform, TestIdentifier, TestPlatform},
};

#[get("/")]
async fn index(req: HttpRequest) -> &'static str {
    println!("REQ: {req:?}");
    "Hello world!\r\n"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadCoverageDataRequest {
    pub commit_identifier: String,
    pub tags: Vec<Tag>, // Note: mishmash between internal data structures and web API
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCoverageDataRequest {
    pub project_name: String,
    pub read_coverage_data: Option<ReadCoverageDataRequest>,
}

#[derive(Error, Debug)]
pub enum GetCoverageDataError {
    // FIXME: we don't want to leak details of this error to the end-user, and hence the error itself isn't printed; but
    // it would be great to log this on the internal logger...
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

async fn get_coverage_data<TP: TestPlatform>(
    req: web::Json<GetCoverageDataRequest>,
) -> Result<impl Responder, GetCoverageDataError> {
    debug!("get_coverage_data received: {:?}", req);

    let mut coverage_db = create_db::<TP::TI, TP::CI>(req.project_name.clone())?;

    // FIXME: read_coverage_data is not async, which will cause the web server to block; either make it async, or, use
    // web::block
    let result: serde_json::Value = match req.read_coverage_data {
        Some(ref read) => serde_json::to_value(
            // Note: mishmash between internal data structures and web API
            coverage_db.read_coverage_data(&read.commit_identifier, &read.tags)?,
        )?,
        None => serde_json::to_value(coverage_db.has_any_coverage_data()?)?,
    };

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostCoverageDataRequest<TI: TestIdentifier, CI: CoverageIdentifier> {
    pub project_name: String,
    pub commit_identifier: String,
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
pub enum PostCoverageDataError {
    // FIXME: we don't want to leak details of this error to the end-user, and hence the error itself isn't printed; but
    // it would be great to log this on the internal logger...
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
    req: web::Json<PostCoverageDataRequest<TP::TI, TP::CI>>,
) -> Result<impl Responder, PostCoverageDataError> {
    debug!("post_coverage_data received: {:?}", req);

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

    let mut coverage_db = create_db::<TP::TI, TP::CI>(req.project_name.clone())?;

    // FIXME: save_coverage_data is not async, which will cause the web server to block; either make it async, or, use
    // web::block
    coverage_db.save_coverage_data(
        &commit_coverage_data,
        &req.commit_identifier,
        req.ancestor_commit_identifier.as_deref(),
        &req.tags,
    )?;

    Ok(HttpResponse::Ok().json(None::<String>))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteCoverageDataRequest {
    pub project_name: String,
}

#[derive(Error, Debug)]
pub enum DeleteCoverageDataError {
    // FIXME: we don't want to leak details of this error to the end-user, and hence the error itself isn't printed; but
    // it would be great to log this on the internal logger...
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
    req: web::Json<DeleteCoverageDataRequest>,
) -> Result<impl Responder, DeleteCoverageDataError> {
    debug!("delete_coverage_data received: {:?}", req);

    let mut coverage_db = create_db::<TP::TI, TP::CI>(req.project_name.clone())?;

    // FIXME: delete_coverage_data is not async, which will cause the web server to block; either make it async, or, use
    // web::block
    println!("web: starting clear_project_data({})", req.project_name);
    coverage_db.clear_project_data()?;
    println!("web: completed clear_project_data({})", req.project_name);

    Ok(HttpResponse::Ok().json(None::<String>))
}

pub trait InstallPlatform {
    fn install_platform<TP: TestPlatform + 'static>(self) -> Self;
}

impl InstallPlatform for Scope {
    fn install_platform<TP: TestPlatform + 'static>(self) -> Self {
        // FIXME: API design here is a mess, DELETE with a body, GET with a body, it's just random
        self.route("/coverage-data", web::get().to(get_coverage_data::<TP>))
            .route("/coverage-data", web::post().to(post_coverage_data::<TP>))
            .route(
                "/coverage-data",
                web::delete().to(delete_coverage_data::<TP>),
            )
    }
}

pub fn cli() {
    run_server().expect("run_server failure");
}

fn run_server() -> std::io::Result<()> {
    rt::System::new().block_on(
        HttpServer::new(|| {
            App::new().service(index).service(
                web::scope("/api/v0")
                    .service(web::scope("/rust").install_platform::<RustTestPlatform>())
                    .service(web::scope("/dotnet").install_platform::<DotnetTestPlatform>()),
            )
        })
        // FIXME: clearly config for this would be useful
        .bind(("127.0.0.1", 8080))?
        .run(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use actix_web::{http::header::ContentType, test, App};
    use anyhow::Result;
    use lazy_static::lazy_static;

    use crate::{
        coverage::{
            commit_coverage_data::{CommitCoverageData, FileCoverage, HeuristicCoverage},
            full_coverage_data::FullCoverageData,
        },
        platform::{
            dotnet::{DotnetCoverageIdentifier, DotnetPackageDependency, DotnetTestIdentifier},
            rust::{RustCoverageIdentifier, RustPackageDependency, RustTestIdentifier},
        },
    };

    use super::*;

    lazy_static! {
        static ref rust_test_identifier: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
        static ref rust_coverage_identifier: RustCoverageIdentifier =
            RustCoverageIdentifier::PackageDependency(RustPackageDependency {
                package_name: String::from("thiserror"),
                version: String::from("0.1"),
            });
        static ref dotnet_test_identifier: DotnetTestIdentifier = {
            DotnetTestIdentifier {
                fully_qualified_name: "Namespace.Class.Test".to_string(),
            }
        };
        static ref dotnet_coverage_identifier: DotnetCoverageIdentifier =
            DotnetCoverageIdentifier::PackageDependency(DotnetPackageDependency {
                package_name: crate::platform::dotnet::PackageName(String::from(
                    "Microsoft.Something"
                )),
                version: crate::platform::dotnet::PackageVersion(String::from("0.1")),
            });
    }

    #[actix_web::test]
    async fn test_index_get() {
        let app = test::init_service(App::new().service(index)).await;
        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_index_post() {
        let app = test::init_service(App::new().service(index)).await;
        let req = test::TestRequest::post().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }

    #[actix_web::test]
    async fn test_get_coverage_rust() -> Result<()> {
        let test_project = String::from("testtrim-tests-2");
        let mut coverage_db =
            create_db::<RustTestIdentifier, RustCoverageIdentifier>(test_project.clone())?;

        let mut saved_data =
            CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        saved_data.add_executed_test(rust_test_identifier.clone());
        saved_data.add_existing_test(rust_test_identifier.clone());
        saved_data.add_file_to_test(FileCoverage {
            test_identifier: rust_test_identifier.clone(),
            file_name: PathBuf::from("file1.rs"),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: rust_test_identifier.clone(),
            coverage_identifier: rust_coverage_identifier.clone(),
        });
        coverage_db.save_coverage_data(
            &saved_data,
            "test-123-correct-identifier",
            None,
            &Vec::new(),
        )?;

        let app = test::init_service(App::new().route(
            "/coverage-data",
            web::get().to(get_coverage_data::<RustTestPlatform>),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/coverage-data")
            .set_json(GetCoverageDataRequest {
                project_name: String::from("testtrim-tests-2"),
                read_coverage_data: Some(ReadCoverageDataRequest {
                    commit_identifier: String::from("test-123-wrong-identifier"),
                    tags: Vec::new(),
                }),
            })
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
            .uri("/coverage-data")
            .set_json(GetCoverageDataRequest {
                project_name: String::from("testtrim-tests-2"),
                read_coverage_data: Some(ReadCoverageDataRequest {
                    commit_identifier: String::from("test-123-correct-identifier"),
                    tags: Vec::new(),
                }),
            })
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
        let mut coverage_db =
            create_db::<DotnetTestIdentifier, DotnetCoverageIdentifier>(test_project.clone())?;

        let mut saved_data =
            CommitCoverageData::<DotnetTestIdentifier, DotnetCoverageIdentifier>::new();
        saved_data.add_executed_test(dotnet_test_identifier.clone());
        saved_data.add_existing_test(dotnet_test_identifier.clone());
        saved_data.add_file_to_test(FileCoverage {
            test_identifier: dotnet_test_identifier.clone(),
            file_name: PathBuf::from("file1.rs"),
        });
        saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: dotnet_test_identifier.clone(),
            coverage_identifier: dotnet_coverage_identifier.clone(),
        });
        coverage_db.save_coverage_data(
            &saved_data,
            "test-456-correct-identifier",
            None,
            &Vec::new(),
        )?;

        let app = test::init_service(App::new().route(
            "/coverage-data",
            web::get().to(get_coverage_data::<DotnetTestPlatform>),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/coverage-data")
            .set_json(GetCoverageDataRequest {
                project_name: String::from("testtrim-tests-3"),
                read_coverage_data: Some(ReadCoverageDataRequest {
                    commit_identifier: String::from("test-123-wrong-identifier"),
                    tags: Vec::new(),
                }),
            })
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
            .uri("/coverage-data")
            .set_json(GetCoverageDataRequest {
                project_name: String::from("testtrim-tests-3"),
                read_coverage_data: Some(ReadCoverageDataRequest {
                    commit_identifier: String::from("test-456-correct-identifier"),
                    tags: Vec::new(),
                }),
            })
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
}
