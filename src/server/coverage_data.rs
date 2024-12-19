// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use actix_web::{
    body::BoxBody,
    http::{header::ContentType, StatusCode},
    web::{self, JsonConfig},
    HttpResponse, Responder, ResponseError, Scope,
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
        create_db, CoverageDatabase as _, CoverageDatabaseDispatch, CreateDatabaseError, Tag,
    },
    platform::{TestIdentifier, TestPlatform},
};

type FactoryFunction<TP> = fn(
    String,
) -> Result<
    CoverageDatabaseDispatch<<TP as TestPlatform>::TI, <TP as TestPlatform>::CI>,
    CreateDatabaseError,
>;

pub enum CoverageDatabaseFactoryHolder<TP: TestPlatform> {
    Function(FactoryFunction<TP>),
    #[allow(dead_code)] // used in tests only
    Fixture(Arc<CoverageDatabaseDispatch<TP::TI, TP::CI>>),
}

// FIXME: this Arc<..> usage is a little ugly, but it is used because the CoverageDatabaseFactoryHolder has one approach
// (factory) that returns an owned object, and one approach (fixture) that returns a reference to an object, hence the
// Arc.  If coverage databases were stored/cached we wouldn't need to do this, but then we'd have to get rid of
// project_name as an input during creation and instead use it as an input during the methods.  Switching to this model
// of a purely injected coverage database seems like the right thing to do, but practically probably doesn't have much
// value.
type ThreadsafeCoverageDatabase<TP> =
    Arc<CoverageDatabaseDispatch<<TP as TestPlatform>::TI, <TP as TestPlatform>::CI>>;

impl<TP: TestPlatform> CoverageDatabaseFactoryHolder<TP> {
    // Rc<T> is a little ugly here; &'a where 'a is the life of this would be better, but we don't hold the result of
    // the Function and we're an enum so don't have a place for one (an enum can't be self mutating, right?)
    fn get_db(
        &self,
        project_name: String,
    ) -> Result<ThreadsafeCoverageDatabase<TP>, CreateDatabaseError> {
        match self {
            CoverageDatabaseFactoryHolder::Function(f) => f(project_name).map(Arc::new),
            CoverageDatabaseFactoryHolder::Fixture(f) => Ok(f.clone()),
        }
    }
}

pub trait InstallCoverageDataHandlers {
    fn coverage_data_handlers<TP: TestPlatform + 'static>(self) -> Self;
    fn coverage_data_handlers_with_db_factory<TP: TestPlatform + 'static>(
        self,
        factory: web::Data<CoverageDatabaseFactoryHolder<TP>>,
    ) -> Self;
}

impl InstallCoverageDataHandlers for Scope {
    fn coverage_data_handlers<TP: TestPlatform + 'static>(self) -> Self {
        let factory = |project_name: String| create_db::<TP>(project_name);
        self.coverage_data_handlers_with_db_factory::<TP>(web::Data::new(
            CoverageDatabaseFactoryHolder::Function(factory),
        ))
    }

    fn coverage_data_handlers_with_db_factory<TP: TestPlatform + 'static>(
        self,
        factory: web::Data<CoverageDatabaseFactoryHolder<TP>>,
    ) -> Self {
        let size_64_mb = 1 << 26;
        self.app_data(factory)
            // Allow larger content than the default (2MB); a full coverage data upload from an Open Source project
            // (ripgrep) for a "first commit" is about 9MB, so 64MB still gives us some breathing room for larger
            // projects but doesn't go crazy.  Not sure if this is measured before, or after,
            .app_data(JsonConfig::default().limit(size_64_mb))
            .route("/{project}", web::get().to(get_any_coverage_data::<TP>))
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

async fn get_any_coverage_data<TP: TestPlatform>(
    path: web::Path<String>,
    db_factory: web::Data<CoverageDatabaseFactoryHolder<TP>>,
) -> Result<impl Responder, GetCoverageDataError> {
    let project_name = path.into_inner();
    debug!("get_any_coverage_data received: {:?}", project_name);

    let coverage_db = db_factory.get_db(project_name.clone())?;
    // let mut mut_coverage_db = coverage_db.lock().await;

    Ok(HttpResponse::Ok().json(serde_json::to_value(
        coverage_db.has_any_coverage_data().await?,
    )?))
}

async fn get_coverage_data<TP: TestPlatform>(
    path: web::Path<(String, String)>,
    tags: web::Query<HashMap<String, String>>,
    db_factory: web::Data<CoverageDatabaseFactoryHolder<TP>>,
) -> Result<impl Responder, GetCoverageDataError> {
    let (project_name, commit_identifier) = path.into_inner();
    let tags = tags.into_inner();
    debug!(
        "get_coverage_data received: {:?} {:?} {:?}",
        project_name, commit_identifier, tags
    );

    // hashmap -> vec; can't be done in Query<T> because it's considered ordered when query parameters aren't, even
    // though we don't care about order (arguably we're using the wrong data struct inside)
    let tags = tags
        .into_iter()
        .map(|(key, value)| Tag { key, value })
        .collect::<Vec<Tag>>();

    let coverage_db = db_factory.get_db(project_name.clone())?;

    Ok(HttpResponse::Ok().json(
        coverage_db
            .read_coverage_data(&commit_identifier, &tags)
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
    path: web::Path<(String, String)>,
    req: web::Json<PostCoverageDataRequest<TP::TI, TP::CI>>,
    db_factory: web::Data<CoverageDatabaseFactoryHolder<TP>>,
) -> Result<impl Responder, PostCoverageDataError> {
    let (project_name, commit_identifier) = path.into_inner();
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

    let coverage_db = db_factory.get_db(project_name.clone())?;

    coverage_db
        .save_coverage_data(
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
    path: web::Path<String>,
    db_factory: web::Data<CoverageDatabaseFactoryHolder<TP>>,
) -> Result<impl Responder, DeleteCoverageDataError> {
    let project_name = path.into_inner();
    debug!("delete_coverage_data received: {:?}", project_name);

    let coverage_db = db_factory.get_db(project_name.clone())?;

    debug!("web: starting clear_project_data({})", project_name);
    coverage_db.clear_project_data().await?;
    debug!("web: completed clear_project_data({})", project_name);

    Ok(HttpResponse::Ok().json(None::<String>))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use actix_web::{test, App};
    use anyhow::Result;
    use lazy_static::lazy_static;

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
    async fn test_get_coverage_rust() -> Result<()> {
        let test_project = String::from("testtrim-tests-2");
        let coverage_db = create_test_db::<RustTestPlatform>(test_project.clone())?;

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
        coverage_db
            .save_coverage_data(
                &saved_data,
                "test-123-correct-identifier",
                None,
                &Vec::new(),
            )
            .await?;

        let factory = web::Data::new(CoverageDatabaseFactoryHolder::<RustTestPlatform>::Fixture(
            Arc::new(coverage_db),
        ));
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
        let coverage_db = create_test_db::<DotnetTestPlatform>(test_project.clone())?;

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
        coverage_db
            .save_coverage_data(
                &saved_data,
                "test-456-correct-identifier",
                None,
                &Vec::new(),
            )
            .await?;

        let factory = web::Data::new(
            CoverageDatabaseFactoryHolder::<DotnetTestPlatform>::Fixture(Arc::new(coverage_db)),
        );
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
}
