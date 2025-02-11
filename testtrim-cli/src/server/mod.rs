// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{net::ToSocketAddrs, time::Duration};

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, Scope,
    dev::{ServiceFactory, ServiceRequest},
    get,
    http::Method,
    middleware, web,
};
use anyhow::Result;
use coverage_data::InstallCoverageDataHandlers as _;
use log::{Log, info, set_boxed_logger, trace, warn};

use crate::{
    coverage::{CoverageDatabase as _, CoverageDatabaseDispatch, create_db},
    platform::{
        TestPlatform, dotnet::DotnetTestPlatform, golang::GolangTestPlatform,
        rust::RustTestPlatform,
    },
};

pub mod coverage_data;

#[get("/")]
async fn index(req: HttpRequest) -> &'static str {
    trace!("REQ: {req:?}");
    "Hello world!\r\n"
}

pub trait InstallTestPlatform {
    fn platform<TP: TestPlatform + 'static>(self) -> Result<Self>
    where
        Self: Sized;
    #[allow(dead_code)] // used in tests only
    fn platform_with_db_factory<TP: TestPlatform + 'static>(
        self,
        factory: web::Data<CoverageDatabaseDispatch>,
    ) -> Self;
}

impl<T> InstallTestPlatform for Scope<T>
where
    T: ServiceFactory<ServiceRequest, Config = (), Error = actix_web::Error, InitError = ()>,
{
    fn platform<TP: TestPlatform + 'static>(self) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(self.service(web::scope("/coverage-data").coverage_data_handlers::<TP>()?))
    }
    fn platform_with_db_factory<TP: TestPlatform + 'static>(
        self,
        factory: web::Data<CoverageDatabaseDispatch>,
    ) -> Self {
        self.service(
            web::scope("/coverage-data").coverage_data_handlers_with_db_factory::<TP>(factory),
        )
    }
}

pub async fn cli(logger: Box<dyn Log>, socket_addrs: impl ToSocketAddrs) {
    set_boxed_logger(logger).unwrap();
    run_server(socket_addrs).await.expect("run_server failure");
}

async fn run_server(socket_addrs: impl ToSocketAddrs) -> std::io::Result<()> {
    tokio::spawn(intermittent_cleanup());
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            // WARN: Do not change without adjusting test_zstd_compression; see comment there
            .wrap(middleware::Compress::default())
            .service(index)
            .service(
                web::scope("/api/v0")
                    .route("", web::method(Method::OPTIONS).to(options_api_v0))
                    .service(
                        web::scope(RustTestPlatform::platform_identifier())
                            .platform::<RustTestPlatform>()
                            .unwrap(),
                    )
                    .service(
                        web::scope(DotnetTestPlatform::platform_identifier())
                            .platform::<DotnetTestPlatform>()
                            .unwrap(),
                    )
                    .service(
                        web::scope(GolangTestPlatform::platform_identifier())
                            .platform::<GolangTestPlatform>()
                            .unwrap(),
                    ),
            )
    })
    .bind(socket_addrs)?
    .run()
    .await
}

async fn options_api_v0() -> impl Responder {
    HttpResponse::Ok().json(vec!["read_first_available_coverage_data"])
}

async fn intermittent_cleanup() {
    let remove_older_than = Duration::from_secs(14 * 24 * 60 * 60);
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));

    loop {
        interval.tick().await;
        do_intermittent_cleanup(&remove_older_than).await;
    }
}

async fn do_intermittent_cleanup(remove_older_than: &Duration) {
    match create_db() {
        Ok(db) => {
            info!("Performing intermittent cleanup");
            if let Err(e) = db.intermittent_clean(remove_older_than).await {
                warn!("Error during intermittent cleanup: {e:?}");
            }
        }
        Err(e) => {
            warn!("Unable to create database for intermittent cleanup: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App, HttpMessage,
        http::header::{
            AcceptEncoding, ContentEncoding, Encoding, Header, Preference, QualityItem,
        },
        test,
    };

    use super::*;

    #[actix_web::test]
    async fn test_index_get() {
        let app = test::init_service(App::new().service(index)).await;
        let req = test::TestRequest::default().to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_zstd_compression() {
        // This is a pretty dumb test because no subject is under-test other than Actix.  The compression middleware is
        // installed in this test, and then tested in this test.  But I haven't been successful yet in breaking up the
        // App initialization into pieces that can be reused in this test, so it's good enough for the short-term to
        // suggest to me that the compression will work.

        let app = test::init_service(
            App::new()
                .wrap(middleware::Compress::default())
                .service(index),
        )
        .await;
        let req = test::TestRequest::default()
            .insert_header(AcceptEncoding(vec![QualityItem::max(
                Preference::Specific(Encoding::zstd()),
            )]))
            .to_request();
        println!("req headers: {:?}", req.headers());
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        println!("resp headers: {:?}", resp.headers());
        assert_eq!(
            resp.headers().get(ContentEncoding::name()),
            Some(&ContentEncoding::Zstd.to_header_value())
        );
    }

    #[actix_web::test]
    async fn test_index_post() {
        let app = test::init_service(App::new().service(index)).await;
        let req = test::TestRequest::post().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }

    #[actix_web::test]
    async fn test_api_v0_options() {
        let app = test::init_service(
            App::new().route("/", web::method(Method::OPTIONS).to(options_api_v0)),
        )
        .await;
        let req = test::TestRequest::default()
            .method(Method::OPTIONS)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
