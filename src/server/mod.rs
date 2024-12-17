// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::ToSocketAddrs;

use actix_web::{
    dev::{ServiceFactory, ServiceRequest},
    get, middleware, web, App, HttpRequest, HttpServer, Scope,
};
use coverage_data::InstallCoverageDataHandlers as _;
use log::debug;

use crate::platform::{
    dotnet::DotnetTestPlatform, golang::GolangTestPlatform, rust::RustTestPlatform, TestPlatform,
};

pub mod coverage_data;

#[get("/")]
async fn index(req: HttpRequest) -> &'static str {
    debug!("REQ: {req:?}");
    "Hello world!\r\n"
}

pub trait InstallTestPlatform {
    fn platform<TP: TestPlatform + 'static>(self) -> Self;
}

impl<T> InstallTestPlatform for Scope<T>
where
    T: ServiceFactory<ServiceRequest, Config = (), Error = actix_web::Error, InitError = ()>,
{
    fn platform<TP: TestPlatform + 'static>(self) -> Self {
        self.service(web::scope("/coverage-data").coverage_data_handlers::<TP>())
    }
}

pub async fn cli(socket_addrs: impl ToSocketAddrs) {
    run_server(socket_addrs).await.expect("run_server failure");
}

async fn run_server(socket_addrs: impl ToSocketAddrs) -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            // WARN: Do not change without adjusting test_zstd_compression; see FIXME comment there
            .wrap(middleware::Compress::default())
            .service(index)
            .service(
                web::scope("/api/v0")
                    .service(
                        web::scope(RustTestPlatform::platform_identifier())
                            .platform::<RustTestPlatform>(),
                    )
                    .service(
                        web::scope(DotnetTestPlatform::platform_identifier())
                            .platform::<DotnetTestPlatform>(),
                    )
                    .service(
                        web::scope(GolangTestPlatform::platform_identifier())
                            .platform::<GolangTestPlatform>(),
                    ),
            )
    })
    .bind(socket_addrs)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use actix_web::{
        http::header::{
            AcceptEncoding, ContentEncoding, Encoding, Header, Preference, QualityItem,
        },
        test, App, HttpMessage,
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
        // FIXME: this is a pretty dumb test because no subject is under-test other than Actix.  The compression
        // middleware is installed in this test, and then tested in this test.  But I haven't been successful yet in
        // breaking up the App initialization into pieces that can be reused in this test, so it's good enough for the
        // short-term to suggest to me that the compression will work.

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
}
