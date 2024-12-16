// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::ToSocketAddrs;

use actix_web::{get, web, App, HttpRequest, HttpServer, Scope};
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

impl InstallTestPlatform for Scope {
    fn platform<TP: TestPlatform + 'static>(self) -> Self {
        self.service(web::scope("/coverage-data").coverage_data_handlers::<TP>())
    }
}

pub async fn cli(socket_addrs: impl ToSocketAddrs) {
    run_server(socket_addrs).await.expect("run_server failure");
}

async fn run_server(socket_addrs: impl ToSocketAddrs) -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().service(index).service(
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
    use actix_web::{http::header::ContentType, test, App};

    use super::*;

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
}
