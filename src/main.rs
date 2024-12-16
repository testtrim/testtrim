// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use testtrim::cmd::cli::run_cli;

#[tokio::main]
async fn main() {
    run_cli().await;
}
