// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::ExitCode;

use testtrim::cmd::cli::run_cli;

#[tokio::main]
async fn main() -> ExitCode {
    run_cli().await
}
