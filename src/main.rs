// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::Parser;
use testtrim::{process_command, Cli};

fn main() {
    let cli = Cli::parse();
    process_command(cli);
}
