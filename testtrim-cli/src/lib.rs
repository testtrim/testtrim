// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

// #![feature(once_cell_try)]
// #![feature(path_add_extension)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unused_self)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::items_after_statements)] // maybe should warn on it, but currently use this pattern and like it
#![allow(clippy::too_many_lines)] // probably the right thing to warn on, but somewhat arbitrary
#![warn(clippy::print_stderr)]
#![warn(clippy::print_stdout)]
#![warn(clippy::string_slice)]

pub mod cmd;
pub mod coverage;
pub mod errors;
mod network;
#[cfg(target_family = "unix")]
mod nsncd;
pub mod platform;
mod repo_config;
mod schema;
pub mod scm;
mod server;
pub mod sys_trace;
pub mod timing_tracer;
mod util;

// allow-print-in-tests
