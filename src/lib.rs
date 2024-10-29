// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![feature(let_chains)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unused_self)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::items_after_statements)] // maybe should warn on it, but currently use this pattern and like it
#![allow(clippy::too_many_lines)] // probably the right thing to warn on, but somewhat arbitrary

pub mod cmd;
mod commit_coverage_data;
mod db;
pub mod errors;
mod full_coverage_data;
pub mod platform;
mod schema;
pub mod scm;
mod sys_trace;
mod timing_tracer;
mod util;
