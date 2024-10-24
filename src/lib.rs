#![feature(let_chains)]

// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod cmd;
mod commit_coverage_data;
mod db;
mod errors;
mod full_coverage_data;
pub mod platform;
mod rust_llvm;
mod schema;
pub mod scm;
mod sys_trace;
mod timing_tracer;
