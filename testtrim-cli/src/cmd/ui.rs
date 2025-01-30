// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::fmt::Debug;
use tracing::field::Visit;

#[derive(Default, Debug)]
pub struct RawUiInformation {
    // FIXME: make a ".into()" for RawUiInformation, which has to collect data field-by-field, to collapse data into a
    // more Rust-y data structure where data fields are unifieid and standardized.  Then RawUiInformation's fields can
    // be !pub
    pub ui_stage: Option<UiStage>,
    pub is_subcommand: bool,
    pub subcommand_binary: Option<String>,
    pub subcommand_args: Option<String>,
    pub test_count: Option<u64>,
    pub test_case: Option<String>,
}

impl Visit for RawUiInformation {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "subcommand_args" {
            self.subcommand_args = Some(format!("{value:?}"));
        }
        if field.name() == "test_case" {
            self.test_case = Some(format!("{value:?}"));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "ui_stage" {
            self.ui_stage = UiStage::try_from(value).ok();
        }
        if field.name() == "test_count" {
            self.test_count = Some(value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "subcommand_binary" {
            self.subcommand_binary = Some(String::from(value));
        }
        if field.name() == "subcommand_args" {
            self.subcommand_args = Some(String::from(value));
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if field.name() == "subcommand" {
            self.is_subcommand = value;
        }
    }
}

// FIXME: In the future maybe we should use `valuable` to store these in the traces
// (https://docs.rs/tracing/latest/tracing/field/index.html#using-valuable), but currently it is unstable and I don't
// want to jump on that.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u64)]
pub enum UiStage {
    // GetTestIdentifiers...
    Compiling,
    ListingTests,
    FindingAncestorCommit,
    ComputeTestCases,

    // RunTests...
    RunTests,
    RunSingleTest,
    WriteCoverageData,
}
