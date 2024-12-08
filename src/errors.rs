// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{io, path::PathBuf};
use thiserror::Error;

use crate::{coverage::CoverageDatabaseError, platform::TestIdentifierCore};

#[derive(Error, Debug)]
pub enum SubcommandErrors {
    #[error(
        "test sub-command '{command:?}' failed with exit code {status:?} and stderr {stderr:?})"
    )]
    SubcommandFailed {
        command: String,
        status: std::process::ExitStatus,
        stderr: String,
    },

    #[error("test sub-command '{command:?}' had unparseable output; error: {error:?} output: {output:?})")]
    SubcommandOutputParseFailed {
        command: String,
        error: String,
        output: String,
    },
}

#[derive(Debug)]
pub enum TestFailure {
    NonZeroExitCode {
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },
}

#[derive(Debug)]
pub struct FailedTestResult {
    pub test_identifier: Box<dyn TestIdentifierCore>,
    pub failure: TestFailure,
}

/// Error running a single test.
#[derive(Error, Debug)]
pub enum RunTestError {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("test was executed but failed: {0:?}")]
    TestExecutionFailure(FailedTestResult),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Error that occurred while running a suite of tests.
#[derive(Error, Debug)]
pub enum RunTestsErrors {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    RecvError(#[from] std::sync::mpsc::RecvError),

    /// TestExecutionFailure(s) from the test suite will be consolidated into this enum value.
    #[error("one or more tests failed: {0:?}")]
    TestExecutionFailures(Vec<FailedTestResult>),

    /// Any `RunTestError` other than a `TestExecutionFailure` will be passed-through via `UnexpectedTestError`.
    #[error(transparent)]
    UnexpectedTestError(#[from] RunTestError),
}

/// Error that occurred while running the "run-tests" command.
#[derive(Error, Debug)]
pub enum RunTestsCommandErrors {
    #[error(
        "the CleanCommit mode cannot be used as the working directory is dirty; either clean the directory, use the WorkingTree mode, or override with OverrideCleanCommit"
    )]
    CleanCommitWorkingDirectoryDirty,

    #[error(transparent)]
    CoverageDatabaseError(#[from] CoverageDatabaseError),

    #[error(transparent)]
    RunTestsErrors(#[from] RunTestsErrors),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum RustLlvmError {
    #[error(
        "attempted to read data about a binary file that was not in the coverage library: {0:?}"
    )]
    LibraryMissingBinary(PathBuf),

    #[error("coverage point found in profiling data was not found in binary's coverage map")]
    CoverageMismatch,
}
