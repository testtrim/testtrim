// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum RunTestsErrors {
    #[error(
        "the CleanCommit mode cannot be used as the working directory is dirty; either clean the directory, use the WorkingTree mode, or override with OverrideCleanCommit"
    )]
    CleanCommitWorkingDirectoryDirty,
}
