// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use lazy_static::lazy_static;
use std::process::Command;
use std::{env, sync::Mutex};
use thiserror::Error;

mod linearcommits_filecoverage;
mod util;

lazy_static! {
    // Avoid running multiple concurrent tests that modify the CWD by having a mutex that each needs to acquire.
    // There's only one of these tests right now but while doing some dev work I had duplicated it and found this
    // problems, so kept this around as a reminder.
    pub static ref CWD_MUTEX: Mutex<i32> = Mutex::new(0);
}

#[derive(Error, Debug)]
pub enum TestError {
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

pub fn git_clone(repo: &str) -> Result<()> {
    // If the environment variable RUST_COVERAGE_SPECIMEN_PAT is set, then we'll compose the repo URL with that token as
    // a PAT for authentication.  Otherwise we'll use the ssh URL and assume that the user's environment will provide
    // the required auth.
    let auth_token = env::var("RUST_COVERAGE_SPECIMEN_PAT").ok();
    let repo_url = match auth_token {
        Some(token) => format!("https://:{}@codeberg.org/testtrim/{}.git", token, repo,),
        None => format!("git@codeberg.org:testtrim/{}.git", repo),
    };

    let output = Command::new("git")
        .args(["clone", &repo_url])
        .output()
        .expect("Failed to execute cargo test command");

    // Check for non-zero exit status
    if !output.status.success() {
        return Err(TestError::SubcommandFailed {
            command: "git clone".to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    Ok(())
}

pub fn git_checkout(commit: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["checkout", commit])
        .output()
        .expect("Failed to execute cargo test command");

    // Check for non-zero exit status
    if !output.status.success() {
        return Err(TestError::SubcommandFailed {
            command: "git checkout".to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    Ok(())
}
