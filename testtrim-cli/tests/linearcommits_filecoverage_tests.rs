// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;
use std::time::Duration;
use testtrim::timing_tracer::RunTestTiming;
use thiserror::Error;
use tokio::sync::Mutex;

mod linearcommits_filecoverage;
mod util;

// Avoid running multiple concurrent tests that modify the CWD by having a mutex that each needs to acquire. There's
// only one of these tests right now but while doing some dev work I had duplicated it and found this problems, so kept
// this around as a reminder.
pub static CWD_MUTEX: LazyLock<Mutex<i32>> = LazyLock::new(|| Mutex::new(0));

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
    #[error(
        "test sub-command '{command:?}' had unparseable output; error: {error:?} output: {output:?})"
    )]
    SubcommandOutputParseFailed {
        command: String,
        error: String,
        output: String,
    },
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn git_clone(repo: &str) -> Result<()> {
    // If the environment variable RUST_COVERAGE_SPECIMEN_PAT is set, then we'll compose the repo URL with that token as
    // a PAT for authentication.  Otherwise we'll use the ssh URL and assume that the user's environment will provide
    // the required auth.
    let auth_token = env::var("RUST_COVERAGE_SPECIMEN_PAT").ok();
    let repo_url = match auth_token {
        Some(token) => format!("https://:{token}@codeberg.org/testtrim/{repo}.git"),
        None => format!("git@codeberg.org:testtrim/{repo}.git"),
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

pub fn assert_performance_tracing(timings: RunTestTiming) {
    assert_ne!(
        timings.discover_tests,
        Duration::ZERO,
        "discover_tests timing was 0"
    );
    assert_ne!(
        timings.read_historical_coverage_data,
        Duration::ZERO,
        "read_historical_coverage_data timing was 0"
    );
    assert_ne!(
        timings.test_determination,
        Duration::ZERO,
        "test_determination timing was 0"
    );
    assert_ne!(
        timings.addt_platform_specific_test_determination,
        Duration::ZERO,
        "addt_platform_specific_test_determination timing was 0"
    );
    assert_ne!(timings.run_tests, Duration::ZERO, "run_tests timing was 0");
    assert_ne!(
        timings.read_new_coverage_data,
        Duration::ZERO,
        "read_new_coverage_data timing was 0"
    );
    assert_ne!(
        timings.write_new_coverage_data,
        Duration::ZERO,
        "write_new_coverage_data timing was 0"
    );
}
