use crate::SubcommandErrors;
use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

// FIXME: move into a git module
// FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
// FIXME: remove 'pub' after integration test is changed to use CLI
// run `git diff` to fetch all the file names changed in a specific commit; eg. git diff --name-only some-commit^ some-commit
pub fn get_changed_files(commit: &str) -> Result<HashSet<PathBuf>> {
    let mut output = Command::new("git")
        .args(["diff", "--name-only", &format!("{commit}^"), commit])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("^': unknown revision or path not in the working tree") {
            // Couldn't find the parent commit ({str}^) for the commit ({str}).  That's a valid case if it's the first
            // commit in the repository.  In that case, replace the base commit with the well-known sha1 of the root git
            // commit, giving us all the changes in the original commit.
            // FIXME: this hard-codes the usage of a sha1 git repo
            let repo_root = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
            output = Command::new("git")
                .args(["diff", "--name-only", repo_root, commit])
                .output()?;
        }
    }

    if !output.status.success() {
        return Err(SubcommandErrors::SubcommandFailed {
            command: format!("git diff --name-only {commit}^ {commit}").to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    // FIXME: this doesn't seem like it will handle platform-specific file name encodings correctly
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().map(PathBuf::from).collect())
}

// FIXME: move into a git module
// FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
pub fn get_revision_sha(commit: &str) -> Result<String> {
    let output = Command::new("git").args(["rev-parse", commit]).output()?;

    if !output.status.success() {
        return Err(SubcommandErrors::SubcommandFailed {
            command: format!("git rev-parse {commit}").to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(String::from(stdout.trim()))
}

// FIXME: move into a git module
// FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
// FIXME: this has no logic that relats to non-linear commit histories; ie. merges
pub fn get_previous_commits() -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["log", "--pretty=oneline"])
        .output()?;

    if !output.status.success() {
        return Err(SubcommandErrors::SubcommandFailed {
            command: "git log --pretty=oneline".to_string(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout
        .lines()
        .map(|s| s.split(" ").next().unwrap())
        .map(String::from)
        .collect())
}
