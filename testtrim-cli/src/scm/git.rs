// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::errors::SubcommandErrors;
use crate::scm::{Scm, ScmCommit};
use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone)]
pub struct GitScmCommit {
    sha: String,
}

impl ScmCommit for GitScmCommit {}

pub struct GitScm {
    project_dir: PathBuf,
}

impl GitScm {
    #[must_use]
    pub fn new(project_dir: PathBuf) -> Self {
        Self { project_dir }
    }

    // FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
    fn get_revision_sha(&self, commit: &str) -> Result<String> {
        let output = Command::new("git")
            .args(["rev-parse", commit])
            .current_dir(&self.project_dir)
            .output()?;

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
}

impl Scm<GitScmCommit> for GitScm {
    // FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
    fn get_changed_files(&self, commit: &GitScmCommit) -> Result<HashSet<PathBuf>> {
        let output = Command::new("git")
            .args(["diff", "--name-only", &commit.sha])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git diff ...".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("git diff --name-only {}", &commit.sha).to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        // FIXME: this doesn't seem like it will handle platform-specific file name encodings correctly
        let stdout = String::from_utf8(output.stdout)?;
        Ok(stdout.lines().map(PathBuf::from).collect())
    }

    fn get_all_repo_files(&self) -> Result<HashSet<PathBuf>> {
        let output = Command::new("git")
            .args(["ls-files"])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git ls-files".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("git ls-files"),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        // FIXME: this doesn't seem like it will handle platform-specific file name encodings correctly
        let stdout = String::from_utf8(output.stdout)?;
        Ok(stdout.lines().map(PathBuf::from).collect())
    }

    fn get_head_commit(&self) -> Result<GitScmCommit> {
        Ok(GitScmCommit {
            sha: self.get_revision_sha("HEAD")?,
        })
    }

    fn get_commit_identifier(&self, commit: &GitScmCommit) -> String {
        commit.sha.clone()
    }

    fn get_commit_parents(&self, commit: &GitScmCommit) -> Result<Vec<GitScmCommit>> {
        let output = Command::new("git")
            .args(["rev-list", "--parents", "-n", "1", &commit.sha])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git rev-list ...".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("git rev-list --parents -n 1 {}", commit.sha).to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        let mut parents = stdout.split_whitespace().collect::<Vec<_>>();
        let first_commit = parents.remove(0);
        if first_commit != commit.sha {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("git rev-list --parents -n 1 {}", commit.sha).to_string(),
                status: output.status,
                stderr: format!(
                    "Expected first commit to be {:?}, but got {first_commit:?}",
                    commit.sha
                ),
            }
            .into());
        }

        Ok(parents
            .into_iter()
            .map(|sha| GitScmCommit {
                sha: String::from(sha),
            })
            .collect())
    }

    fn get_best_common_ancestor(&self, commits: &[GitScmCommit]) -> Result<Option<GitScmCommit>> {
        let mut args = vec!["merge-base"];
        for c in commits {
            args.push(c.sha.as_str());
        }

        let output = Command::new("git")
            .args(&args)
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git merge-base ...".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("git merge-base ({} commits)", args.len() - 1).to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        // FIXME: it's probably possible for this to return no common base, which would be the Ok(None) case, but this
        // code isn't detecting that case
        Ok(Some(GitScmCommit {
            sha: String::from(stdout.trim()),
        }))
    }

    fn is_working_dir_clean(&self) -> Result<bool> {
        let output = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git status --porcelain".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("git status --porcelain"),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        Ok(stdout.trim() == "")
    }

    fn fetch_file_content(&self, commit: &GitScmCommit, path: &std::path::Path) -> Result<Vec<u8>> {
        let output = Command::new("git")
            .args([
                "show",
                &format!("{}:{}", &commit.sha, path.to_str().unwrap()),
            ])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git show ...".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("git show {}:{}", &commit.sha, path.to_str().unwrap()),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        Ok(output.stdout)
    }

    fn checkout(&self, commit: &GitScmCommit) -> Result<()> {
        let output = Command::new("git")
            .args(["checkout", &commit.sha])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git checkout ...".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: format!("git checkout {}", &commit.sha),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        Ok(())
    }

    fn clean_lightly(&self) -> Result<()> {
        let output = Command::new("git")
            .args(["clean", "-f", "-d"])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "git clean -f -d".to_string(),
                error: e,
            })?;

        if !output.status.success() {
            return Err(SubcommandErrors::SubcommandFailed {
                command: String::from("git clean -f -d"),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }

        Ok(())
    }
}
