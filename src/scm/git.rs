use crate::scm::{Scm, ScmCommit};
use crate::SubcommandErrors;
use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

pub struct GitScmCommit {
    sha: String,
}

impl ScmCommit for GitScmCommit {}

pub struct GitScm;

impl GitScm {
    // FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
    fn get_revision_sha(&self, commit: &str) -> Result<String> {
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
}

impl Scm<GitScmCommit> for GitScm {
    // FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
    fn get_changed_files(&self, commit: &GitScmCommit) -> Result<HashSet<PathBuf>> {
        let output = Command::new("git")
            .args(["diff", "--name-only", &commit.sha])
            .output()?;

        // This case shouldn't be needed anymore since we'll only diff when we've found an ancestor commit.
        // if !output.status.success() {
        //     let stderr = String::from_utf8_lossy(&output.stderr);
        //     if stderr.contains("^': unknown revision or path not in the working tree") {
        //         // Couldn't find the parent commit ({str}^) for the commit ({str}).  That's a valid case if it's the first
        //         // commit in the repository.  In that case, replace the base commit with the well-known sha1 of the root git
        //         // commit, giving us all the changes in the original commit.
        //         // FIXME: this hard-codes the usage of a sha1 git repo
        //         let repo_root = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
        //         output = Command::new("git")
        //             .args(["diff", "--name-only", repo_root, commit])
        //             .output()?;
        //     }
        // }

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
            .output()?;

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

        let output = Command::new("git").args(&args).output()?;

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
            .output()?;

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
            .output()?;

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
}
