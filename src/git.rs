use crate::SubcommandErrors;
use anyhow::Result;
use std::collections::HashSet;
use std::iter;
use std::path::PathBuf;
use std::process::Command;

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

// FIXME: reimplement in a way that doesn't use a git subcommand; shouldn't really be necessary
// FIXME: this has no logic that relats to non-linear commit histories; ie. merges
pub fn get_previous_commits() -> impl Iterator<Item = Result<String>> {
    get_previous_commits_internal(&CommandLineGitLogBatchFetcher {})
}

trait GetBatchFetcher {
    fn get_previous_commits_batch(&self, skip: i32, batch_size: i32) -> Result<Vec<String>>;
}

fn get_previous_commits_internal<T: GetBatchFetcher>(
    fetcher: &T,
) -> impl Iterator<Item = Result<String>> + '_ {
    let mut current_batch: Option<Vec<String>> = None;
    let mut current_batch_idx = 0;
    let mut skip = 0;
    let batch_size = 100;

    iter::from_fn(move || {
        if current_batch.is_some() {
            let batch = current_batch.as_ref().unwrap();
            if batch.is_empty() {
                return None;
            } else if let Some(retval) = batch.get(current_batch_idx) {
                current_batch_idx += 1;
                return Some(Ok(retval.clone()));
            } else {
                current_batch = None;
                skip += batch_size;
            }
        }

        if current_batch.is_none() {
            match fetcher.get_previous_commits_batch(skip, batch_size) {
                Ok(batch) => {
                    current_batch = Some(batch);
                    current_batch_idx = 0;
                }
                Err(e) => {
                    return Some(Err(e));
                }
            }
        }

        let batch = current_batch.as_ref().unwrap();
        if batch.is_empty() {
            None
        } else if let Some(retval) = batch.get(current_batch_idx) {
            current_batch_idx += 1;
            Some(Ok(retval.clone()))
        } else {
            unreachable!("doesn't make sense that the batch was just initialized, was not empty, but can't get an item");
        }
    })
}

struct CommandLineGitLogBatchFetcher;

impl GetBatchFetcher for CommandLineGitLogBatchFetcher {
    fn get_previous_commits_batch(&self, skip: i32, batch_size: i32) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args([
                "log",
                "--pretty=oneline",
                &format!("--max-count={}", batch_size),
                &format!("--skip={}", skip),
            ])
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    struct MockBatchFetcher {
        batches: Vec<Vec<String>>,
    }

    impl GetBatchFetcher for MockBatchFetcher {
        fn get_previous_commits_batch(&self, skip: i32, batch_size: i32) -> Result<Vec<String>> {
            let index = (skip / batch_size) as usize;
            if index < self.batches.len() {
                Ok(self.batches[index].clone())
            } else {
                Ok(vec![])
            }
        }
    }

    #[test]
    fn test_get_previous_commits_internal() {
        let mock_fetcher = MockBatchFetcher {
            batches: vec![
                vec!["commit1".to_string(), "commit2".to_string()],
                vec!["commit3".to_string()],
                vec![],
            ],
        };

        let commits: Vec<String> = get_previous_commits_internal(&mock_fetcher)
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert_eq!(commits, vec!["commit1", "commit2", "commit3"]);
    }

    #[test]
    fn test_get_previous_commits_internal_empty() {
        let mock_fetcher = MockBatchFetcher { batches: vec![] };

        let commits: Vec<String> = get_previous_commits_internal(&mock_fetcher)
            .collect::<Result<Vec<_>>>()
            .unwrap();

        let empty: Vec<String> = vec![];
        assert_eq!(commits, empty);
    }

    #[test]
    fn test_get_previous_commits_internal_error() {
        struct ErrorBatchFetcher;

        impl GetBatchFetcher for ErrorBatchFetcher {
            fn get_previous_commits_batch(
                &self,
                _skip: i32,
                _batch_size: i32,
            ) -> Result<Vec<String>> {
                Err(anyhow!("Error fetching batch").into())
            }
        }

        let error_fetcher = ErrorBatchFetcher;

        let result: Result<Vec<String>> =
            get_previous_commits_internal(&error_fetcher).collect::<Result<Vec<_>>>();

        assert!(result.is_err());
    }
}
