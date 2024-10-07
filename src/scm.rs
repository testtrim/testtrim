use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;

pub trait ScmCommit {}

pub trait Scm<Commit: ScmCommit> {
    fn get_changed_files(&self, commit: &str) -> Result<HashSet<PathBuf>>;
    fn get_previous_commits(&self) -> impl Iterator<Item = Result<String>>;
    fn get_revision_sha(&self, commit: &str) -> Result<String>;

    fn get_head_commit(&self) -> Result<Commit>;

    fn get_commit_identifier(&self, commit: &Commit) -> String;
    fn get_commit_parents(&self, commit: &Commit) -> Result<Vec<Commit>>;

    /// Operates similarly to the `git merge-base` command, which finds the most recent common ancestor between multiple
    /// commits.  The expectation is that when get_commit_parents returns multiple parents, this function can be used to
    /// "skip" the diverging history and get to the shared ancestor of both commits.
    fn get_best_common_ancestor(&self, commits: &[Commit]) -> Result<Option<Commit>>;
}
