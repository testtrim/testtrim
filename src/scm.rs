use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;

pub trait Scm {
    fn get_changed_files(&self, commit: &str) -> Result<HashSet<PathBuf>>;
    fn get_previous_commits(&self) -> impl Iterator<Item = Result<String>>;
    fn get_revision_sha(&self, commit: &str) -> Result<String>;
}
