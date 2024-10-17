// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub mod git;

pub trait ScmCommit {}

pub trait Scm<Commit: ScmCommit> {
    fn get_changed_files(&self, commit: &Commit) -> Result<HashSet<PathBuf>>;
    fn is_working_dir_clean(&self) -> Result<bool>;
    fn get_head_commit(&self) -> Result<Commit>;
    fn get_commit_identifier(&self, commit: &Commit) -> String;
    fn get_commit_parents(&self, commit: &Commit) -> Result<Vec<Commit>>;
    /// Operates similarly to the `git merge-base` command, which finds the most recent common ancestor between multiple
    /// commits.  The expectation is that when get_commit_parents returns multiple parents, this function can be used to
    /// "skip" the diverging history and get to the shared ancestor of both commits.
    fn get_best_common_ancestor(&self, commits: &[Commit]) -> Result<Option<Commit>>;
    fn fetch_file_content(&self, commit: &Commit, path: &Path) -> Result<Vec<u8>>;
}
