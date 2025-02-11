// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub mod git;

pub trait ScmCommit: Clone {}

// FIXME: it might make sense to split apart some of these functions into smaller traits?  That would allow tests which
// need to create mock implementations a simpler path to doing so...
pub trait Scm<Commit: ScmCommit> {
    fn get_changed_files(&self, commit: &Commit) -> Result<HashSet<PathBuf>>;
    fn get_all_repo_files(&self) -> Result<HashSet<PathBuf>>;
    fn is_working_dir_clean(&self) -> Result<bool>;
    fn get_head_commit(&self) -> Result<Commit>;
    fn get_commit_identifier(&self, commit: &Commit) -> String;
    fn get_commit_parents(&self, commit: &Commit) -> Result<Vec<Commit>>;
    /// Operates similarly to the `git merge-base` command, which finds the most recent common ancestor between multiple
    /// commits.  The expectation is that when `get_commit_parents` returns multiple parents, this function can be used to
    /// "skip" the diverging history and get to the shared ancestor of both commits.
    fn get_best_common_ancestor(&self, commits: &[Commit]) -> Result<Option<Commit>>;
    fn fetch_file_content(&self, commit: &Commit, path: &Path) -> Result<Vec<u8>>;
    fn checkout(&self, commit: &Commit) -> Result<()>;
    /// Remove any working dir garbage that could occur from changing commits.
    ///
    /// The goal is to keep around build output that might be relevant between commits to support incremental builds,
    /// but not keep around files that would otherwise make the working directory dirty.
    ///
    /// Typically this means files that (a) aren't part of the source tree, and (b) were ignored in one commit but not
    /// in another commit.  For example, if commit-a had a "target" directory with build output, but in a later commit-b
    /// that directory was renamed to `build_target` and the scm's ignore files were updated to match, that's the kind
    /// of file we want to cleanup.  `git clean -fd` will perform this in git -- no `-x` (cleaning ignored files).
    fn clean_lightly(&self) -> Result<()>;
}
