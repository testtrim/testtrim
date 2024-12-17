// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{
    sync::{AcquireError, Semaphore},
    task::JoinSet,
};

use crate::errors::SpawnError;

/// Given a path which is referenced from `relative_to` (eg. "src/module/lib.rs"), normalize it to a relative
/// reference within the absolute path `repo_root` where the files exist.
///
/// The path is canonicalized, and therefore the file must exist.
///
/// For example, if path is "../blah.txt", `relative_to` is "src/module/lib.rs", then "src/blah.txt" would be
/// returned.  `repo_root` is used to ensure that the path reference stays within the repo.
///
/// The expectation is that problems, if they occur, are not errors but might be warnings.  Therefore the parameter
/// `warn` represents a function that can be called to provide contextual warnings about the problem.
pub fn normalize_path<T: FnOnce(&str)>(
    path: &Path,
    relative_to: &Path,
    repo_root: &Path,
    warn: T,
) -> Option<PathBuf> {
    // Target path within the referencing file will be relative to the target file; so first we pretend we're in the
    // referencing file's path and join in the target file name...
    let target_path = if let Some(parent) = relative_to.parent() {
        parent.join(path)
    } else {
        warn("couldn't get relative_to's parent");
        return None;
    };

    // Now the file path may have relative elements in it (eg. ../../some/thing); we need a canonical form of the
    // path in order to strip the repo root.  This will fail if the file doesn't exist.
    let target_path = match target_path.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) => {
            warn(&format!("error occurred in canonicalize: {e:?}"));
            return None;
        }
    };

    // Now we strip the repo root so that we get to the repo-relative path to the included file, which is the form
    // that we'll later look for this file when we do a git diff to see changed files.
    let target_path = match target_path.strip_prefix(repo_root) {
        Ok(stripped) => stripped,
        Err(e) => {
            warn(&format!("error occurred stripping repo root: {e:?}"));
            return None;
        }
    };

    Some(PathBuf::from(target_path))
}

/// Run any number of futures, but limited in concurrency by `max_concurrency`.
pub async fn spawn_limited_concurrency<F>(
    max_concurrency: usize,
    futures: Vec<F>,
) -> Result<Vec<F::Output>, SpawnError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let mut results = Vec::with_capacity(futures.len());
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut set = JoinSet::new();

    for future in futures {
        let my_semaphore = semaphore.clone();
        set.spawn(async move {
            let _permit = my_semaphore.acquire().await?;
            Ok::<_, AcquireError>(future.await)
        });
    }

    while let Some(res) = set.join_next().await {
        let run_task_response = res??;
        results.push(run_task_response);
    }

    Ok(results)
}
