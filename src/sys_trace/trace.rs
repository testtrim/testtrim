// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, path::PathBuf};

pub struct Trace {
    open_paths: HashSet<PathBuf>,
}

impl Trace {
    pub fn new() -> Trace {
        Trace {
            open_paths: HashSet::new(),
        }
    }

    pub fn add_open(&mut self, path: PathBuf) {
        self.open_paths.insert(path);
    }

    pub fn get_open_paths(&self) -> &HashSet<PathBuf> {
        &self.open_paths
    }
}
