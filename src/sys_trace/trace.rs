// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, hash::Hash, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnifiedSocketAddr {
    Inet(std::net::SocketAddr),

    // Because unix::net::SocketAddr is only buildable on Unix (even though we might need to deserialize this data on
    // another platform), and, we don't really *use* the SocketAddr (eg. for connecting), the Unix version of this enum
    // just keeps a PathBuf.
    Unix(PathBuf),
}

pub struct Trace {
    open_paths: HashSet<PathBuf>,
    connect_sockets: HashSet<UnifiedSocketAddr>,
}

impl Trace {
    pub fn new() -> Trace {
        Trace {
            open_paths: HashSet::new(),
            connect_sockets: HashSet::new(),
        }
    }

    #[allow(dead_code)] // may not be used on a platform that doesn't support tracing yet
    pub fn add_open(&mut self, path: PathBuf) {
        self.open_paths.insert(path);
    }

    #[allow(dead_code)] // may not be used on a platform that doesn't support tracing yet
    pub fn add_connect(&mut self, socket: UnifiedSocketAddr) {
        self.connect_sockets.insert(socket);
    }

    #[must_use]
    pub fn get_open_paths(&self) -> &HashSet<PathBuf> {
        &self.open_paths
    }

    #[must_use]
    pub fn get_connect_sockets(&self) -> &HashSet<UnifiedSocketAddr> {
        &self.connect_sockets
    }
}
