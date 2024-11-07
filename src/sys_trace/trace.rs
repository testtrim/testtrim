// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, hash::Hash, path::PathBuf};

#[derive(Debug)]
pub enum UnifiedSocketAddr {
    Inet(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::os::unix::net::SocketAddr),
}

impl PartialEq for UnifiedSocketAddr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Inet(l0), Self::Inet(r0)) => l0 == r0,
            (Self::Unix(l0), Self::Unix(r0)) => {
                if let Some(lpath) = l0.as_pathname()
                    && let Some(rpath) = r0.as_pathname()
                {
                    return lpath == rpath;
                }
                false // assuming all unnamed sockets are also not the same as each other
            }
            _ => false,
        }
    }
}

impl Eq for UnifiedSocketAddr {}

impl Hash for UnifiedSocketAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            UnifiedSocketAddr::Inet(addr) => addr.hash(state),
            UnifiedSocketAddr::Unix(addr) => {
                if let Some(path) = addr.as_pathname() {
                    path.hash(state);
                } else {
                    state.write(&[0, 1, 2, 3]);
                }
            }
        }
    }
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

    pub fn add_open(&mut self, path: PathBuf) {
        self.open_paths.insert(path);
    }

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
