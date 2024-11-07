// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, fmt, hash::Hash, path::PathBuf};

use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize,
};

#[derive(Debug, Clone)]
pub enum UnifiedSocketAddr {
    Inet(std::net::SocketAddr),

    // FIXME: since this is going to compile-time disappear on non-unix platforms, but the type is serializable, then it
    // won't be deserializable on other platforms and instead we'll get runtime errors...
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

impl Serialize for UnifiedSocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("UnifiedSocketAddr", 2)?;
        match *self {
            UnifiedSocketAddr::Inet(ref addr) => {
                state.serialize_field("type", "Inet")?;
                state.serialize_field("addr", &addr.to_string())?;
            }
            #[cfg(unix)]
            UnifiedSocketAddr::Unix(ref addr) => {
                state.serialize_field("type", "Unix")?;
                state.serialize_field(
                    "addr",
                    addr.as_pathname()
                        .ok_or_else(|| {
                            serde::ser::Error::custom("Failed to serialize Unix socket address")
                        })?
                        .to_str()
                        .ok_or_else(|| serde::ser::Error::custom("Non-UTF8 Unix socket path"))?,
                )?;
            }
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for UnifiedSocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UnifiedSocketAddrVisitor;

        impl<'de> Visitor<'de> for UnifiedSocketAddrVisitor {
            type Value = UnifiedSocketAddr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a struct representing a UnifiedSocketAddr")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut addr_type: Option<String> = None;
                let mut addr: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            addr_type = Some(map.next_value()?);
                        }
                        "addr" => {
                            addr = Some(map.next_value()?);
                        }
                        _ => return Err(de::Error::unknown_field(&key, &["type", "addr"])),
                    }
                }
                let addr_type = addr_type.ok_or_else(|| de::Error::missing_field("type"))?;
                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;

                match addr_type.as_str() {
                    "Inet" => {
                        let inet_addr = addr.parse().map_err(de::Error::custom)?;
                        Ok(UnifiedSocketAddr::Inet(inet_addr))
                    }
                    "Unix" => {
                        #[cfg(unix)]
                        {
                            let unix_addr =
                                std::os::unix::net::SocketAddr::from_pathname(PathBuf::from(addr))
                                    .map_err(|_| de::Error::custom("Invalid Unix socket path"))?;
                            Ok(UnifiedSocketAddr::Unix(unix_addr))
                        }
                        #[cfg(not(unix))]
                        {
                            Err(de::Error::custom(
                                "Unix socket addresses are not supported on this platform",
                            ))
                        }
                    }
                    _ => Err(de::Error::custom("unknown addr type")),
                }
            }
        }

        deserializer.deserialize_struct(
            "UnifiedSocketAddr",
            &["type", "addr"],
            UnifiedSocketAddrVisitor,
        )
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
