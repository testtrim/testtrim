// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    hash::Hash,
    net::IpAddr,
    path::PathBuf,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnifiedSocketAddr {
    Inet(std::net::SocketAddr),

    // Because unix::net::SocketAddr is only buildable on Unix (even though we might need to deserialize this data on
    // another platform), and, we don't really *use* the SocketAddr (eg. for connecting), the Unix version of this enum
    // just keeps a PathBuf.
    Unix(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolvedSocketAddr {
    pub address: UnifiedSocketAddr,
    pub hostnames: BTreeSet<String>, // implements Hash, whereas HashSet doesn't; ordering is not important though
}

// Not a functionality that I want to do often, but reduces code complexity in some tests:
#[cfg(test)]
impl From<UnifiedSocketAddr> for ResolvedSocketAddr {
    fn from(value: UnifiedSocketAddr) -> Self {
        Self {
            address: value,
            hostnames: BTreeSet::default(),
        }
    }
}

pub struct DraftTrace {
    open_paths: HashSet<PathBuf>,
    connect_sockets: HashSet<UnifiedSocketAddr>,
    socket_captures: Vec<SocketCapture>,
}

#[derive(Debug)]
pub struct SocketCapture {
    pub socket_addr: UnifiedSocketAddr,
    pub state: SocketCaptureState,
}

#[derive(Debug, PartialEq)]
pub enum SocketCaptureState {
    Complete(Vec<SocketOperation>),
    Incomplete,
}

#[derive(Debug, PartialEq)]
pub enum SocketOperation {
    Sent(Vec<u8>),
    Read(Vec<u8>),
}

impl Default for DraftTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl DraftTrace {
    #[must_use]
    pub fn new() -> DraftTrace {
        DraftTrace {
            open_paths: HashSet::new(),
            connect_sockets: HashSet::new(),
            socket_captures: Vec::new(),
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

    #[allow(dead_code)] // may not be used on a platform that doesn't support tracing yet
    pub fn add_socket_capture(&mut self, socket_capture: SocketCapture) {
        self.socket_captures.push(socket_capture);
    }
}

pub struct Trace {
    open_paths: HashSet<PathBuf>,
    connect_sockets: HashSet<ResolvedSocketAddr>,
    // socket_captures: Vec<SocketCapture>,
}

impl Trace {
    fn create_resolved_socket_addrs(
        socket_addresses: HashSet<UnifiedSocketAddr>,
        dns_resolutions: &HashMap<IpAddr, HashSet<String>>,
    ) -> HashSet<ResolvedSocketAddr> {
        // Add hostname resolution information to the connect sockets, if present.
        let mut resolved_connect_sockets = HashSet::new();
        for socket_addr in socket_addresses {
            let mut hostnames = BTreeSet::new();
            if let UnifiedSocketAddr::Inet(inet) = socket_addr {
                if let Some(resolved_hostnames) = dns_resolutions.get(&inet.ip()) {
                    hostnames.extend(resolved_hostnames.to_owned());
                }

                // If we completed a connection to an IPv6 address which was actually an IPv4-mapped address (eg.
                // ::ffff:192.229.211.108), then lookup the IPv4 address in the DNS resolutions (eg. if we did an `A`
                // record resolution) and add those hostnames to the ResolvedSocketAddr as well.
                if let IpAddr::V6(ip6) = inet.ip()
                    && let Some(v4) = ip6.to_ipv4_mapped()
                    && let Some(resolved_hostnames) = dns_resolutions.get(&IpAddr::V4(v4))
                {
                    hostnames.extend(resolved_hostnames.to_owned());
                }

                // Not really expecting that DNS resolution would make external socket access for 'localhost', and it'd
                // be very common for a network policy to refer to 'localhost' and expect it to match. Note that
                // ::ffff:127.0.0.1 isn't matched by the Rust stdlib as loopback (an IPv4 mapped IPv6 address), so do a
                // specific check for that.
                if inet.ip().is_loopback() {
                    hostnames.insert(String::from("localhost"));
                } else if let IpAddr::V6(ip6) = inet.ip()
                    && ip6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
                {
                    hostnames.insert(String::from("localhost"));
                }
            }

            let resolved = ResolvedSocketAddr {
                address: socket_addr,
                hostnames,
            };
            resolved_connect_sockets.insert(resolved);
        }

        resolved_connect_sockets
    }
}

impl TryFrom<DraftTrace> for Trace {
    type Error = anyhow::Error;
    fn try_from(value: DraftTrace) -> Result<Self> {
        let dns_resolutions = crate::network::analyze_socket_captures(&value.socket_captures)?;

        // Add hostname resolution information to the connect sockets, if present.
        let resolved_connect_sockets =
            Trace::create_resolved_socket_addrs(value.connect_sockets, &dns_resolutions);

        Ok(Self {
            open_paths: value.open_paths,
            connect_sockets: resolved_connect_sockets,
        })
    }
}

impl Trace {
    #[must_use]
    pub fn get_open_paths(&self) -> &HashSet<PathBuf> {
        &self.open_paths
    }

    #[must_use]
    pub fn get_connect_sockets(&self) -> &HashSet<ResolvedSocketAddr> {
        &self.connect_sockets
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap, HashSet},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        str::FromStr as _,
    };

    use anyhow::Result;

    use crate::sys_trace::trace::ResolvedSocketAddr;

    use super::{Trace, UnifiedSocketAddr};

    #[test]
    fn test_dns_enhancement() -> Result<()> {
        let addr = UnifiedSocketAddr::Inet(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("217.197.91.145")?,
            443,
        )));
        let resolution_map = HashMap::new();
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr.clone(),
                hostnames: BTreeSet::from([])
            }])
        );

        let resolution_map = HashMap::from([
            (
                IpAddr::V4(Ipv4Addr::from_str("217.197.91.145")?),
                HashSet::from([String::from("example.com"), String::from("example.org")]),
            ),
            (
                IpAddr::V4(Ipv4Addr::from_str("123.123.123.123")?),
                HashSet::from([String::from("testtrim.org")]),
            ),
        ]);
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr,
                hostnames: BTreeSet::from([
                    String::from("example.com"),
                    String::from("example.org")
                ])
            }])
        );

        let addr = UnifiedSocketAddr::Inet(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_str("2607:f8b0:400a:80b::2003")?,
            443,
            0,
            0,
        )));
        let resolution_map = HashMap::new();
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr.clone(),
                hostnames: BTreeSet::from([])
            }])
        );

        let resolution_map = HashMap::from([
            (
                IpAddr::V6(Ipv6Addr::from_str("2607:f8b0:400a:80b::2003")?),
                HashSet::from([String::from("example.com"), String::from("example.org")]),
            ),
            (
                IpAddr::V6(Ipv6Addr::from_str("2001:67c:1401:20f0::1")?),
                HashSet::from([String::from("codeberg.org")]),
            ),
        ]);
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr,
                hostnames: BTreeSet::from([
                    String::from("example.com"),
                    String::from("example.org")
                ])
            }])
        );

        Ok(())
    }

    #[test]
    fn test_dns_enhancement_localhost() -> Result<()> {
        let addr = UnifiedSocketAddr::Inet(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1")?,
            443,
        )));
        let resolution_map = HashMap::from([(
            IpAddr::V4(Ipv4Addr::from_str("127.0.0.1")?),
            HashSet::from([String::from("example.org")]),
        )]);
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr,
                hostnames: BTreeSet::from([String::from("localhost"), String::from("example.org")])
            }])
        );

        let addr = UnifiedSocketAddr::Inet(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_str("::1")?,
            443,
            0,
            0,
        )));
        let resolution_map = HashMap::from([(
            IpAddr::V6(Ipv6Addr::from_str("::1")?),
            HashSet::from([String::from("example.com")]),
        )]);
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr,
                hostnames: BTreeSet::from([String::from("example.com"), String::from("localhost")])
            }])
        );

        let addr = UnifiedSocketAddr::Inet(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_str("::ffff:127.0.0.1")?,
            443,
            0,
            0,
        )));
        let resolution_map = HashMap::new();
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr,
                hostnames: BTreeSet::from([String::from("localhost")])
            }])
        );

        Ok(())
    }

    #[test]
    fn test_dns_enhancement_ipv4_mapped() -> Result<()> {
        let addr = UnifiedSocketAddr::Inet(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_str("::ffff:123.123.123.123")?,
            443,
            0,
            0,
        )));
        let resolution_map = HashMap::from([(
            IpAddr::V4(Ipv4Addr::from_str("123.123.123.123")?),
            HashSet::from([String::from("testtrim.org")]),
        )]);
        let resolved =
            Trace::create_resolved_socket_addrs(HashSet::from([addr.clone()]), &resolution_map);
        assert_eq!(
            resolved,
            HashSet::from([ResolvedSocketAddr {
                address: addr,
                hostnames: BTreeSet::from([String::from("testtrim.org")])
            }])
        );

        Ok(())
    }
}
