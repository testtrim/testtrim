// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    ops::RangeInclusive,
    path::PathBuf,
};

use ipnet::IpNet;
use log::debug;
use regex::Regex;
use serde::Deserialize;

use crate::{
    coverage::full_coverage_data::FullCoverageData,
    platform::{TestPlatform, TestReason},
    sys_trace::trace::UnifiedSocketAddr,
    util::inline_range,
};

#[derive(Debug)]
pub struct NetworkDependency {
    pub socket: UnifiedSocketAddr,
}

/// Network policies; after matching a test based upon network access that it performed, different rules can be defined
/// for when the test is rerun in the future.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Policy {
    name: String,
    #[serde(rename = "match")]
    match_rules: Vec<PolicyMatch>,
    #[serde(rename = "apply")]
    apply_rules: PolicyApply,
}

/// One or more rule to define when a test policy is applied based upon network access specifics.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
enum PolicyMatch {
    /// Matches any access to a Unix socket; can contain glob wildcards.
    UnixSocket(String),
    /// Matches network access on a specific port, regardless of the IP address used.
    Port(u16),
    /// Matches network access on a range of ports (eg. 1000-2000), inclusive, regardless of the IP address used.
    PortRange(#[serde(deserialize_with = "inline_range")] RangeInclusive<u16>),
    /// Matches network access on subnet (eg. 127.0.0.1/32, 10.0.0.0/8), regardless of the port used.
    Address(IpNet),
    /// Matches network access on subnet (eg. 127.0.0.1/32, 10.0.0.0/8) and specific network port.
    AddressPort(IpNet, u16),
    /// Matches network access on subnet (eg. 127.0.0.1/32, 10.0.0.0/8) and range of ports (eg. 1000-2000), inclusive.
    AddressPortRange(
        IpNet,
        #[serde(deserialize_with = "inline_range")] RangeInclusive<u16>,
    ),
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
enum PolicyApply {
    /// Always rerun the test because of the matched network access.  If network access matches no rules, the default is
    /// to rerun the test always, so this apply rule is rarely used.  However it can be used to force a test to rerun
    /// based upon one network match, even if other network matches end up omitting it.
    RunAlways,
    /// Ignore this network access; never rerun the test because of it.
    Ignore,
    /// For a test that matched this network access, run the test if other repository files are changed.  Each path can
    /// contain glob wildcards, and are interpreted relative to the repository root.  eg. `db/postgres/*.sql`
    RunIfFilesChanged(Vec<String>),
}

#[derive(PartialEq, Eq, Debug)]
enum Outcome {
    DefaultRun,
    ForceRun(String), // w/ at least one policy name that forced it (multiple are ignored)
    RunFromFileChange(String, PathBuf), // policy name and changed file that caused run
    Ignore(String),   // w/ at least one policy name that ignored it (multiple are ignored)
}

pub fn compute_tests_from_network_accesses<TP>(
    coverage_data: &FullCoverageData<TP::TI, TP::CI>,
    policies: &[Policy],
    eval_target_changed_files: &HashSet<PathBuf>,
) -> HashMap<TP::TI, HashSet<TestReason<TP::CI>>>
where
    TP: TestPlatform,
{
    let mut test_cases: HashMap<TP::TI, HashSet<TestReason<TP::CI>>> = HashMap::new();

    for (ci, tests) in coverage_data.coverage_identifier_to_test_map() {
        if let Ok(network_dependency) = TryInto::<NetworkDependency>::try_into(ci.clone()) {
            let test_reason = match evaluate_policy(
                policies,
                &network_dependency,
                eval_target_changed_files,
            ) {
                Outcome::DefaultRun => TestReason::CoverageIdentifier(ci.clone()),
                Outcome::ForceRun(ref policy_name) => {
                    debug!("network to {network_dependency:?} hit force-run policy {policy_name}");
                    TestReason::SideEffect(
                        Box::new(TestReason::CoverageIdentifier(ci.clone())),
                        Box::new(TestReason::NetworkPolicy(policy_name.clone())),
                    )
                }
                Outcome::RunFromFileChange(ref policy_name, ref file_changed) => {
                    debug!("network to {network_dependency:?} + file {file_changed:?} hit run policy {policy_name}");
                    TestReason::SideEffect(
                        Box::new(TestReason::CoverageIdentifier(ci.clone())),
                        Box::new(TestReason::NetworkPolicy(format!(
                            "{policy_name} ({file_changed:?})",
                        ))),
                    )
                }
                Outcome::Ignore(ref policy_name) => {
                    debug!(
                        "ignoring network to {network_dependency:?} due to policy {policy_name}"
                    );
                    continue;
                }
            };

            for test in tests {
                test_cases
                    .entry(test.clone())
                    .or_default()
                    .insert(test_reason.clone());
            }
        }
    }

    test_cases
}

fn check_policy_match(network_dependency: &NetworkDependency, policy: &PolicyMatch) -> bool {
    match network_dependency.socket {
        UnifiedSocketAddr::Unix(ref nd) => match policy {
            PolicyMatch::UnixSocket(ref mtch) => {
                evaluate_glob(mtch, &HashSet::from([nd.clone()])).is_some()
            }
            _ => false,
        },
        UnifiedSocketAddr::Inet(SocketAddr::V4(ref v4)) => match policy {
            PolicyMatch::Port(ref port) => v4.port() == *port,
            PolicyMatch::PortRange(ref port_range) => port_range.contains(&v4.port()),
            PolicyMatch::Address(IpNet::V4(ref v4_subnet)) => v4_subnet.contains(v4.ip()),
            PolicyMatch::AddressPort(IpNet::V4(ref v4_subnet), ref port) => {
                v4_subnet.contains(v4.ip()) && v4.port() == *port
            }
            PolicyMatch::AddressPortRange(IpNet::V4(ref v4_subnet), ref port_range) => {
                v4_subnet.contains(v4.ip()) && port_range.contains(&v4.port())
            }
            PolicyMatch::Address(IpNet::V6(_))
            | PolicyMatch::AddressPort(IpNet::V6(_), _)
            | PolicyMatch::AddressPortRange(IpNet::V6(_), _)
            | PolicyMatch::UnixSocket(_) => false,
        },
        UnifiedSocketAddr::Inet(SocketAddr::V6(ref v6)) => match policy {
            PolicyMatch::Port(ref port) => v6.port() == *port,
            PolicyMatch::PortRange(ref port_range) => port_range.contains(&v6.port()),
            PolicyMatch::Address(IpNet::V6(ref v6_subnet)) => v6_subnet.contains(v6.ip()),
            PolicyMatch::AddressPort(IpNet::V6(ref v6_subnet), ref port) => {
                v6_subnet.contains(v6.ip()) && v6.port() == *port
            }
            PolicyMatch::AddressPortRange(IpNet::V6(ref v6_subnet), ref port_range) => {
                v6_subnet.contains(v6.ip()) && port_range.contains(&v6.port())
            }
            // v6 could be an IPv4 Mapped address, and if so we match it to IPv4 policies as well:
            PolicyMatch::Address(IpNet::V4(ref v4_subnet)) => v6
                .ip()
                .to_ipv4_mapped()
                .is_some_and(|v4| v4_subnet.contains(&v4)),
            PolicyMatch::AddressPort(IpNet::V4(ref v4_subnet), ref port) => {
                v6.ip()
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4_subnet.contains(&v4))
                    && v6.port() == *port
            }
            PolicyMatch::AddressPortRange(IpNet::V4(ref v4_subnet), ref port_range) => {
                v6.ip()
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4_subnet.contains(&v4))
                    && port_range.contains(&v6.port())
            }
            PolicyMatch::UnixSocket(_) => false,
        },
    }
}

fn evaluate_policy(
    policies: &[Policy],
    network_dependency: &NetworkDependency,
    eval_target_changed_files: &HashSet<PathBuf>,
) -> Outcome {
    let mut outcome = Outcome::DefaultRun;

    for policy in policies {
        for match_rule in &policy.match_rules {
            if check_policy_match(network_dependency, match_rule) {
                match policy.apply_rules {
                    PolicyApply::RunAlways => {
                        // stop evaluating at this point as we've decided to force it already
                        return Outcome::ForceRun(policy.name.clone());
                    }

                    // if we've already moved on from DefaultRun, don't overwrite outcome
                    PolicyApply::Ignore if outcome == Outcome::DefaultRun => {
                        // don't return; allow all policies to be matched in case one forces it to run
                        outcome = Outcome::Ignore(policy.name.clone());
                    }
                    PolicyApply::Ignore => {}

                    PolicyApply::RunIfFilesChanged(ref globs) => {
                        // Ignore, unless we find a matching file...
                        outcome = Outcome::Ignore(policy.name.clone());

                        for glob in globs {
                            if let Some(path) = evaluate_glob(glob, eval_target_changed_files) {
                                // stop evaluating as this is treated like a force; can't be ignored after this
                                return Outcome::RunFromFileChange(
                                    policy.name.clone(),
                                    path.clone(),
                                );
                            }
                        }
                    }
                }
                break; // no need to check any other match rules on this policy
            }
        }
    }

    outcome
}

fn evaluate_glob<'a>(glob: &str, paths: &'a HashSet<PathBuf>) -> Option<&'a PathBuf> {
    // The glob library seems like the right thing to use here, but it seems to require that it works against a live
    // filesystem only... we're going to be using it against a set of "changed files", and in unit tests with fake
    // files, so it seems more straightforward to do it with a hacky little regex creation.

    // FIXME: probably need revision to support Windows file path separators
    let regex_txt = regex::escape(glob)
        // note, none of these replaces can use a RHS that could be matched by the next replace. :-p
        // path wildcard
        .replace("\\*\\*", ".{0,}")
        // non-path wildcard
        .replace("\\*", "[^/]{0,}");

    // anchor to ensure we're doing a full path match:
    let mut full_regex = String::with_capacity(regex_txt.len() + 2);
    full_regex.push('^');
    full_regex.push_str(&regex_txt);
    full_regex.push('$');

    // FIXME: cache the regex by glob?  Could be constructed quite a few times, if there are a lot of changed files.
    let regex = Regex::new(&full_regex).unwrap();

    paths
        .iter()
        .find(|&path| regex.is_match(&path.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::PathBuf,
        str::FromStr as _,
    };

    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use lazy_static::lazy_static;
    use serde::Deserialize;

    use crate::{
        coverage::full_coverage_data::FullCoverageData,
        network::{
            check_policy_match, evaluate_glob, evaluate_policy, NetworkDependency, Outcome,
            PolicyApply, PolicyMatch,
        },
        platform::{
            rust::{RustCoverageIdentifier, RustTestIdentifier, RustTestPlatform},
            TestReason,
        },
        sys_trace::trace::UnifiedSocketAddr,
    };

    use super::{compute_tests_from_network_accesses, Policy};

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "kebab-case")]
    struct Config {
        network_policy: Vec<Policy>,
    }

    #[test]
    fn parse_config() {
        let config: Config = toml::from_str(
            r#"
                [[network-policy]]
                name = "DNS access" # used to report test reasons in get-test-identifiers
                apply = 'run-always'
                [[network-policy.match]]
                unix-socket = "/var/run/nscd/socket"
                [[network-policy.match]]
                port = 53

                [[network-policy]]
                name = "internal test servers"
                apply = 'ignore'
                [[network-policy.match]]
                port-range = "16384-32768"
                [[network-policy.match]]
                address = "10.0.0.0/8"
                [[network-policy.match]]
                address = "::1/128"
                [[network-policy.match]]
                address-port = ["127.0.0.1/32", 8080]
                [[network-policy.match]]
                address-port-range = ["127.0.0.1/32", "8085-8086"]
                [[network-policy.match]]
                port-range = "1024-65535"

                [[network-policy]]
                name = "PostgreSQL server"
                apply.run-if-files-changed = [
                    "db/postgres/*.sql",
                ]
                [[network-policy.match]]
                port = 5432
            "#,
        )
        .unwrap();

        let policy = &config.network_policy[0];
        assert_eq!(policy.name, "DNS access");
        assert_eq!(policy.apply_rules, PolicyApply::RunAlways);

        let PolicyMatch::UnixSocket(ref unix_socket) = &policy.match_rules[0] else {
            panic!("expected match_rules[0] to be UnixSocket");
        };
        assert_eq!(unix_socket, "/var/run/nscd/socket");

        let PolicyMatch::Port(ref port) = &policy.match_rules[1] else {
            panic!("expected match_rules[0] to be Port");
        };
        assert_eq!(port, &53);

        let policy = &config.network_policy[1];
        assert_eq!(policy.name, "internal test servers");
        assert_eq!(policy.apply_rules, PolicyApply::Ignore);

        let PolicyMatch::PortRange(ref port_range) = &policy.match_rules[0] else {
            panic!("expected match_rules[0] to be PortRange");
        };
        assert_eq!(*port_range.start(), 16384);
        assert_eq!(*port_range.end(), 32768);

        let PolicyMatch::Address(ref address) = &policy.match_rules[1] else {
            panic!("expected match_rules[1] to be Address");
        };
        let IpNet::V4(ref address_ip4) = address else {
            panic!("expected match_rules[1] to be Ipv4Net");
        };
        assert_eq!(
            address_ip4,
            &Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap()
        );

        let PolicyMatch::Address(ref address) = &policy.match_rules[2] else {
            panic!("expected match_rules[2] to be Address");
        };
        let IpNet::V6(ref address_ip6) = address else {
            panic!("expected match_rules[2] to be Ipv6Net");
        };
        assert_eq!(
            address_ip6,
            &Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128).unwrap()
        );

        let PolicyMatch::AddressPort(ref address, ref port) = &policy.match_rules[3] else {
            panic!("expected match_rules[3] to be AddressPort");
        };
        let IpNet::V4(ref address_ip4) = address else {
            panic!("expected match_rules[3] to be Ipv4Net");
        };
        assert_eq!(
            address_ip4,
            &Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap()
        );
        assert_eq!(port, &8080);

        let PolicyMatch::AddressPortRange(ref address, ref port_range) = &policy.match_rules[4]
        else {
            panic!("expected match_rules[4] to be AddressPortRange");
        };
        let IpNet::V4(ref address_ip4) = address else {
            panic!("expected match_rules[4] to be Ipv4Net");
        };
        assert_eq!(
            address_ip4,
            &Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap()
        );
        assert_eq!(*port_range.start(), 8085);
        assert_eq!(*port_range.end(), 8086);

        let PolicyMatch::PortRange(ref port_range) = &policy.match_rules[5] else {
            panic!("expected match_rules[5] to be PortRange");
        };
        assert_eq!(*port_range.start(), 1024);
        assert_eq!(*port_range.end(), 65535);

        let policy = &config.network_policy[2];
        assert_eq!(policy.name, "PostgreSQL server");
        assert_eq!(
            policy.apply_rules,
            PolicyApply::RunIfFilesChanged(vec!["db/postgres/*.sql".to_string()])
        );
    }

    /// Helper function to create a `SocketAddr` for testing.
    fn create_socket_addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from_str(ip).unwrap(), port)
    }

    #[test]
    fn test_match_port() {
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("127.0.0.1", 8080)),
        };
        let pm = PolicyMatch::Port(8080);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::Port(8081);
        assert!(!check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::1", 8080)),
        };
        let pm = PolicyMatch::Port(8080);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::Port(8081);
        assert!(!check_policy_match(&nd, &pm));
    }

    #[test]
    fn test_match_port_range() {
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("127.0.0.1", 1500)),
        };
        let pm = PolicyMatch::PortRange(1000..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::PortRange(1500..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::PortRange(1000..=1501);
        assert!(check_policy_match(&nd, &pm));

        let pm = PolicyMatch::PortRange(0..=1024);
        assert!(!check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::1", 1500)),
        };
        let pm = PolicyMatch::PortRange(1000..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::PortRange(1500..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::PortRange(1000..=1501);
        assert!(check_policy_match(&nd, &pm));

        let pm = PolicyMatch::PortRange(0..=1024);
        assert!(!check_policy_match(&nd, &pm));
    }

    #[test]
    fn test_match_unix_socket() {
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Unix(PathBuf::from("/tmp/socket")),
        };
        let pm = PolicyMatch::UnixSocket(String::from("/tmp/socket"));
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::UnixSocket(String::from("/tmp/socket2"));
        assert!(!check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Unix(PathBuf::from("/tmp/dir/socket")),
        };
        let pm = PolicyMatch::UnixSocket(String::from("/**/*"));
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::UnixSocket(String::from("/tmp/dir/sock*"));
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::UnixSocket(String::from("/var/run/*"));
        assert!(!check_policy_match(&nd, &pm));
    }

    #[test]
    fn test_match_address() {
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("10.0.0.1", 8080)),
        };
        let pm = PolicyMatch::Address(IpNet::from_str("10.0.0.0/8").unwrap());
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::Address(IpNet::from_str("11.0.0.0/8").unwrap());
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::Address(IpNet::from_str("::/0").unwrap());
        assert!(!check_policy_match(&nd, &pm));

        // If policy is an ipv4 addr, but tracing shows an IPv4 Mapped address, we should still match:
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::ffff:10.0.0.1", 8080)),
        };
        let pm = PolicyMatch::Address(IpNet::from_str("10.0.0.0/8").unwrap());
        assert!(check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("2400:4000::1234", 8080)),
        };
        let pm = PolicyMatch::Address(IpNet::from_str("2400:4000::/21").unwrap());
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::Address(IpNet::from_str("0000:4000::/21").unwrap());
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::Address(IpNet::from_str("0.0.0.0/0").unwrap());
        assert!(!check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::1", 8080)),
        };
        let pm = PolicyMatch::Address(IpNet::from_str("0.0.0.0/0").unwrap());
        assert!(!check_policy_match(&nd, &pm));
    }

    #[test]
    fn test_match_address_port() {
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("10.0.0.1", 8080)),
        };
        let pm = PolicyMatch::AddressPort(IpNet::from_str("10.0.0.0/8").unwrap(), 8080);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPort(IpNet::from_str("127.0.0.0/8").unwrap(), 8080);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPort(IpNet::from_str("10.0.0.0/8").unwrap(), 8081);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPort(IpNet::from_str("::/0").unwrap(), 8080);
        assert!(!check_policy_match(&nd, &pm));

        // If policy is an ipv4 addr, but tracing shows an IPv4 Mapped address, we should still match:
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::ffff:10.0.0.1", 8080)),
        };
        let pm = PolicyMatch::AddressPort(IpNet::from_str("10.0.0.0/8").unwrap(), 8080);
        assert!(check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::1", 8080)),
        };
        let pm = PolicyMatch::AddressPort(IpNet::from_str("::/0").unwrap(), 8080);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPort(IpNet::from_str("2400:4000::/21").unwrap(), 8080);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPort(IpNet::from_str("::/0").unwrap(), 8081);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPort(IpNet::from_str("0.0.0.0/0").unwrap(), 8080);
        assert!(!check_policy_match(&nd, &pm));
    }

    #[test]
    fn test_match_address_port_range() {
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("10.0.0.1", 1500)),
        };
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("10.0.0.0/8").unwrap(), 1000..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("10.0.0.0/8").unwrap(), 1500..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("10.0.0.0/8").unwrap(), 1000..=1501);
        assert!(check_policy_match(&nd, &pm));

        let pm =
            PolicyMatch::AddressPortRange(IpNet::from_str("127.0.0.1/32").unwrap(), 1000..=2000);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("10.0.0.0/8").unwrap(), 1501..=1502);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("::/0").unwrap(), 1000..=2000);
        assert!(!check_policy_match(&nd, &pm));

        // If policy is an ipv4 addr, but tracing shows an IPv4 Mapped address, we should still match:
        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::ffff:10.0.0.1", 8080)),
        };
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("10.0.0.0/8").unwrap(), 8000..=9000);
        assert!(check_policy_match(&nd, &pm));

        let nd = NetworkDependency {
            socket: UnifiedSocketAddr::Inet(create_socket_addr("::1", 1500)),
        };
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("::/0").unwrap(), 1000..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("::/0").unwrap(), 1500..=2000);
        assert!(check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("::/0").unwrap(), 1000..=1501);
        assert!(check_policy_match(&nd, &pm));

        let pm =
            PolicyMatch::AddressPortRange(IpNet::from_str("2400:4000::/21").unwrap(), 1000..=2000);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("10.0.0.0/8").unwrap(), 1501..=1502);
        assert!(!check_policy_match(&nd, &pm));
        let pm = PolicyMatch::AddressPortRange(IpNet::from_str("0.0.0.0/0").unwrap(), 1000..=2000);
        assert!(!check_policy_match(&nd, &pm));
    }

    #[test]
    fn test_evaluate_policy() {
        let config: Config = toml::from_str(
            r#"
                [[network-policy]]
                name = "local router access"
                apply = "run-always"
                [[network-policy.match]]
                address = "192.168.0.0/16"

                [[network-policy]]
                name = "DNS access"
                apply = "ignore"
                [[network-policy.match]]
                port = 53

                [[network-policy]]
                # This is the same policy as above, but just shows what happens if we match multiple ignores.
                name = "DNS access #2"
                apply = "ignore"
                [[network-policy.match]]
                port = 53

                [[network-policy]]
                name = "PostgreSQL server"
                apply.run-if-files-changed = [
                    "db/postgres/*.sql",
                ]
                [[network-policy.match]]
                port = 5432
            "#,
        )
        .unwrap();

        // Case that doesn't match any policy
        let outcome = evaluate_policy(
            &config.network_policy,
            &NetworkDependency {
                socket: UnifiedSocketAddr::Inet(create_socket_addr("10.1.1.1", 8080)),
            },
            &HashSet::new(),
        );
        assert_eq!(outcome, Outcome::DefaultRun);

        // Matches two ignore policies; expect the first one's name to be returned:
        let outcome = evaluate_policy(
            &config.network_policy,
            &NetworkDependency {
                socket: UnifiedSocketAddr::Inet(create_socket_addr("10.1.1.1", 53)),
            },
            &HashSet::new(),
        );
        assert_eq!(outcome, Outcome::Ignore("DNS access".to_string()));

        // Matches the *both* the ignore and always-run policy; always-run overrides ignore:
        let outcome = evaluate_policy(
            &config.network_policy,
            &NetworkDependency {
                socket: UnifiedSocketAddr::Inet(create_socket_addr("192.168.1.1", 53)),
            },
            &HashSet::new(),
        );
        assert_eq!(
            outcome,
            Outcome::ForceRun("local router access".to_string())
        );

        // Matches the run-if-files-changed but doesn't have any matching files:
        let outcome = evaluate_policy(
            &config.network_policy,
            &NetworkDependency {
                socket: UnifiedSocketAddr::Inet(create_socket_addr("10.1.1.1", 5432)),
            },
            &HashSet::new(),
        );
        assert_eq!(outcome, Outcome::Ignore("PostgreSQL server".to_string()));

        // Matches the run-if-files-changed and also matches files changed:
        let outcome = evaluate_policy(
            &config.network_policy,
            &NetworkDependency {
                socket: UnifiedSocketAddr::Inet(create_socket_addr("10.1.1.1", 5432)),
            },
            &HashSet::from([PathBuf::from("db/postgres/2024_schema.sql")]),
        );
        assert_eq!(
            outcome,
            Outcome::RunFromFileChange(
                "PostgreSQL server".to_string(),
                PathBuf::from("db/postgres/2024_schema.sql")
            )
        );
    }

    #[test]
    fn test_evaluate_glob() {
        assert_eq!(
            evaluate_glob(
                "CHANGELOG.md",
                &HashSet::from([PathBuf::from("CHANGELOG.md")])
            ),
            Some(&PathBuf::from("CHANGELOG.md"))
        );
        assert_eq!(
            evaluate_glob(
                "CHANGELOG.md",
                &HashSet::from([PathBuf::from("CHANGELOG-md")])
            ),
            None
        );
        assert_eq!(
            evaluate_glob("*.md", &HashSet::from([PathBuf::from("CHANGELOG.md")])),
            Some(&PathBuf::from("CHANGELOG.md"))
        );
        assert_eq!(
            evaluate_glob("*.md", &HashSet::from([PathBuf::from("docs/CHANGELOG.md")])),
            None
        );
        assert_eq!(
            evaluate_glob(
                "**/*.md",
                &HashSet::from([PathBuf::from("docs/CHANGELOG.md")])
            ),
            Some(&PathBuf::from("docs/CHANGELOG.md"))
        );
        assert_eq!(
            evaluate_glob(
                "**/*.md",
                &HashSet::from([PathBuf::from("docs/CHANGELOG.txt")])
            ),
            None
        );
    }

    lazy_static! {
        static ref test1: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
        static ref test2: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("src/lib.rs"),
                test_name: "test2".to_string(),
            }
        };
        static ref test3: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("sub_module/src/lib.rs"),
                test_name: "test1".to_string(),
            }
        };
        static ref test4: RustTestIdentifier = {
            RustTestIdentifier {
                test_src_path: PathBuf::from("sub_module/src/lib.rs"),
                test_name: "test4".to_string(),
            }
        };
    }

    #[test]
    fn test_compute_tests() {
        let config: Config = toml::from_str(
            r#"
                [[network-policy]]
                name = "local router access"
                apply = "run-always"
                [[network-policy.match]]
                address = "192.168.0.0/16"

                [[network-policy]]
                name = "DNS access"
                apply = "ignore"
                [[network-policy.match]]
                port = 53

                [[network-policy]]
                name = "PostgreSQL server"
                apply.run-if-files-changed = [
                    "db/postgres/*.sql",
                ]
                [[network-policy.match]]
                port = 5432
            "#,
        )
        .unwrap();

        let mut coverage_data =
            FullCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
        let policies = &config.network_policy;

        // default case; a network access that isn't part of the policy
        let test1_network_ci = RustCoverageIdentifier::NetworkDependency(UnifiedSocketAddr::Unix(
            PathBuf::from("/tmp/socket"),
        ));
        coverage_data.add_heuristic_coverage_to_test(test1.clone(), test1_network_ci.clone());

        // ignore case; network access was present but policy says nevermind it
        let test2_network_ci = RustCoverageIdentifier::NetworkDependency(UnifiedSocketAddr::Inet(
            create_socket_addr("127.0.0.1", 53),
        ));
        coverage_data.add_heuristic_coverage_to_test(test2.clone(), test2_network_ci.clone());

        // force-run case; network access was both "ignored" and "run-always"'d
        let test3_network_ci = RustCoverageIdentifier::NetworkDependency(UnifiedSocketAddr::Inet(
            create_socket_addr("192.168.1.1", 53),
        ));
        coverage_data.add_heuristic_coverage_to_test(test3.clone(), test3_network_ci.clone());

        // run-if-files-changed case
        let test4_network_ci = RustCoverageIdentifier::NetworkDependency(UnifiedSocketAddr::Inet(
            create_socket_addr("10.1.1.1", 5432),
        ));
        coverage_data.add_heuristic_coverage_to_test(test4.clone(), test4_network_ci.clone());

        let test_result = compute_tests_from_network_accesses::<RustTestPlatform>(
            &coverage_data,
            policies,
            &HashSet::from([PathBuf::from("db/postgres/2024_schema.sql")]),
        );

        let test1_reasons = test_result.get(&test1);
        assert!(test1_reasons.is_some());
        let test1_reasons = test1_reasons.unwrap();
        assert!(test1_reasons.contains(&TestReason::CoverageIdentifier(test1_network_ci)));

        let test2_reasons = test_result.get(&test2);
        assert!(test2_reasons.is_none());

        let test3_reasons = test_result.get(&test3);
        assert!(test3_reasons.is_some());
        let test3_reasons = test3_reasons.unwrap();
        assert!(test3_reasons.contains(&TestReason::SideEffect(
            Box::new(TestReason::CoverageIdentifier(test3_network_ci)),
            Box::new(TestReason::NetworkPolicy("local router access".to_string())),
        )));

        let test4_reasons = test_result.get(&test4);
        assert!(test4_reasons.is_some());
        let test4_reasons = test4_reasons.unwrap();
        assert!(test4_reasons.contains(&TestReason::SideEffect(
            Box::new(TestReason::CoverageIdentifier(test4_network_ci)),
            Box::new(TestReason::NetworkPolicy(
                "PostgreSQL server (\"db/postgres/2024_schema.sql\")".to_string()
            )),
        )));
    }
}
