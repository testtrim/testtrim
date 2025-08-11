// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, CString},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Result, anyhow, ensure};
use nix::sys::socket::AddressFamily;
use protocol::{AiResponseHeader, Request, RequestType};

mod protocol;

#[derive(Debug, PartialEq)]
struct AiResponse {
    header: AiResponseHeader,
    content: protocol::AiResponse,
}

#[allow(clippy::cast_sign_loss)]
fn read_response_getai<T: io::Read>(reader: &mut T) -> Result<AiResponse> {
    let mut buf: [u8; size_of::<AiResponseHeader>()] = [0; size_of::<AiResponseHeader>()];
    reader.read_exact(&mut buf)?;
    let header = AiResponseHeader::parse(&buf)?;

    ensure!(header.addrslen >= 0, "addrslen cannot be negative");
    let mut addrs_bytes = vec![0; header.addrslen as usize];
    reader.read_exact(addrs_bytes.as_mut_slice())?;

    ensure!(header.naddrs >= 0, "naddrs cannot be negative");
    let mut families_bytes = vec![0; header.naddrs as usize];
    reader.read_exact(families_bytes.as_mut_slice())?;

    ensure!(header.canonlen >= 0, "canonlen cannot be negative");
    let mut canon_bytes = vec![0; header.canonlen as usize];
    reader.read_exact(canon_bytes.as_mut_slice())?;
    let canon = CString::from_vec_with_nul(canon_bytes)?;

    let mut addrs: Vec<IpAddr> = Vec::with_capacity(header.naddrs as usize);
    let mut addr_idx = 0;
    for family in families_bytes {
        match family {
            val if val == AddressFamily::Inet as u8 => {
                let addr = &addrs_bytes[addr_idx..addr_idx + 4]
                    .try_into()
                    .map(u32::from_be_bytes)?;
                addrs.push(IpAddr::V4(Ipv4Addr::from_bits(*addr)));
                addr_idx += 4;
            }
            val if val == AddressFamily::Inet6 as u8 => {
                let addr = &addrs_bytes[addr_idx..addr_idx + 16]
                    .try_into()
                    .map(u128::from_be_bytes)?;
                addrs.push(IpAddr::V6(Ipv6Addr::from_bits(*addr)));
                addr_idx += 16;
            }
            n => {
                return Err(anyhow!("unrecognized address family: {n}"));
            }
        }
    }

    Ok(AiResponse {
        header,
        content: protocol::AiResponse {
            addrs,
            canon_name: canon.into_string()?,
        },
    })
}

pub fn parse_nscd_interchange(
    send_data: &[u8],
    recv_data: &[u8],
    dns_resolutions: &mut HashMap<IpAddr, HashSet<String>>,
) -> Result<()> {
    let request = Request::parse(send_data)?;
    if let RequestType::GETAI = request.ty {
        let queried_hostname = String::from(CStr::from_bytes_with_nul(request.key)?.to_str()?);
        let mut slice = recv_data;
        let response = read_response_getai(&mut slice)?;
        let canonical_hostname = response.content.canon_name;
        for addr in response.content.addrs {
            let hashset = dns_resolutions.entry(addr).or_default();
            hashset.insert(queried_hostname.clone());
            hashset.insert(canonical_hostname.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        ffi::CStr,
        net::IpAddr,
        str::FromStr as _,
    };

    use anyhow::Result;

    use crate::nsncd::{
        AiResponse,
        protocol::{AiResponseHeader, RequestType},
    };

    use super::{parse_nscd_interchange, protocol::Request, read_response_getai};

    #[test]
    fn test_request_packet_getfdhst() {
        let packet = b"\x02\x00\x00\x00\r\x00\x00\x00\x06\x00\x00\x00hosts\x00";

        let parsed = Request::parse(packet);
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        match parsed.ty {
            RequestType::GETFDHST => {}
            n => panic!("parsed.ty expected to be RequestType::GETFDHST, but was {n:?}"),
        }
    }

    #[test]
    fn test_request_packet_getfdpw() {
        let packet = b"\x02\x00\x00\x00\x0b\x00\x00\x00\x07\x00\x00\x00passwd\x00";

        let parsed = Request::parse(packet);
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        match parsed.ty {
            RequestType::GETFDPW => {}
            n => panic!("parsed.ty expected to be RequestType::GETFDPW, but was {n:?}"),
        }
    }

    #[test]
    fn test_request_packet_getpwbyuid() {
        let packet = b"\x02\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x001000\x00";

        let parsed = Request::parse(packet);
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        match parsed.ty {
            RequestType::GETPWBYUID => {}
            n => panic!("parsed.ty expected to be RequestType::GETPWBYUID, but was {n:?}"),
        }
    }

    #[test]
    fn test_request_packet_getai() -> Result<()> {
        let packet = b"\x02\x00\x00\x00\x0e\x00\x00\x00\x0b\x00\x00\x00\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x00";

        let packet = Request::parse(packet);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        match packet.ty {
            RequestType::GETAI => {}
            n => panic!("packet.ty expected to be RequestType::GETAI but was {n:?}"),
        }

        let hostname = CStr::from_bytes_with_nul(packet.key)?.to_str()?;
        assert_eq!(hostname, "google.com");

        Ok(())
    }

    #[test]
    fn test_response_from_getai() -> Result<()> {
        // Captured from strace-curl-nscd.txt
        let reader = b"\x02\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00&\x07\xf8\xb0@\n\x08\x01\x00\x00\x00\x00\x00\x00 \x03\xac\xd9\x0e\xc3\n\x02google.ca\x00";

        let mut slice = &reader[..];
        let airesponse = read_response_getai(&mut slice)?;
        assert_eq!(
            airesponse,
            AiResponse {
                header: AiResponseHeader {
                    version: 2,
                    found: 1,
                    naddrs: 2,
                    addrslen: 20,
                    canonlen: 10,
                    error: 0,
                },
                content: crate::nsncd::protocol::AiResponse {
                    addrs: vec![
                        IpAddr::from_str("2607:f8b0:400a:801::2003")?,
                        IpAddr::from_str("172.217.14.195")?,
                    ],
                    canon_name: String::from("google.ca"),
                }
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_nscd_interchange() -> Result<()> {
        let send = b"\x02\x00\x00\x00\x0e\x00\x00\x00\x18\x00\x00\x00cname-test.testtrim.org\x00";
        let recv = b"\x02\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x00\x00x\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00&\x00\x14\x06:\x00\x00!\x00\x00\x00\x00\x17>.e&\x00\x14\x06:\x00\x00!\x00\x00\x00\x00\x17>.f&\x00\x14\x08\xec\x00\x006\x00\x00\x00\x00\x176\x7f$&\x00\x14\x08\xec\x00\x006\x00\x00\x00\x00\x176\x7f1&\x00\x14\x06\xbc\x00\x00S\x00\x00\x00\x00\xb8\x1e\x94\xc8&\x00\x14\x06\xbc\x00\x00S\x00\x00\x00\x00\xb8\x1e\x94\xce\x17\xc0\xe4P\x17\xc0\xe4T\x17\xd7\x00\x88`\x07\x80\xaf`\x07\x80\xc6\x17\xd7\x00\x8a\n\n\n\n\n\n\x02\x02\x02\x02\x02\x02example.com\x00";

        let mut hashmap = HashMap::new();

        // 2600:1406:bc00:53::b81e:94ce: {"example.com"},
        // 2600:1408:ec00:36::1736:7f31: {"example.com"},
        // 23.192.228.80: {"example.com"},
        // 23.215.0.136: {"example.com"},
        // 2600:1406:3a00:21::173e:2e65: {"example.com"},
        // 96.7.128.198: {"example.com"},
        // 23.192.228.84: {"example.com"},
        // 2600:1408:ec00:36::1736:7f24: {"example.com"},
        // 23.215.0.138: {"example.com"},
        // 2600:1406:bc00:53::b81e:94c8: {"example.com"},
        // 96.7.128.175: {"example.com"},
        // 2600:1406:3a00:21::173e:2e66: {"example.com"}

        parse_nscd_interchange(send, recv, &mut hashmap)?;

        let hostnames = hashmap.get(&IpAddr::from_str("96.7.128.175")?);
        assert!(hostnames.is_some());
        let hostnames = hostnames.unwrap();
        assert_eq!(
            *hostnames,
            HashSet::from([
                String::from("example.com"),
                String::from("cname-test.testtrim.org")
            ])
        );

        Ok(())
    }
}
