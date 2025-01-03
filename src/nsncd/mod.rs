// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Result, anyhow, ensure};
use nix::sys::socket::AddressFamily;
#[cfg(test)]
use protocol::PwResponseHeader;
use protocol::{AiResponseHeader, Request, RequestType};

mod protocol;

#[cfg(test)]
#[derive(Debug, PartialEq)]
struct PwResponse {
    header: PwResponseHeader,
    name: CString,
    passwd: CString,
    gecos: CString,
    dir: CString,
    shell: CString,
}

// Don't really need this in testtrim right now, but it was the first packet I decoded for testing... will keep it
// around just in case it might be needed in the future.  It is technically an external dependency that can change.
#[cfg(test)]
#[allow(clippy::cast_sign_loss)]
fn read_response_getpwbyuid<T: io::Read>(reader: &mut T) -> Result<PwResponse> {
    let mut buf: [u8; size_of::<PwResponseHeader>()] = [0; size_of::<PwResponseHeader>()];
    reader.read_exact(&mut buf)?;
    let header = PwResponseHeader::parse(&buf)?;

    ensure!(header.pw_name_len >= 0, "pw_name_len cannot be negative");
    let mut name_bytes = vec![0; header.pw_name_len as usize];
    reader.read_exact(name_bytes.as_mut_slice())?;
    let name = CString::from_vec_with_nul(name_bytes)?;

    ensure!(
        header.pw_passwd_len >= 0,
        "pw_passwd_len cannot be negative"
    );
    let mut passwd_bytes = vec![0; header.pw_passwd_len as usize];
    reader.read_exact(passwd_bytes.as_mut_slice())?;
    let passwd = CString::from_vec_with_nul(passwd_bytes)?;

    ensure!(header.pw_gecos_len >= 0, "pw_gecos_len cannot be negative");
    let mut gecos_bytes = vec![0; header.pw_gecos_len as usize];
    reader.read_exact(gecos_bytes.as_mut_slice())?;
    let gecos = CString::from_vec_with_nul(gecos_bytes)?;

    ensure!(header.pw_dir_len >= 0, "pw_dir_len cannot be negative");
    let mut dir_bytes = vec![0; header.pw_dir_len as usize];
    reader.read_exact(dir_bytes.as_mut_slice())?;
    let dir = CString::from_vec_with_nul(dir_bytes)?;

    ensure!(header.pw_shell_len >= 0, "pw_shell_len cannot be negative");
    let mut shell_bytes = vec![0; header.pw_shell_len as usize];
    reader.read_exact(shell_bytes.as_mut_slice())?;
    let shell = CString::from_vec_with_nul(shell_bytes)?;

    Ok(PwResponse {
        header,
        name,
        passwd,
        gecos,
        dir,
        shell,
    })
}

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
        let mut slice = recv_data;
        let response = read_response_getai(&mut slice)?;
        let hostname = response.content.canon_name;
        for addr in response.content.addrs {
            dns_resolutions
                .entry(addr)
                .or_default()
                .insert(hostname.clone());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{CStr, CString},
        net::IpAddr,
        str::FromStr as _,
    };

    use anyhow::Result;

    use crate::nsncd::{
        AiResponse, PwResponse,
        protocol::{AiResponseHeader, PwResponseHeader, RequestType},
    };

    use super::{protocol::Request, read_response_getai, read_response_getpwbyuid};

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
    fn test_response_from_getpwbyuid() -> Result<()> {
        // Captured from strace-curl-nscd.txt
        let reader = b"\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00mfenniak\x00x\x00Mathieu Fenniak\x00/home/mfenniak\x00/run/current-system/sw/bin/zsh\x00";

        let mut slice = &reader[..];
        let pwresponse = read_response_getpwbyuid(&mut slice)?;
        assert_eq!(pwresponse, PwResponse {
            header: PwResponseHeader {
                version: 2,
                found: 1,
                pw_name_len: 9,
                pw_passwd_len: 2,
                pw_uid: 1000,
                pw_gid: 100,
                pw_gecos_len: 16,
                pw_dir_len: 15,
                pw_shell_len: 31,
            },
            name: CString::new(b"mfenniak")?,
            passwd: CString::new(b"x")?,
            gecos: CString::new(b"Mathieu Fenniak")?,
            dir: CString::new(b"/home/mfenniak")?,
            shell: CString::new(b"/run/current-system/sw/bin/zsh")?,
        });

        Ok(())
    }

    #[test]
    fn test_response_from_getai() -> Result<()> {
        // Captured from strace-curl-nscd.txt
        let reader = b"\x02\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00&\x07\xf8\xb0@\n\x08\x01\x00\x00\x00\x00\x00\x00 \x03\xac\xd9\x0e\xc3\n\x02google.ca\x00";

        let mut slice = &reader[..];
        let airesponse = read_response_getai(&mut slice)?;
        assert_eq!(airesponse, AiResponse {
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
        });

        Ok(())
    }
}
