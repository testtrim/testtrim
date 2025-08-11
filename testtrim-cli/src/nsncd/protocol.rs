// SPDX-FileCopyrightText: Copyright 2020 Two Sigma Open Source, LLC
// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: Apache-2.0
//
// Modifications have been made from the original source (https://github.com/twosigma/nsncd) by subsequent author
// Mathieu Fenniak.  The terms of the Apache 2.0 license are retained for this file, as required by the license.  The
// modifications are not likely suitable for upstream inclusion due to the varied nature of usage: in this project these
// definitions are being used to interpret and decode bi-diretional nscd communication, a capability that is not
// required to serve the needs of the upstream project.
//
// Original copyright and licensing header follows:
/*
 * Copyright 2020 Two Sigma Open Source, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! The nscd protocol definition (at least, the parts of it we care about).
//!
//! The response structs here only describe the format of the header of the
//! response. For each such response, if the lookup succeeded, there are
//! additional strings we need to send after the header. Those are dealt with in
//! `handlers::send_{user,group}`. For a full picture of the protocol, you will
//! need to read both.

use std::net::IpAddr;

use anyhow::{Context, Result, ensure};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;

use nix::libc::c_int;

/// This is version 2 of the glibc nscd protocol. The version is passed as part
/// of each message header.
pub const VERSION: i32 = 2;

// /// Errors used in {Ai,Hst}ResponseHeader structs.
// /// See NSCD's resolv/netdb.h for the complete list.
// pub const H_ERRNO_NETDB_SUCCESS: i32 = 0;
// #[allow(dead_code)]
// pub const H_ERRNO_TRY_AGAIN: i32 = 2; // Non-Authoritative Host not found

/// Available services. This enum describes all service types the nscd protocol
/// knows about, though we only implement `GETPW*`, `GETGR*`, and `INITGROUPS`.
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[allow(clippy::upper_case_acronyms)]
pub enum RequestType {
    GETPWBYNAME,
    GETPWBYUID,
    GETGRBYNAME,
    GETGRBYGID,
    GETHOSTBYNAME,
    GETHOSTBYNAMEv6,
    GETHOSTBYADDR,
    GETHOSTBYADDRv6,
    /// Shut the server down.
    SHUTDOWN,
    /// Get the server statistic.
    GETSTAT,
    /// Invalidate one special cache.
    INVALIDATE,
    GETFDPW,
    GETFDGR,
    GETFDHST,
    GETAI,
    INITGROUPS,
    GETSERVBYNAME,
    GETSERVBYPORT,
    GETFDSERV,
    GETNETGRENT,
    INNETGR,
    GETFDNETGR,
    LASTREQ,
}

/// An incoming request. All requests have a version, a type, and a string key.
/// This struct keeps the type and key, because that's what we need to reply to
/// it, we only handle one version and we validate, but don't retain it.
///
/// The parsed Request object is valid as long as the buffer it is parsed from
/// (that is, the key is a reference to the bytes in the buffer).
#[derive(Debug)]
pub struct Request<'a> {
    pub ty: RequestType,
    #[allow(dead_code)] // used in a test, only
    pub key: &'a [u8],
}

impl<'a> Request<'a> {
    /// Parse a Request from a buffer.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        ensure!(buf.len() >= 12, "request body too small: {}", buf.len());

        let version = buf[0..4].try_into().map(i32::from_ne_bytes)?;
        ensure!(version == VERSION, "wrong protocol version {version}");

        let type_val = buf[4..8].try_into().map(i32::from_ne_bytes)?;
        let ty = FromPrimitive::from_i32(type_val)
            .with_context(|| format!("invalid enum value {type_val}"))?;

        let key_len = buf[8..12].try_into().map(i32::from_ne_bytes)?;
        let key_end = (12 + key_len).try_into()?;
        ensure!(buf.len() >= key_end, "request body too small");

        Ok(Request {
            ty,
            key: &buf[12..key_end],
        })
    }
}

// the nscd protocol just puts structs onto a socket and hopes they come out
// the same size on the other end. it seems to assume there is no padding
// interpreted by the compiler.
//
// this is pretty sketchy, but we have to match it, so all of the structs
// below use repr(C) and not repr(padded).

/// Structure containing the resulting data of a [`RequestType::GETAI`] operation.
///
/// Unlike most of the data types declared in this module, this structure isn't meant to be directly serialized to the
/// wire. Instead, it contains all the necessary informations to to generate a [`AiResponseHeader`] and its associated
/// payload.
#[derive(Debug, Clone, PartialEq)]
pub struct AiResponse {
    pub addrs: Vec<IpAddr>,
    pub canon_name: String,
}

/// Response Header derived from the glibc `ai_response_header` structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AiResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub naddrs: c_int,
    pub addrslen: c_int,
    pub canonlen: c_int,
    pub error: c_int,
}

impl AiResponseHeader {
    // /// Serialize the header to bytes
    // ///
    // /// The C implementations of nscd just take the address of the struct, so
    // /// we will too, to make it easy to convince ourselves it's correct.
    // pub fn as_slice(&self) -> &[u8] {
    //     let p = self as *const _ as *const u8;
    //     unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    // }

    /// Parse from a buffer.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        ensure!(buf.len() >= 24, "request body too small: {}", buf.len());

        let version = buf[0..4].try_into().map(i32::from_ne_bytes)?;
        ensure!(version == VERSION, "wrong protocol version {version}");

        let found = buf[4..8].try_into().map(i32::from_ne_bytes)?;
        let naddrs = buf[8..12].try_into().map(i32::from_ne_bytes)?;
        let addrslen = buf[12..16].try_into().map(i32::from_ne_bytes)?;
        let canonlen = buf[16..20].try_into().map(i32::from_ne_bytes)?;
        let error = buf[20..24].try_into().map(i32::from_ne_bytes)?;

        Ok(AiResponseHeader {
            version,
            found,
            naddrs,
            addrslen,
            canonlen,
            error,
        })
    }
}
