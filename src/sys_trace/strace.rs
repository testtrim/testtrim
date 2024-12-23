// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, ensure, Result};
use lazy_static::lazy_static;
use log::warn;
use regex::Regex;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command as SyncCommand, Output},
    str::FromStr,
};
use tokio::process::Command;

use crate::{errors::SubcommandErrors, sys_trace::trace::SocketCaptureState};

use super::{
    trace::{DraftTrace, SocketCapture, SocketOperation, Trace, UnifiedSocketAddr},
    SysTraceCommand,
};

/// Implementation of `SysTraceCommand` that uses the `strace` command to trace all the relevant system calls.
pub struct STraceSysTraceCommand;

lazy_static! {

    // When tracing multiple processes, it's likely to get situations like this:
    //
    // ```
    // 189532 chdir("/home/mfenniak/Dev" <unfinished ...>
    // 189531 openat(AT_FDCWD, "README.md", O_RDONLY|O_CLOEXEC <unfinished ...>
    // 189532 <... chdir resumed>)             = 0
    // 189531 <... openat resumed>)            = 4
    // ```
    //
    // This indicates that before 189532's chdir call was completed, 189531 started an openat call; then they both
    // finished.  The return-value is listed on a separate line in the strace.  In these cases, to filter out failed
    // calls, we'll need to put these together and track them across multiple lines.

    static ref openat: Regex = Regex::new(
        // note that this will exclude any openat that had an error (eg. ENOENT) because it matches on a number then the
        // string terminator; an error would have a -1 response followed by an error code that wouldn't match.
        r#"^(?<pid>[0-9]+)\s+openat\((?<dirfd>AT_FDCWD|[0-9]+),\s+"(?<path>(?:[^"\\]|\\.)*)",\s+[^)]+(?<end>\)\s+=\s+\d+|\s*<unfinished \.\.\.>)$"#
    )
    .unwrap();

    // Here we don't filter out failures; we need to still match so that we can unwind any state stored from the
    // "unfinished" syscall.
    static ref openat_resumed: Regex = Regex::new(
        r"^(?<pid>[0-9]+)\s+<... openat resumed>\)\s+=\s+(?<retval>-?\d+)"
    )
    .unwrap();

    static ref chdir: Regex = Regex::new(
        // note that this will exclude any syscall that had an error, unless unfinished
        r#"^(?<pid>[0-9]+)\s+chdir\("(?<path>(?:[^"\\]|\\.)*)"(?<end>\)\s+=\s+0|\s*<unfinished \.\.\.>)$"#
    )
    .unwrap();

    // Here we don't filter out failures; we need to still match so that we can unwind any state stored from the
    // "unfinished" syscall.
    static ref chdir_resumed: Regex = Regex::new(
        r"^(?<pid>[0-9]+)\s+<... chdir resumed>\)\s+=\s+(?<retval>-?\d+)"
    )
    .unwrap();

    // 337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653
    static ref clone: Regex = Regex::new(
        r"(?x)
        ^(?<pid>[0-9]+)
        \s+
        clone3?\(.+                      # call & arguments
        (?<end>
            \)\s+=\s+(?<child_pid>-?\d+)
            .*                         # possible errno output; child_pid = -1
            |
            <unfinished\s\.\.\.>
        )
        $"
    )
    .unwrap();

    // Here we don't filter out failures; we need to still match so that we can unwind any state stored from the
    // "unfinished" syscall.
    static ref clone_resumed: Regex = Regex::new(
        r"(?x)
        ^(?<pid>[0-9]+)
        \s+
        <...\sclone3?\sresumed>,?.*\)   # child_tidptr retval comes back here
        \s+=\s+
        (?<retval>-?\d+)
        .*                           # possible errno output; child_pid = -1
        $"
    )
    .unwrap();

    // 337651 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0
    // 337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)
    // 337651 connect(17, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, 16) = 0
    static ref connect: Regex = Regex::new(
        r#"(?x)
        ^(?<pid>[0-9]+)
        \s+
        connect\(                         # call & arguments
            (?<fd>\d+),                   # file descriptor (socket)
            \s+
            (
                \{
                    sa_family=AF_UNIX,
                    \s+
                    sun_path="(?<unix_path>(?:[^"\\]|\\.)*)"
                \}
                |
                \{
                    sa_family=AF_INET6,
                    \s+
                    sin6_port=htons\((?<sin6_port>\d+)\),
                    \s+
                    sin6_flowinfo=htonl\((?<sin6_flowinfo>\d+)\),
                    \s+
                    inet_pton\(
                        AF_INET6,
                        \s+
                        "(?<sin6_addr>[^"]+)",
                        \s+
                        &sin6_addr
                    \),
                    \s+
                    sin6_scope_id=(?<sin6_scope_id>\d+)
                \}
                |
                \{
                    sa_family=AF_INET,
                    \s+
                    sin_port=htons\((?<sin_port>\d+)\),
                    \s+
                    sin_addr=inet_addr\("(?<sin_addr>[^"]+)"\)
                \}
            ),
            \s+
            \d+                           # addrlen
        (?<end>
            \)\s+=\s+(?<retval>-?\d+)
            .*                         # possible errno output
            |
            \s+
            <unfinished\s\.\.\.>
        )
        $"#
    )
    .unwrap();

    // 1343641 sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00", 19, MSG_NOSIGNAL, NULL, 0) = 19
    static ref sendto: Regex = Regex::new(
        r#"(?x)
        ^(?<pid>[0-9]+)
        \s+
        sendto\(                          # call & arguments
            (?<fd>\d+),                   # file descriptor (socket)
            \s+
            (
                "(?<data>(?:[^"\\]|\\.)*)"(?<data_incomplete>\.\.\.)?,   # buffer
                |
                (?<struct> \[.+ ),  # some form of structured data
            )
            \s+
            (?<buffer_size>\d+),
            \s+
            (MSG_NOSIGNAL|0),
            \s+
            (NULL|\{.*\}),
            \s+
            \d+
        (?<end>
            \)\s+=\s+(?<send_size>-?\d+)
            .*                         # possible errno output
            |
            \s+
            <unfinished\s\.\.\.>
        )
        $"#
    )
    .unwrap();

    static ref sendto_resumed: Regex = Regex::new(
        r"^(?<pid>[0-9]+)\s+<... sendto resumed>\)\s+=\s+(?<retval>-?\d+)"
    )
    .unwrap();

    // 1316971 close(3)                        = 0
    static ref close: Regex = Regex::new(
        r"(?x)
        ^(?<pid>[0-9]+)
        \s+
        close\(                          # call
            (?<fd>\d+)                   # file descriptor (socket)
        (?<end>
            \)\s+=\s+(?<retval>-?\d+)
            .*                         # possible errno output; child_pid = -1
            |
            \s+
            <unfinished\s\.\.\.>
        )
        $"
    )
    .unwrap();

    // 1435293 <... close resumed>)            = 0
    static ref close_resumed: Regex = Regex::new(
        r"(?x)
        ^(?<pid>[0-9]+)
        \s+
        <...\sclose\sresumed>\)
        \s+=\s+
        (?<retval>-?\d+)
        .*                           # possible errno output; child_pid = -1
        $"
    )
    .unwrap();

    // 1343641 read(3, "\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00", 36) = 36
    static ref read_regex: Regex = Regex::new(
        r#"(?x)
        ^(?<pid>[0-9]+)
        \s+
        read\(                            # call & arguments
            (?<fd>\d+),                   # file descriptor (socket)
            \s+
        (?<end>
            "(?<data>(?:[^"\\]|\\.)*)"(?<data_incomplete>\.\.\.)?,   # buffer
            \s+
            (?<buffer_size>\d+)
            \)\s+=\s+(?<read_size>-?\d+)
            .*                         # possible errno output
            |
            \s+
            <unfinished\s\.\.\.>
        )
        $"#
    )
    .unwrap();

    // 1435250 <... read resumed>"{\"reason\":\"compiler-artifact\",\"package_id\":\"registry+https://github.com/rust-lang/crates.io-index#byteorder@1.5.0\",\"manifest_path\":\"/home/mfenniak/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/byteorder-1.5.0/Cargo.toml\",\"target\":{\"kind\":[\"lib\"],\"cr"..., 1140) = 792
    // 1435250 <... read resumed>0x5582bab4718c, 1140) = -1 EAGAIN (Resource temporarily unavailable)
    static ref read_resumed: Regex = Regex::new(
        r#"(?x)
        ^(?<pid>[0-9]+)
        \s+
        <...\sread\sresumed>
        (
            "(?<data>(?:[^"\\]|\\.)*)"(?<data_incomplete>\.\.\.)?,   # buffer
            |
            0x[0-9a-f]+,    # pointer to buffer
        )
        \s+
        (?<buffer_size>\d+)
        \)
        \s+=\s+
        (?<retval>(-?\d+|\?))        # retval can be a number, pos or neg, or ? for a ERESTARTSYS
        .*                           # possible errno output; child_pid = -1
        $"#
    )
    .unwrap();

}

#[derive(Debug, PartialEq)]
enum CloneParse {
    FinishedError,
    FinishedSuccess {
        parent_pid: String,
        child_pid: String,
    },
    Unfinished {
        parent_pid: String,
    },
}

#[derive(Debug, PartialEq)]
enum OpenPath {
    RelativeToCwd(PathBuf),
    RelativeToOpenDirFD(PathBuf, i32), // i32 is the directory file descriptor
}

#[derive(Debug, PartialEq)]
enum OpenParse {
    FinishedError { pid: String },
    FinishedSuccess { pid: String, path: OpenPath },
    FinishedPreviousSuccessfully { pid: String },
    Unfinished { pid: String, path: OpenPath },
}

#[derive(Debug, PartialEq)]
enum ChdirParse {
    FinishedError { pid: String },
    FinishedSuccess { pid: String, path: PathBuf },
    FinishedPreviousSuccessfully { pid: String },
    Unfinished { pid: String, path: PathBuf },
}

#[derive(Debug, PartialEq)]
enum SendtoParse {
    FinishedError {
        pid: String,
    },
    FinishedSuccess {
        pid: String,
        socket_fd: String,
        data: Vec<u8>,
        bytes_to_send: usize,
        bytes_sent: usize,
    },
    FinishedSuccessPartialBuffer {
        pid: String,
        socket_fd: String,
    },
    FinishedPreviousSuccessfully {
        pid: String,
        bytes_sent: usize,
    },
    UnfinishedPartialBuffer {
        pid: String,
        socket_fd: String,
    },
    Unfinished {
        pid: String,
        socket_fd: String,
        data: Vec<u8>,
        bytes_to_send: usize,
    },
    UnfinishedStructuredData {
        pid: String,
        socket_fd: String,
    },
}

#[derive(Debug, PartialEq)]
enum ReadParse {
    FinishedError {
        pid: String,
    },
    FinishedSuccess {
        pid: String,
        fd: String,
        data: Vec<u8>,
        buffer_size: usize,
        bytes_read: usize,
    },
    FinishedSuccessPartialBuffer {
        pid: String,
        fd: String,
    },
    FinishedPreviousSuccessfully {
        pid: String,
        data: Vec<u8>,
        buffer_size: usize,
        bytes_read: usize,
    },
    FinishedPreviousSuccessPartialBuffer {
        pid: String,
    },
    Unfinished {
        pid: String,
        fd: String,
    },
}

#[derive(Debug, PartialEq)]
enum CloseParse {
    FinishedError { pid: String },
    FinishedSuccess { pid: String, socket_fd: String },
    FinishedPreviousSuccessfully { pid: String },
    Unfinished { pid: String, socket_fd: String },
}

#[derive(Debug, PartialEq)]
enum ConnectParse {
    // connect is a trickier syscall than the others we've handled because it is typically used with non-blocking
    // sockets, and so connect() is likely to return EINPROGRESS immediately and then be followed-up with poll() calls
    // to check if the socket is available.  I think it doesn't matter if connect succeeds, fails, becomes an unfinished
    // syscall, or returns EINPROGRESS or EAGAIN -- all of them mean the same thing, this strace tried to reach outside
    // of its process through the network and therefore we'll report that it has an external dependency.  This
    // simplifies the implementation here and seems more-or-less right.
    //
    // So rather than all the states that other parses will have, we'll just have an indeterminate state with the socket
    // address that was accessed.
    IndeterminateResult {
        pid: String,
        socket_fd: String,
        socket_addr: UnifiedSocketAddr,
    },
}

#[derive(Debug, PartialEq)]
enum ParseLine {
    Open(OpenParse),
    Chdir(ChdirParse),
    Clone(CloneParse),
    Connect(ConnectParse),
    Sendto(SendtoParse),
    Close(CloseParse),
    Read(ReadParse),
}

impl STraceSysTraceCommand {
    pub fn is_available() -> bool {
        let output = SyncCommand::new("strace").arg("--help").output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn new() -> Self {
        STraceSysTraceCommand {}
    }

    fn parse_openat(trace: &str) -> Option<OpenParse> {
        // Note: only openat w/ AT_FDCWD is supported, which opens a path from the current working directory (unless
        // absolute).  Opening a directory, then opening a file in it, isn't supported by this.  FIXME: It *should*
        // probably be detected and either a warning or error generated though, so that it's not silently ignored.
        openat.captures(trace).map(|cap| {
            let dirfd = String::from(&cap["dirfd"]);
            let pid = String::from(&cap["pid"]);
            let path = PathBuf::from(
                String::from(&cap["path"])
                    // Un-escape any escaped double-quotes
                    .replace("\\\"", "\""),
            );
            let path = if dirfd == "AT_FDCWD" {
                OpenPath::RelativeToCwd(path)
            } else {
                OpenPath::RelativeToOpenDirFD(
                    path,
                    str::parse(&dirfd).expect("regex-verified int couldn't be parsed as int"),
                )
            };
            if cap["end"].starts_with(')') {
                OpenParse::FinishedSuccess { pid, path }
            } else {
                OpenParse::Unfinished { pid, path }
            }
        })
    }

    fn parse_openat_resumed(trace: &str) -> Option<OpenParse> {
        openat_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                OpenParse::FinishedError { pid }
            } else {
                OpenParse::FinishedPreviousSuccessfully { pid }
            }
        })
    }

    fn parse_chdir(trace: &str) -> Option<ChdirParse> {
        chdir.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let path = String::from(&cap["path"])
                // Un-escape any escaped double-quotes
                .replace("\\\"", "\"");
            if cap["end"].starts_with(')') {
                ChdirParse::FinishedSuccess {
                    pid,
                    path: PathBuf::from(path),
                }
            } else {
                ChdirParse::Unfinished {
                    pid,
                    path: PathBuf::from(path),
                }
            }
        })
    }

    fn parse_chdir_resumed(trace: &str) -> Option<ChdirParse> {
        chdir_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                ChdirParse::FinishedError { pid }
            } else {
                ChdirParse::FinishedPreviousSuccessfully { pid }
            }
        })
    }

    fn parse_clone(trace: &str) -> Option<CloneParse> {
        clone.captures(trace).map(|cap| {
            let parent_pid = String::from(&cap["pid"]);
            if cap["end"].starts_with(')') {
                let child_pid = String::from(&cap["child_pid"]);
                if child_pid == "-1" {
                    CloneParse::FinishedError
                } else {
                    CloneParse::FinishedSuccess {
                        parent_pid,
                        child_pid,
                    }
                }
            } else {
                CloneParse::Unfinished { parent_pid }
            }
        })
    }

    fn parse_clone_resumed(trace: &str) -> Option<CloneParse> {
        clone_resumed.captures(trace).map(|cap| {
            let parent_pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                CloneParse::FinishedError
            } else {
                CloneParse::FinishedSuccess {
                    parent_pid,
                    child_pid: retval,
                }
            }
        })
    }

    fn parse_connect(trace: &str) -> Option<ConnectParse> {
        connect.captures(trace).and_then(|cap| {
            #[allow(clippy::manual_map)] // more extensible with current pattern
            let socket_addr = if let Some(unix_path) = cap.name("unix_path") {
                Some(UnifiedSocketAddr::Unix(PathBuf::from(unix_path.as_str())))
            } else if let Some(sin6_addr) = cap.name("sin6_addr") {
                let port = u16::from_str(&cap["sin6_port"]).unwrap();
                if port == 0 {
                    // port = 0 are internal syscalls to prepare the local endpoint and test feasibility of different
                    // remote endpoints.  As they don't really communicate externally, it makes sense to filter them
                    // out.
                    None
                } else {
                    Some(UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(
                        std::net::SocketAddrV6::new(
                            std::net::Ipv6Addr::from_str(sin6_addr.as_str()).unwrap(),
                            port,
                            u32::from_str(&cap["sin6_flowinfo"]).unwrap(),
                            u32::from_str(&cap["sin6_scope_id"]).unwrap(),
                        ),
                    )))
                }
            } else if let Some(sin_addr) = cap.name("sin_addr") {
                let port = u16::from_str(&cap["sin_port"]).unwrap();
                if port == 0 {
                    // port = 0 are internal syscalls to prepare the local endpoint and test feasibility of different
                    // remote endpoints.  As they don't really communicate externally, it makes sense to filter them
                    // out.
                    None
                } else {
                    Some(UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(
                        std::net::SocketAddrV4::new(
                            std::net::Ipv4Addr::from_str(sin_addr.as_str()).unwrap(),
                            port,
                        ),
                    )))
                }
            } else {
                panic!("must have parsed socket_addr or else our regex isn't matching the strace output");
            };

            socket_addr.map(|s| ConnectParse::IndeterminateResult {
                pid: String::from(&cap["pid"]),
                socket_fd: String::from(&cap["fd"]),
                socket_addr: s,
            })
        })
    }

    /// Input string is "\"...\"", containing octal escape codes (\x00 -> null byte) and other ascii characters, as
    /// output from strace during --strings-in-hex=non-ascii-chars
    fn parse_strace_hex_string(input: &str) -> Vec<u8> {
        let mut result = Vec::with_capacity(input.len());
        let mut chars = input.chars();

        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('x') => {
                        // Parse hex escape \xNN
                        let hex = chars
                            .next()
                            .expect("Invalid escape sequence \\x not followed by two chars")
                            .to_string()
                            + &chars
                                .next()
                                .expect("Invalid escape sequence \\x not followed by two chars")
                                .to_string();
                        result.push(
                            u8::from_str_radix(&hex, 16).expect("Invalid hex escape: \\x{hex}"),
                        );
                    }
                    // `man strace` -> \t, \n, \v, \f, \r are all possible
                    Some('t') => result.push(b'\t'),  // Tab
                    Some('n') => result.push(b'\n'),  // Newline
                    Some('v') => result.push(0x0b),   // Vertical tab
                    Some('f') => result.push(0x0c),   // form feed page break
                    Some('r') => result.push(b'\r'),  // Carriage return
                    Some('"') => result.push(b'"'),   // Escaped double-quote
                    Some('\\') => result.push(b'\\'), // Backslash escaped
                    Some(c) => {
                        panic!("Invalid escape sequence: \\{c}; original string was: {input}")
                    }
                    None => panic!("Invalid escape sequence, \\ with no following character"),
                },
                c => result.push(c as u8),
            }
        }

        result
    }

    fn parse_sendto(trace: &str) -> Option<SendtoParse> {
        sendto.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            if cap["end"].starts_with(')') {
                let send_size = String::from(&cap["send_size"]);
                if send_size == "-1" {
                    SendtoParse::FinishedError { pid }
                } else if cap.name("data_incomplete").is_some() || cap.name("struct").is_some() {
                    SendtoParse::FinishedSuccessPartialBuffer {
                        pid,
                        socket_fd: String::from(&cap["fd"]),
                    }
                } else {
                    SendtoParse::FinishedSuccess {
                        pid,
                        socket_fd: String::from(&cap["fd"]),
                        data: Self::parse_strace_hex_string(&cap["data"]),
                        bytes_to_send: usize::from_str(&cap["buffer_size"]).unwrap(),
                        bytes_sent: usize::from_str(&cap["send_size"]).unwrap(),
                    }
                }
            } else if cap.name("data_incomplete").is_some() {
                SendtoParse::UnfinishedPartialBuffer {
                    pid,
                    socket_fd: String::from(&cap["fd"]),
                }
            } else if cap.name("struct").is_some() {
                SendtoParse::UnfinishedStructuredData {
                    pid,
                    socket_fd: String::from(&cap["fd"]),
                }
            } else {
                SendtoParse::Unfinished {
                    pid,
                    socket_fd: String::from(&cap["fd"]),
                    data: Self::parse_strace_hex_string(&cap["data"]),
                    bytes_to_send: usize::from_str(&cap["buffer_size"]).unwrap(),
                }
            }
        })
    }

    fn parse_sendto_resumed(trace: &str) -> Option<SendtoParse> {
        sendto_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                SendtoParse::FinishedError { pid }
            } else {
                SendtoParse::FinishedPreviousSuccessfully {
                    pid,
                    bytes_sent: usize::from_str(&cap["retval"]).unwrap(),
                }
            }
        })
    }

    fn parse_read(trace: &str) -> Option<ReadParse> {
        read_regex.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            if cap["end"].starts_with('\"') {
                let read_size = String::from(&cap["read_size"]);
                if read_size == "-1" {
                    ReadParse::FinishedError { pid }
                } else if cap.name("data_incomplete").is_some() {
                    ReadParse::FinishedSuccessPartialBuffer {
                        pid,
                        fd: String::from(&cap["fd"]),
                    }
                } else {
                    ReadParse::FinishedSuccess {
                        pid,
                        fd: String::from(&cap["fd"]),
                        data: Self::parse_strace_hex_string(&cap["data"]),
                        buffer_size: usize::from_str(&cap["buffer_size"]).unwrap(),
                        bytes_read: usize::from_str(&cap["read_size"]).unwrap(),
                    }
                }
            } else {
                ReadParse::Unfinished {
                    pid,
                    fd: String::from(&cap["fd"]),
                }
            }
        })
    }

    fn parse_read_resumed(trace: &str) -> Option<ReadParse> {
        read_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') || retval.starts_with('?') {
                // negative or restart retval
                ReadParse::FinishedError { pid }
            } else if cap.name("data_incomplete").is_some() {
                ReadParse::FinishedPreviousSuccessPartialBuffer { pid }
            } else {
                ReadParse::FinishedPreviousSuccessfully {
                    pid,
                    data: Self::parse_strace_hex_string(&cap["data"]),
                    buffer_size: usize::from_str(&cap["buffer_size"]).unwrap(),
                    bytes_read: usize::from_str(&retval).unwrap(),
                }
            }
        })
    }

    fn parse_close(trace: &str) -> Option<CloseParse> {
        close.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            if cap["end"].starts_with(')') {
                let retval = String::from(&cap["retval"]);
                if retval == "0" {
                    CloseParse::FinishedSuccess {
                        pid,
                        socket_fd: String::from(&cap["fd"]),
                    }
                } else {
                    CloseParse::FinishedError { pid }
                }
            } else {
                CloseParse::Unfinished {
                    pid,
                    socket_fd: String::from(&cap["fd"]),
                }
            }
        })
    }

    fn parse_close_resumed(trace: &str) -> Option<CloseParse> {
        close_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                CloseParse::FinishedError { pid }
            } else {
                CloseParse::FinishedPreviousSuccessfully { pid }
            }
        })
    }

    fn parse_line(trace: &str) -> Option<ParseLine> {
        if let Some(clone_parse) = Self::parse_clone(trace) {
            return Some(ParseLine::Clone(clone_parse));
        }
        if let Some(clone_parse) = Self::parse_clone_resumed(trace) {
            return Some(ParseLine::Clone(clone_parse));
        }
        if let Some(chdir_parse) = Self::parse_chdir(trace) {
            return Some(ParseLine::Chdir(chdir_parse));
        }
        if let Some(chdir_parse) = Self::parse_chdir_resumed(trace) {
            return Some(ParseLine::Chdir(chdir_parse));
        }
        if let Some(open_parse) = Self::parse_openat(trace) {
            return Some(ParseLine::Open(open_parse));
        }
        if let Some(open_parse) = Self::parse_openat_resumed(trace) {
            return Some(ParseLine::Open(open_parse));
        }
        if let Some(connect_parse) = Self::parse_connect(trace) {
            return Some(ParseLine::Connect(connect_parse));
        }
        if let Some(sendto_parse) = Self::parse_sendto(trace) {
            return Some(ParseLine::Sendto(sendto_parse));
        }
        if let Some(sendto_parse) = Self::parse_sendto_resumed(trace) {
            return Some(ParseLine::Sendto(sendto_parse));
        }
        if let Some(close_parse) = Self::parse_close(trace) {
            return Some(ParseLine::Close(close_parse));
        }
        if let Some(close_parse) = Self::parse_close_resumed(trace) {
            return Some(ParseLine::Close(close_parse));
        }
        if let Some(read_parse) = Self::parse_read(trace) {
            return Some(ParseLine::Read(read_parse));
        }
        if let Some(read_parse) = Self::parse_read_resumed(trace) {
            return Some(ParseLine::Read(read_parse));
        }
        None
    }

    fn read_trace_file(trace: &mut DraftTrace, trace_file: &Path) -> Result<()> {
        let file = File::open(trace_file)?;
        Self::read_trace(trace, BufReader::new(file))
    }

    fn read_trace<T: Read>(trace: &mut DraftTrace, read: T) -> Result<()> {
        // FIXME: this assumes that the contents of the trace are UTF-8; this probably isn't right
        let lines = BufReader::new(read).lines();

        let mut pid_openat_in_progress: HashMap<String, OpenPath> = HashMap::new();
        let mut pid_cwd: HashMap<String, PathBuf> = HashMap::new();
        let mut pid_cwd_in_progress: HashMap<String, PathBuf> = HashMap::new();
        let mut pid_socket_fd_captures: HashMap<(String, String), SocketCapture> = HashMap::new();
        let mut pid_close_in_progress: HashMap<String, String> = HashMap::new();
        struct InProgressSendto {
            socket_fd: String,
            data: Option<Vec<u8>>,
        }
        let mut pid_sendto_in_progress: HashMap<String, InProgressSendto> = HashMap::new();
        let mut pid_read_in_progress: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        for line in lines {
            let line = line?;
            line_count += 1;

            let Some(parse_result) = Self::parse_line(&line) else {
                continue;
            };

            match parse_result {
                ParseLine::Open(OpenParse::FinishedSuccess {
                    pid,
                    path: open_path,
                }) => {
                    if let OpenPath::RelativeToCwd(mut path) = open_path {
                        if let Some(cwd) = pid_cwd.get(&pid) {
                            path = cwd.join(path);
                        }
                        trace.add_open(path);
                    } else {
                        warn!("open path {:?} not yet supported for strace", open_path);
                    }
                }
                ParseLine::Open(OpenParse::FinishedError { pid }) => {
                    pid_openat_in_progress.remove(&pid);
                }
                ParseLine::Open(OpenParse::Unfinished {
                    pid,
                    path: mut open_path,
                }) => {
                    if let OpenPath::RelativeToCwd(ref inner_path) = open_path {
                        if let Some(cwd) = pid_cwd.get(&pid) {
                            // As pid_cwd could change by the time the open finishes, we'll capture and join it as soon
                            // as we can.
                            open_path = OpenPath::RelativeToCwd(cwd.join(inner_path));
                        }
                    }
                    let prev = pid_openat_in_progress.insert(pid, open_path);
                    ensure!(
                        prev.is_none(),
                        "pid_openat_in_progress shouldn't be in-progress multiple times; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Open(OpenParse::FinishedPreviousSuccessfully { pid }) => {
                    let path = pid_openat_in_progress.remove(&pid);
                    if let Some(path) = path {
                        match path {
                            OpenPath::RelativeToCwd(path) => trace.add_open(path),
                            OpenPath::RelativeToOpenDirFD(path, fd) => {
                                warn!("open path {path:?} relative to directory fd {fd} is not yet supported for trace");
                            }
                        }
                    } else {
                        return Err(anyhow!(
                            "pid openat was resumed but no unfinished syscall was found; line # {line_count} = {line:?}"
                        ));
                    }
                }

                ParseLine::Chdir(ChdirParse::FinishedSuccess { pid, path }) => {
                    let previous_path = pid_cwd.remove(&pid).unwrap_or(PathBuf::from(""));
                    let new_path = previous_path.join(path);
                    pid_cwd.insert(pid, new_path);
                }
                ParseLine::Chdir(ChdirParse::Unfinished { pid, path }) => {
                    let prev = pid_cwd_in_progress.insert(pid, PathBuf::from(&path));
                    ensure!(
                        prev.is_none(),
                        "pid_cwd_in_progress shouldn't be in-progress multiple times; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Chdir(ChdirParse::FinishedError { pid }) => {
                    pid_cwd_in_progress.remove(&pid);
                }
                ParseLine::Chdir(ChdirParse::FinishedPreviousSuccessfully { pid }) => {
                    let path = pid_cwd_in_progress.remove(&pid);
                    if let Some(filepath) = path {
                        // FIXME: code duplication between interrupted and direct path
                        let previous_path = pid_cwd.remove(&pid).unwrap_or(PathBuf::from(""));
                        let new_path = previous_path.join(filepath);
                        pid_cwd.insert(pid, new_path);
                    } else {
                        return Err(anyhow!(
                            "pid chdir was resumed but no unfinished syscall was found; line # {line_count} = {line:?}"
                        ));
                    }
                }

                ParseLine::Clone(CloneParse::FinishedSuccess {
                    parent_pid,
                    child_pid,
                }) => {
                    // Inherit working directory
                    if let Some(cwd) = pid_cwd.get(&parent_pid) {
                        pid_cwd.insert(child_pid, cwd.clone());
                    }
                }
                ParseLine::Clone(_) => {}

                ParseLine::Connect(ConnectParse::IndeterminateResult {
                    pid,
                    socket_fd,
                    socket_addr,
                }) => {
                    // Insert a new SocketCaptureState into pid_socket_in_progress by the pid & socket_fd.  Because we
                    // don't parse connect in a very precise way -- eg. handling unfinished and errors -- it's possible
                    // that pid_socket_fd_captures could already contain the same pid & socket.  In that case this will
                    // be a reinitialization which should be fine; the expected case is we're just finished an
                    // incomplete or non-blocking connect.
                    pid_socket_fd_captures.insert(
                        (pid, socket_fd),
                        SocketCapture {
                            socket_addr: socket_addr.clone(),
                            state: SocketCaptureState::Complete(Vec::new()),
                        },
                    );

                    // FIXME: in the near future we could probably remove add_connect and just use the SocketCapture
                    // data that is fed over to the trace when the socket is closed to extract all the connections.
                    trace.add_connect(socket_addr);
                }

                ParseLine::Sendto(SendtoParse::FinishedSuccess {
                    pid,
                    socket_fd,
                    data,
                    bytes_to_send: _,
                    bytes_sent,
                }) => {
                    let socket_capture =
                        pid_socket_fd_captures.get_mut(&(pid.clone(), socket_fd.clone()));
                    if let Some(socket_capture) = socket_capture {
                        if let SocketCaptureState::Complete(ref mut socket_operations) =
                            socket_capture.state
                        {
                            // Trim `data` to just the data actually sent (`bytes_sent`); a follow-up send operation should
                            // be invoked by the program if it wants to send the rest of this buffer.
                            socket_operations
                                .push(SocketOperation::Sent(data[..bytes_sent].to_owned()));
                        }
                        // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                ParseLine::Sendto(SendtoParse::FinishedSuccessPartialBuffer { pid, socket_fd }) => {
                    // "Corrupt" this stream as strace didn't receive all the data necessary to recreate it.
                    let in_progress =
                        pid_socket_fd_captures.get_mut(&(pid.clone(), socket_fd.clone()));
                    if let Some(in_progress) = in_progress {
                        in_progress.state = SocketCaptureState::Incomplete;
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                ParseLine::Sendto(
                    SendtoParse::UnfinishedPartialBuffer { pid, socket_fd }
                    | SendtoParse::UnfinishedStructuredData { pid, socket_fd },
                ) => {
                    let prev = pid_sendto_in_progress.insert(
                        pid,
                        InProgressSendto {
                            socket_fd,
                            data: None,
                        },
                    );
                    ensure!(
                        prev.is_none(),
                        "pid_sendto_in_progress shouldn't be in-progress multiple times; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Sendto(SendtoParse::Unfinished {
                    pid,
                    socket_fd,
                    data,
                    bytes_to_send: _,
                }) => {
                    let prev = pid_sendto_in_progress.insert(
                        pid,
                        InProgressSendto {
                            socket_fd,
                            data: Some(data),
                        },
                    );
                    ensure!(
                        prev.is_none(),
                        "pid_sendto_in_progress shouldn't be in-progress multiple times; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Sendto(SendtoParse::FinishedError { pid }) => {
                    let prev = pid_sendto_in_progress.remove(&pid);
                    ensure!(
                        prev.is_some(),
                        "received sendto FinishedError but had none in-progress; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Sendto(SendtoParse::FinishedPreviousSuccessfully {
                    pid,
                    bytes_sent,
                }) => {
                    let prev = pid_sendto_in_progress.remove(&pid);
                    ensure!(
                        prev.is_some(),
                        "received sendto FinishedPreviousSuccessfully but had none in-progress; line # {line_count} = {line:?}"
                    );
                    // FIXME: duplicate logic between finish here, and finished without doing "unfinished" logic, would
                    // be nice to consolidate this logic.
                    if let Some(inprogress) = prev {
                        let socket_capture = pid_socket_fd_captures
                            .get_mut(&(pid.clone(), inprogress.socket_fd.clone()));
                        if let Some(socket_capture) = socket_capture {
                            if let SocketCaptureState::Complete(ref mut socket_operations) =
                                socket_capture.state
                            {
                                if let Some(data) = inprogress.data {
                                    // Trim `data` to just the data actually sent (`bytes_sent`); a follow-up send
                                    // operation should be invoked by the program if it wants to send the rest of this
                                    // buffer.
                                    socket_operations
                                        .push(SocketOperation::Sent(data[..bytes_sent].to_owned()));
                                } else {
                                    socket_capture.state = SocketCaptureState::Incomplete;
                                }
                            }
                            // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                        }
                        // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                        // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                        // trace those, so we'll ignore any unrecognized sockets.
                    }
                }

                ParseLine::Close(CloseParse::FinishedSuccess { pid, socket_fd }) => {
                    let socket_capture = pid_socket_fd_captures.remove(&(pid, socket_fd));
                    if let Some(socket_capture) = socket_capture {
                        trace.add_socket_capture(socket_capture);
                    }
                    // No else case for warning if no socket present -- close(n) is used for file FDs which we're not
                    // capturing, so it will be common and normal for (pid, fd) to not be present.
                }
                ParseLine::Close(CloseParse::Unfinished { pid, socket_fd }) => {
                    let prev = pid_close_in_progress.insert(pid, socket_fd);
                    ensure!(
                        prev.is_none(),
                        "pid_close_in_progress shouldn't be in-progress multiple times; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Close(CloseParse::FinishedError { pid }) => {
                    let prev = pid_close_in_progress.remove(&pid);
                    ensure!(
                        prev.is_some(),
                        "received close FinishedError but had none in-progress; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Close(CloseParse::FinishedPreviousSuccessfully { pid }) => {
                    let prev = pid_close_in_progress.remove(&pid);
                    ensure!(
                        prev.is_some(),
                        "received close FinishedPreviousSuccessfully but had none in-progress; line # {line_count} = {line:?}"
                    );
                    if let Some(socket_fd) = prev {
                        let socket_capture = pid_socket_fd_captures.remove(&(pid, socket_fd));
                        if let Some(socket_capture) = socket_capture {
                            trace.add_socket_capture(socket_capture);
                        }
                    }
                }

                ParseLine::Read(ReadParse::FinishedSuccess {
                    pid,
                    fd,
                    data,
                    buffer_size: _,
                    bytes_read,
                }) => {
                    let socket_capture = pid_socket_fd_captures.get_mut(&(pid.clone(), fd.clone()));
                    if let Some(socket_capture) = socket_capture {
                        if let SocketCaptureState::Complete(ref mut socket_operations) =
                            socket_capture.state
                        {
                            // Trim `data` to just the data actually sent (`bytes_read`); of course strace does this for
                            // us already by only printing a partial buffer, but, seems like the right thing to do
                            socket_operations
                                .push(SocketOperation::Read(data[..bytes_read].to_owned()));
                        }
                        // else, socket capture is already marked as Incomplete, no need to put any data into it
                    }
                    // else -- read(fd) can read from files as well, which we aren't tracking the contents of -- so the
                    // else case here is common and not an error indicating any failed tracing.
                }
                ParseLine::Read(ReadParse::FinishedSuccessPartialBuffer { pid, fd }) => {
                    // "Corrupt" this stream as strace didn't receive all the data necessary to recreate it.
                    let socket_capture = pid_socket_fd_captures.get_mut(&(pid.clone(), fd.clone()));
                    if let Some(socket_capture) = socket_capture {
                        socket_capture.state = SocketCaptureState::Incomplete;
                    }
                    // else -- read(fd) can read from files as well, which we aren't tracking the contents of -- so the
                    // else case here is common and not an error indicating any failed tracing.
                }
                ParseLine::Read(ReadParse::Unfinished { pid, fd }) => {
                    let prev = pid_read_in_progress.insert(pid, fd);
                    ensure!(
                        prev.is_none(),
                        "pid_read_in_progress shouldn't be in-progress multiple times; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Read(ReadParse::FinishedError { pid }) => {
                    let prev = pid_read_in_progress.remove(&pid);
                    ensure!(
                        prev.is_some(),
                        "received read FinishedError but had none in-progress; line # {line_count} = {line:?}"
                    );
                }
                ParseLine::Read(ReadParse::FinishedPreviousSuccessfully {
                    pid,
                    data,
                    buffer_size: _,
                    bytes_read,
                }) => {
                    let fd = pid_read_in_progress.remove(&pid);
                    ensure!(
                        fd.is_some(),
                        "received read FinishedPreviousSuccessfully but had none in-progress; line # {line_count} = {line:?}"
                    );
                    if let Some(fd) = fd {
                        let socket_capture =
                            pid_socket_fd_captures.get_mut(&(pid.clone(), fd.clone()));
                        if let Some(socket_capture) = socket_capture {
                            if let SocketCaptureState::Complete(ref mut socket_operations) =
                                socket_capture.state
                            {
                                // Trim `data` to just the data actually sent (`bytes_read`); of course strace does this for
                                // us already by only printing a partial buffer, but, seems like the right thing to do
                                socket_operations
                                    .push(SocketOperation::Read(data[..bytes_read].to_owned()));
                            }
                            // else, socket capture is already marked as Incomplete, no need to put any data into it
                        }
                        // else -- read(fd) can read from files as well, which we aren't tracking the contents of -- so the
                        // else case here is common and not an error indicating any failed tracing.
                    }
                }
                ParseLine::Read(ReadParse::FinishedPreviousSuccessPartialBuffer { pid }) => {
                    let fd = pid_read_in_progress.remove(&pid);
                    ensure!(
                        fd.is_some(),
                        "received read FinishedPreviousSuccessPartialBuffer but had none in-progress; line # {line_count} = {line:?}"
                    );
                    if let Some(fd) = fd {
                        let socket_capture =
                            pid_socket_fd_captures.get_mut(&(pid.clone(), fd.clone()));
                        if let Some(socket_capture) = socket_capture {
                            socket_capture.state = SocketCaptureState::Incomplete;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl SysTraceCommand for STraceSysTraceCommand {
    async fn trace_command(&self, orig_cmd: Command, tmp: &Path) -> Result<(Output, Trace)> {
        let mut new_cmd = Command::new("strace");
        new_cmd
            .arg("--follow-forks")
            .arg("--trace=chdir,openat,clone,clone3,connect,sendto,close,read")
            .arg("--string-limit=256") // should be sufficient for DNS
            .arg("--strings-in-hex=non-ascii-chars")
            .arg("--output")
            .arg(tmp);

        new_cmd.arg(orig_cmd.as_std().get_program());
        for arg in orig_cmd.as_std().get_args() {
            new_cmd.arg(arg);
        }
        for (ref key, ref value) in orig_cmd.as_std().get_envs() {
            match value {
                Some(value) => new_cmd.env(key, value),
                None => new_cmd.env_remove(key),
            };
        }
        if let Some(cwd) = orig_cmd.as_std().get_current_dir() {
            new_cmd.current_dir(cwd);
        }

        let output = new_cmd
            .output()
            .await
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: "strace ...".to_string(),
                error: e,
            })?;
        let mut trace = DraftTrace::new();

        if output.status.success() {
            if let Err(e) = Self::read_trace_file(&mut trace, tmp) {
                // FIXME: this is a helpful debugging tool, but it needs to be disabled-by-default and configurable.
                std::fs::copy(
                    tmp,
                    Path::new("/home/mfenniak/Dev/testtrim/broken-trace.txt"),
                )?;
                return Err(e);
            }
        }

        // Occasionally useful for debugging to keep a copy of all the strace output...
        // std::fs::copy(
        //     &tmp,
        //     PathBuf::from("/home/mfenniak/Dev/testtrim-test-projects/logs/strace/")
        //         .join(tmp.file_name().unwrap()),
        // )?;

        Ok((output, trace.try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn parse_openat() {
        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/Fibonacci_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some(OpenParse::FinishedSuccess {
                pid: String::from("2892755"),
                path: OpenPath::RelativeToCwd(PathBuf::from("test_data/Fibonacci_Sequence.txt")),
            })
        );

        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/\"Fibonacci\"_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some(OpenParse::FinishedSuccess {
                pid: String::from("2892755"),
                path: OpenPath::RelativeToCwd(PathBuf::from(
                    "test_data/\"Fibonacci\"_Sequence.txt"
                )),
            })
        );

        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/\"Fibonacci\"_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some(OpenParse::FinishedSuccess {
                pid: String::from("2892755"),
                path: OpenPath::RelativeToCwd(PathBuf::from(
                    "test_data/\"Fibonacci\"_Sequence.txt"
                )),
            })
        );

        let res = STraceSysTraceCommand::parse_openat(
            // whitespace variations here; strace makes some weak alignment attempts
            r#"6503  openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 4"#,
        );
        assert_eq!(
            res,
            Some(OpenParse::FinishedSuccess {
                pid: String::from("6503"),
                path: OpenPath::RelativeToCwd(PathBuf::from("/proc/self/maps")),
            })
        );

        let res = STraceSysTraceCommand::parse_openat(
            // started without finish
            r#"189531 openat(AT_FDCWD, "README.md", O_RDONLY|O_CLOEXEC <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some(OpenParse::Unfinished {
                pid: String::from("189531"),
                path: OpenPath::RelativeToCwd(PathBuf::from("README.md")),
            })
        );

        let res = STraceSysTraceCommand::parse_openat(
            // not using AT_FDCWD...
            r#"1094494 openat(7, "gocoverdir", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some(OpenParse::Unfinished {
                pid: String::from("1094494"),
                path: OpenPath::RelativeToOpenDirFD(PathBuf::from("gocoverdir"), 7),
            })
        );
    }

    #[test]
    fn parse_openat_resumed() {
        let res = STraceSysTraceCommand::parse_openat_resumed(
            r"189531 <... openat resumed>)            = 4",
        );
        assert_eq!(
            res,
            Some(OpenParse::FinishedPreviousSuccessfully {
                pid: String::from("189531")
            })
        );
        let res = STraceSysTraceCommand::parse_openat_resumed(
            r"189531 <... openat resumed>)            = -1 ENOENT (No such file or directory)",
        );
        assert_eq!(
            res,
            Some(OpenParse::FinishedError {
                pid: String::from("189531")
            })
        );
    }

    #[test]
    fn parse_chdir() {
        let res =
            STraceSysTraceCommand::parse_chdir(r#"152738 chdir("/home/mfenniak")          = 0"#);
        assert_eq!(
            res,
            Some(ChdirParse::FinishedSuccess {
                pid: String::from("152738"),
                path: PathBuf::from("/home/mfenniak")
            })
        );

        let res = STraceSysTraceCommand::parse_chdir(
            r#"152738 chdir("test_data/\"Fibonacci\"_Sequence.txt") = 0"#,
        );
        assert_eq!(
            res,
            Some(ChdirParse::FinishedSuccess {
                pid: String::from("152738"),
                path: PathBuf::from("test_data/\"Fibonacci\"_Sequence.txt"),
            })
        );

        let res = STraceSysTraceCommand::parse_chdir(
            r#"189532 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some(ChdirParse::Unfinished {
                pid: String::from("189532"),
                path: PathBuf::from("/home/mfenniak/Dev"),
            })
        );

        let res = STraceSysTraceCommand::parse_chdir(
            r#"152738 chdir("/home/mfenniak")               = -1 ENOENT (No such file or directory)"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn parse_chdir_resumed() {
        let res = STraceSysTraceCommand::parse_chdir_resumed(
            r"189532 <... chdir resumed>)             = 0",
        );
        assert_eq!(
            res,
            Some(ChdirParse::FinishedPreviousSuccessfully {
                pid: String::from("189532")
            })
        );
        let res = STraceSysTraceCommand::parse_chdir_resumed(
            r"189531 <... chdir resumed>)             = -1 ENOENT (No such file or directory)",
        );
        assert_eq!(
            res,
            Some(ChdirParse::FinishedError {
                pid: String::from("189531")
            })
        );
    }

    #[test]
    fn parse_clone() {
        let res = STraceSysTraceCommand::parse_clone(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("337651"),
                child_pid: String::from("337653"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r"416671 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7fcdb7d7f990, parent_tid=0x7fcdb7d7f990, exit_signal=0, stack=0x7fcdb7b7f000, stack_size=0x1fff00, tls=0x7fcdb7d7f6c0} => {parent_tid=[416676]}, 88) = 416676",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("416671"),
                child_pid: String::from("416676"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = -1",
        );
        assert_eq!(res, Some(CloneParse::FinishedError));

        let res = STraceSysTraceCommand::parse_clone(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>",
        );
        assert_eq!(
            res,
            Some(CloneParse::Unfinished {
                parent_pid: String::from("337651")
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r"416676 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0x7fcdb7b73000, stack_size=0x9000}, 88 <unfinished ...>",
        );
        assert_eq!(
            res,
            Some(CloneParse::Unfinished {
                parent_pid: String::from("416676")
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r#"337653 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn parse_clone_resumed() {
        let res = STraceSysTraceCommand::parse_clone_resumed(
            r"337651 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("337651"),
                child_pid: String::from("337654"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone_resumed(
            r"416676 <... clone3 resumed>)            = 416677",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("416676"),
                child_pid: String::from("416677"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone_resumed(
            r"337651 <... clone resumed>, child_tidptr=0x0) = -1 EAGAIN (Some text here)",
        );
        assert_eq!(res, Some(CloneParse::FinishedError));

        let res = STraceSysTraceCommand::parse_clone_resumed(
            r#"337653 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn parse_connect() {
        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0"#,
        );
        assert_eq!(
            res,
            Some(ConnectParse::IndeterminateResult {
                pid: String::from("337651"),
                socket_fd: String::from("3"),
                socket_addr: UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket")),
            })
        );

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        );
        assert_eq!(
            res,
            Some(ConnectParse::IndeterminateResult {
                pid: String::from("337651"),
                socket_fd: String::from("5"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2607, 0xf8b0, 0x400a, 0x805, 0, 0, 0, 0x2003),
                    443,
                    0,
                    0
                ))),
            })
        );

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(17, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, 16) = 0"#,
        );
        assert_eq!(
            res,
            Some(ConnectParse::IndeterminateResult {
                pid: String::from("337651"),
                socket_fd: String::from("17"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(100, 100, 100, 100),
                    53
                ))),
            })
        );

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(17, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("100.100.100.100")}, 16) = 0"#,
        );
        assert_eq!(res, None);

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(17, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, 16 <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some(ConnectParse::IndeterminateResult {
                pid: String::from("337651"),
                socket_fd: String::from("17"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(100, 100, 100, 100),
                    53
                ))),
            })
        );

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)"#,
        );
        assert_eq!(
            res,
            Some(ConnectParse::IndeterminateResult {
                pid: String::from("337651"),
                socket_fd: String::from("5"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2607, 0xf8b0, 0x400a, 0x805, 0, 0, 0, 0x2003),
                    443,
                    0,
                    0
                ))),
            })
        );

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)"#,
        );
        assert_eq!(res, None);

        let res = STraceSysTraceCommand::parse_connect(
            r#"337653 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn multiprocess_cwd() {
        // trace_raw contains an strace that was generated by running scripts/generate-strace-multiproc-chdir.py under
        // strace.  This script accesses these files, but all in separate processes with `chdir` commands to the parent
        // directories; this creates a test case for per-process cwd tracking:
        //
        // - "flake.nix" (from start process's cwd)
        // - "/home/mfenniak/Dev/testtrim/README.md"
        // - "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
        // - "/home/mfenniak/.zsh_history"
        // - "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
        // - "/home/mfenniak/Dev/test.txt"
        //
        // The files listed above are not required to be present to make this test work; read_trace doesn't canonicalize
        // the paths.
        //
        // Regenerating this file (if needed?) is done by...
        // - run: strace --follow-forks --trace=chdir,openat,clone,clone3,connect --output
        //   tests/test_data/strace-multiproc-chdir.txt python scripts/generate-strace-multiproc-chdir.py
        // - verify: check to ensure that <...unfinished> cases exist in the newly generated file; this may randomly
        //   *not* happen, and if that's the case then we'd be missing some testing scope.
        let trace_raw = include_bytes!("../../tests/test_data/strace-multiproc-chdir.txt");

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok());

        let paths = trace.get_open_paths();
        assert!(paths.contains(&PathBuf::from("flake.nix")));
        assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/testtrim/README.md")));
        assert!(paths.contains(&PathBuf::from(
            "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
        )));
        assert!(paths.contains(&PathBuf::from("/home/mfenniak/.zsh_history")));
        assert!(paths.contains(&PathBuf::from(
            "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
        )));

        // test.txt is accessed in an unusual way compared to above cases; one process chdir's into /home/mfenniak/Dev,
        // and then starts a subprocess which inherits that directory, and then accesses "test.txt".  So if this test
        // case is failing, it's the inheritence of the cwd from parent processes that is to blame (probably).
        assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/test.txt")));
    }

    #[test]
    fn connect_trace_read() {
        // trace_raw contains an strace that was generated by running `curl https://www.google.com/` under an strace.
        //
        // Regenerating this file (if needed?) is done by...
        // - run: strace --follow-forks --trace=chdir,openat,clone,clone3,connect --output
        //   tests/test_data/strace-connect.txt curl https://www.google.com/
        let trace_raw = include_bytes!("../../tests/test_data/strace-connect.txt");

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok());

        let sockets = trace.get_connect_sockets();

        assert!(sockets.contains(&UnifiedSocketAddr::Unix(PathBuf::from(
            "/var/run/nscd/socket"
        ))));

        assert!(
            sockets.contains(&UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::new(142, 250, 217, 100), 443)
            )))
        );
    }

    #[test]
    fn parse_sendto() {
        let res = STraceSysTraceCommand::parse_sendto(
            r#"1343641 sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00\\", 20, MSG_NOSIGNAL, NULL, 0) = 20"#,
        );
        assert_eq!(
            res,
            Some(SendtoParse::FinishedSuccess {
                pid: String::from("1343641"),
                socket_fd: String::from("3"),
                data: Vec::from(b"\x02\x00\x00\x00\x0b\x00\x00\x00\x07\x00\x00\x00passwd\x00\x5C"),
                bytes_to_send: 20,
                bytes_sent: 20,
            })
        );

        let res = STraceSysTraceCommand::parse_sendto(
            r#"1343641 sendto(5, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xb5NG\xda\xd9\x9fX\x07\xd4\xb3a\x7f\xe7\\\xbe\x96\xe1\x01\xe3E;\x85\x1ei\xcc\xd6\xdfc\xf7~\xec\xb4 q\x96\x1cW\x805\x84\xce\x9b\xe8\xd4\x89j%|\x95:<\xd952zYbj\rM\xd1(\xa0D\x8e\x00>\x13\x02\x13\x03\x13\x01\xc0,\xc00\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0+\xc0/\x00\x9e\xc0$\xc0(\x00k\xc0#\xc0'\x00g\xc0\n\xc0\x14\x009\xc0\t\xc0\x13\x003\x00\x9d\x00\x9c\x00=\x00<\x005\x00/\x00\xff\x01\x00\x01u\x00\x00\x00\x0e\x00\f\x00\x00\tgoogle.ca\x00\v\x00\x04\x03\x00\x01\x02\x00\n\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x10\x00\x0e\x00\f\x02h2\x08http/1.1\x00\x16\x00\x00\x00\x17\x00\x00\x001\x00\x00\x00\r\x000\x00.\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x1a\x08\x1b\x08\x1c\x08\t\x08\n\x08\v\x08\x04"..., 517, MSG_NOSIGNAL, NULL, 0) = 517"#,
        );
        assert_eq!(
            res,
            // string length in capture wasn't large enough, so we got a "..." at the end of the buffer and lost part of
            // it.  The stream will be 'corrupted' by this so there's no point in returning the partial data.
            Some(SendtoParse::FinishedSuccessPartialBuffer {
                pid: String::from("1343641"),
                socket_fd: String::from("5"),
            })
        );

        let res = STraceSysTraceCommand::parse_sendto(
            r#"1924439 sendto(67, "\x08\x16\x9d\x01\x00\x0f\x00\x00\x00\x01\x00\x00\x00P\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00F\x00\x00\x00\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00(\x00\xf4\x82\x7f#\xdd\x08\x01g/tmp/testtrim-test.4ohDV2opl3P3/dotnet-coverage-specimen/MathFunctions.Tests/MathFunctions.Tests.csproj\r\x0fVSTestListTests\x04true\x14VSTestCLIRunSettings\x1aNUnit.DisplayName=FullName\x1dVSTestArtifactsProcess"..., 105755, 0, NULL, 0 <unfinished ...>"#,
        );
        assert_eq!(
            res,
            // string length in capture wasn't large enough, so we got a "..." at the end of the buffer and lost part of
            // it.  The stream will be 'corrupted' by this so there's no point in returning the partial data.
            Some(SendtoParse::UnfinishedPartialBuffer {
                pid: String::from("1924439"),
                socket_fd: String::from("67"),
            })
        );

        let res = STraceSysTraceCommand::parse_sendto(
            r#"1437464 sendto(14, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00", 19, MSG_NOSIGNAL, NULL, 0 <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some(SendtoParse::Unfinished {
                pid: String::from("1437464"),
                socket_fd: String::from("14"),
                data: Vec::from(b"\x02\x00\x00\x00\x0b\x00\x00\x00\x07\x00\x00\x00passwd\x00"),
                bytes_to_send: 19,
            })
        );

        let res = STraceSysTraceCommand::parse_sendto_resumed(
            r"1437464 <... sendto resumed>)           = 19",
        );
        assert_eq!(
            res,
            Some(SendtoParse::FinishedPreviousSuccessfully {
                pid: String::from("1437464"),
                bytes_sent: 19,
            })
        );

        let res = STraceSysTraceCommand::parse_sendto(
            r"1951665 sendto(12, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1734979518, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12 <unfinished ...>",
        );
        assert_eq!(
            res,
            Some(SendtoParse::UnfinishedStructuredData {
                pid: String::from("1951665"),
                socket_fd: String::from("12"),
            })
        );
    }

    #[test]
    fn parse_close() {
        let res =
            STraceSysTraceCommand::parse_close(r"1316971 close(3)                        = 0");
        assert_eq!(
            res,
            Some(CloseParse::FinishedSuccess {
                pid: String::from("1316971"),
                socket_fd: String::from("3"),
            })
        );

        let res = STraceSysTraceCommand::parse_close(r"1435293 close(17 <unfinished ...>");
        assert_eq!(
            res,
            Some(CloseParse::Unfinished {
                pid: String::from("1435293"),
                socket_fd: String::from("17"),
            })
        );

        let res = STraceSysTraceCommand::parse_close_resumed(
            r"1435293 <... close resumed>)            = 0",
        );
        assert_eq!(
            res,
            Some(CloseParse::FinishedPreviousSuccessfully {
                pid: String::from("1435293"),
            })
        );

        let res = STraceSysTraceCommand::parse_close_resumed(
            r"1436648 <... close resumed>)            = -1 EBADF (Bad file descriptor)",
        );
        assert_eq!(
            res,
            Some(CloseParse::FinishedError {
                pid: String::from("1436648"),
            })
        );
    }

    #[test]
    fn parse_read() {
        let res = STraceSysTraceCommand::parse_read(
            r#"1343641 read(3, "\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00", 38) = 36"#,
        );
        assert_eq!(
            res,
            Some(ReadParse::FinishedSuccess {
                pid: String::from("1343641"),
                fd: String::from("3"),
                data: Vec::from(b"\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00"),
                buffer_size: 38,
                bytes_read: 36,
            })
        );

        let res = STraceSysTraceCommand::parse_read(
            r#"1343641 read(3, "d attributes must be the same, and the optional\n# and supplied fields are just that :-)\npolicy\t\t= policy_match\n\n# For the CA policy\n[ policy_match ]\ncountryName\t\t= match\nstateOrProvinceName\t= match\norganizationName\t= match\norganizationalUnitName\t= optional"..., 4096) = 4096"#,
        );
        assert_eq!(
            res,
            Some(ReadParse::FinishedSuccessPartialBuffer {
                pid: String::from("1343641"),
                fd: String::from("3"),
            })
        );

        let res =
            STraceSysTraceCommand::parse_read(r#"1316971 read(3, "", 4096)               = 0"#);
        assert_eq!(
            res,
            Some(ReadParse::FinishedSuccess {
                pid: String::from("1316971"),
                fd: String::from("3"),
                data: Vec::from(b""),
                buffer_size: 4096,
                bytes_read: 0,
            })
        );

        let res = STraceSysTraceCommand::parse_read(
            r"1437466 read(17, 0x7fb0f00111d6, 122)   = -1 EAGAIN (Resource temporarily unavailable)",
        );
        assert_eq!(res, None);

        let res = STraceSysTraceCommand::parse_read(r"1435250 read(10,  <unfinished ...>");
        assert_eq!(
            res,
            Some(ReadParse::Unfinished {
                pid: String::from("1435250"),
                fd: String::from("10"),
            })
        );

        let res = STraceSysTraceCommand::parse_read_resumed(
            r"1435250 <... read resumed>0x5582bab4718c, 1140) = -1 EAGAIN (Resource temporarily unavailable)",
        );
        assert_eq!(
            res,
            Some(ReadParse::FinishedError {
                pid: String::from("1435250"),
            })
        );

        let res = STraceSysTraceCommand::parse_read_resumed(
            r"1924017 <... read resumed>0x7fffdb5c34b0, 46) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)",
        );
        assert_eq!(
            res,
            Some(ReadParse::FinishedError {
                pid: String::from("1924017"),
            })
        );

        let res = STraceSysTraceCommand::parse_read_resumed(
            r#"1435250 <... read resumed>"f6bf07ecc6bba4b4b5a0bae0aee00c08", 32) = 32"#,
        );
        assert_eq!(
            res,
            Some(ReadParse::FinishedPreviousSuccessfully {
                pid: String::from("1435250"),
                data: Vec::from(b"f6bf07ecc6bba4b4b5a0bae0aee00c08"),
                buffer_size: 32,
                bytes_read: 32,
            })
        );

        let res = STraceSysTraceCommand::parse_read_resumed(
            r#"1435250 <... read resumed>"{\"reason\":\"compiler-artifact\",\"package_id\":\"registry+https://github.com/rust-lang/crates.io-index#byteorder@1.5.0\",\"manifest_path\":\"/home/mfenniak/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/byteorder-1.5.0/Cargo.toml\",\"target\":{\"kind\":[\"lib\"],\"cr"..., 1140) = 792"#,
        );
        assert_eq!(
            res,
            Some(ReadParse::FinishedPreviousSuccessPartialBuffer {
                pid: String::from("1435250"),
            })
        );
    }

    #[test]
    fn sendto_read_trace_read() {
        // trace_raw contains an strace that was generated by running `curl https://www.google.com/` under an strace.
        //
        // Regenerating this file (if needed?) is done by...
        // - run: strace --follow-forks --trace=chdir,openat,clone,clone3,connect,sendto,close,read --string-limit=256
        //   --strings-in-hex=non-ascii-chars --output tests/test_data/strace-curl-nscd.txt curl https://www.google.com/
        let trace_raw = include_bytes!("../../tests/test_data/strace-curl-nscd.txt");

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok());

        let socket_captures = trace.get_socket_captures();

        let capture = &socket_captures[0];
        assert_eq!(
            capture.socket_addr,
            UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket"))
        );
        match &capture.state {
            SocketCaptureState::Complete(complete) => {
                assert_eq!(complete.len(), 1);
                assert_eq!(
                    &complete[0],
                    &SocketOperation::Sent(vec![
                        2, 0, 0, 0, 11, 0, 0, 0, 7, 0, 0, 0, 112, 97, 115, 115, 119, 100, 0
                    ])
                );
            }
            SocketCaptureState::Incomplete => {
                panic!("required state Complete, but was {:?}", capture.state);
            }
        }

        let capture = &socket_captures[1];
        assert_eq!(
            capture.socket_addr,
            UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket"))
        );
        match &capture.state {
            SocketCaptureState::Complete(complete) => {
                // FIXME: two read() operations are expected here once read support is added
                assert_eq!(complete.len(), 3);
                assert_eq!(
                    &complete[0],
                    &SocketOperation::Sent(vec![
                        2, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 49, 48, 48, 48, 0
                    ])
                );
                assert_eq!(
                    &complete[1],
                    &SocketOperation::Read(vec![
                        2, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 232, 3, 0, 0, 100, 0, 0, 0,
                        16, 0, 0, 0, 15, 0, 0, 0, 31, 0, 0, 0
                    ])
                );
                assert_eq!(
                    &complete[2],
                    &SocketOperation::Read(vec![
                        109, 102, 101, 110, 110, 105, 97, 107, 0, 120, 0, 77, 97, 116, 104, 105,
                        101, 117, 32, 70, 101, 110, 110, 105, 97, 107, 0, 47, 104, 111, 109, 101,
                        47, 109, 102, 101, 110, 110, 105, 97, 107, 0, 47, 114, 117, 110, 47, 99,
                        117, 114, 114, 101, 110, 116, 45, 115, 121, 115, 116, 101, 109, 47, 115,
                        119, 47, 98, 105, 110, 47, 122, 115, 104, 0
                    ])
                );
            }
            SocketCaptureState::Incomplete => {
                panic!("required state Complete, but was {:?}", capture.state);
            }
        }

        let capture = &socket_captures[5];
        assert_eq!(
            capture.socket_addr,
            UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from_str("2607:f8b0:400a:801::2003").unwrap(),
                443,
                0,
                0,
            ))),
        );
        assert_eq!(capture.state, SocketCaptureState::Incomplete);
    }
}
