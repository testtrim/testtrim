// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
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

use crate::errors::SubcommandErrors;

use super::{
    trace::{Trace, UnifiedSocketAddr},
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
    IndeterminateResult { socket_addr: UnifiedSocketAddr },
}

#[derive(Debug, PartialEq)]
enum ParseLine {
    Open(OpenParse),
    Chdir(ChdirParse),
    Clone(CloneParse),
    Connect(ConnectParse),
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
                Some(UnifiedSocketAddr::Unix(
                    std::os::unix::net::SocketAddr::from_pathname(unix_path.as_str()).unwrap(),
                ))
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

            socket_addr.map(|s| ConnectParse::IndeterminateResult { socket_addr: s })
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
        None
    }

    fn read_trace_file(trace: &mut Trace, trace_file: &Path) -> Result<()> {
        let file = File::open(trace_file)?;
        Self::read_trace(trace, BufReader::new(file))
    }

    fn read_trace<T: Read>(trace: &mut Trace, read: T) -> Result<()> {
        // FIXME: this assumes that the contents of the trace are UTF-8; this probably isn't right
        let lines = BufReader::new(read).lines();

        let mut pid_openat_in_progress: HashMap<String, OpenPath> = HashMap::new();
        let mut pid_cwd: HashMap<String, PathBuf> = HashMap::new();
        let mut pid_cwd_in_progress: HashMap<String, PathBuf> = HashMap::new();

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
                    assert!(
                        prev.is_none(),
                        "pid_openat_in_progress shouldn't be in-progress multiple times"
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
                    assert!(
                        prev.is_none(),
                        "pid_cwd_in_progress shouldn't be in-progress multiple times"
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

                ParseLine::Connect(ConnectParse::IndeterminateResult { socket_addr }) => {
                    trace.add_connect(socket_addr);
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
            .arg("--trace=chdir,openat,clone,clone3,connect")
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
        let mut trace = Trace::new();

        if output.status.success() {
            if let Err(e) = Self::read_trace_file(&mut trace, tmp) {
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

        Ok((output, trace))
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
                socket_addr: UnifiedSocketAddr::Unix(
                    std::os::unix::net::SocketAddr::from_pathname("/var/run/nscd/socket").unwrap(),
                ),
            })
        );

        let res = STraceSysTraceCommand::parse_connect(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        );
        assert_eq!(
            res,
            Some(ConnectParse::IndeterminateResult {
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

        let mut trace = Trace::new();

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

        let mut trace = Trace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok());

        let sockets = trace.get_connect_sockets();

        assert!(sockets.contains(&UnifiedSocketAddr::Unix(
            std::os::unix::net::SocketAddr::from_pathname("/var/run/nscd/socket").unwrap(),
        )));

        assert!(
            sockets.contains(&UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::new(142, 250, 217, 100), 443)
            )))
        );

        // assert!(paths.contains(&PathBuf::from("flake.nix")));
        // assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/testtrim/README.md")));
        // assert!(paths.contains(&PathBuf::from(
        //     "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
        // )));
        // assert!(paths.contains(&PathBuf::from("/home/mfenniak/.zsh_history")));
        // assert!(paths.contains(&PathBuf::from(
        //     "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
        // )));

        // // test.txt is accessed in an unusual way compared to above cases; one process chdir's into /home/mfenniak/Dev,
        // // and then starts a subprocess which inherits that directory, and then accesses "test.txt".  So if this test
        // // case is failing, it's the inheritence of the cwd from parent processes that is to blame (probably).
        // assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/test.txt")));
    }
}
