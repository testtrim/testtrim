// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context as _, Result};
use funcs::{Function, FunctionExtractor, OpenPath, StringArgument};
use log::warn;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command as SyncCommand, Output},
};
use tokio::process::Command;

use crate::{errors::SubcommandErrors, sys_trace::trace::SocketCaptureState};

use super::{
    trace::{DraftTrace, SocketCapture, SocketOperation, Trace},
    SysTraceCommand,
};

mod funcs;
mod sequencer;
mod tokenizer;

/// Implementation of `SysTraceCommand` that uses the `strace` command to trace all the relevant system calls.
pub struct STraceSysTraceCommand;

impl STraceSysTraceCommand {
    pub fn new() -> Self {
        Self {}
    }

    pub fn is_available() -> bool {
        let output = SyncCommand::new("strace").arg("--help").output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    fn read_trace_file(trace: &mut DraftTrace, trace_file: &Path) -> Result<()> {
        let file = File::open(trace_file)?;
        Self::read_trace(trace, BufReader::new(file))
    }

    fn read_trace<T: Read>(trace: &mut DraftTrace, read: T) -> Result<()> {
        // FIXME: this assumes that the contents of the trace are UTF-8; this probably isn't right
        let lines = BufReader::new(read).lines();

        let mut pid_cwd: HashMap<String, PathBuf> = HashMap::new();
        let mut pid_socket_fd_captures: HashMap<(String, String), SocketCapture> = HashMap::new();

        let mut extractor = FunctionExtractor::new();

        let mut line_count = 0;
        for line in lines {
            let line = line?;
            line_count += 1;

            // Hack for test data files which contain some copyright headers (arguably stupid)
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            let Some(function) = extractor.extract(&line).context(format!(
                "error parsing strace output line {line_count}: {line}"
            ))?
            else {
                continue;
            };

            match function {
                Function::Openat {
                    pid,
                    path: open_path,
                } => {
                    if let OpenPath::RelativeToCwd(mut path) = open_path {
                        if let Some(cwd) = pid_cwd.get(&pid) {
                            path = cwd.join(path);
                        }
                        trace.add_open(path);
                    } else {
                        warn!("open path {:?} not yet supported for strace", open_path);
                    }
                }
                Function::Chdir { pid, path } => {
                    let previous_path = pid_cwd.remove(&pid).unwrap_or(PathBuf::from(""));
                    let new_path = previous_path.join(path);
                    pid_cwd.insert(pid, new_path);
                }
                Function::Clone {
                    parent_pid,
                    child_pid,
                } => {
                    // Inherit working directory
                    if let Some(cwd) = pid_cwd.get(&parent_pid) {
                        pid_cwd.insert(child_pid, cwd.clone());
                    }
                }
                Function::Connect {
                    pid,
                    socket_fd,
                    socket_addr,
                } => {
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
                Function::Sendto {
                    pid,
                    socket_fd,
                    data: StringArgument::Complete(data),
                } => {
                    let socket_capture =
                        pid_socket_fd_captures.get_mut(&(pid.clone(), socket_fd.clone()));
                    if let Some(socket_capture) = socket_capture {
                        if let SocketCaptureState::Complete(ref mut socket_operations) =
                            socket_capture.state
                        {
                            socket_operations.push(SocketOperation::Sent(data));
                        }
                        // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                Function::Read {
                    pid,
                    fd,
                    data: StringArgument::Complete(data),
                } => {
                    let socket_capture = pid_socket_fd_captures.get_mut(&(pid.clone(), fd.clone()));
                    if let Some(socket_capture) = socket_capture {
                        if let SocketCaptureState::Complete(ref mut socket_operations) =
                            socket_capture.state
                        {
                            socket_operations.push(SocketOperation::Read(data));
                        }
                        // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                Function::Sendto {
                    pid,
                    socket_fd: fd,
                    data: StringArgument::Partial,
                }
                | Function::Read {
                    pid,
                    fd,
                    data: StringArgument::Partial,
                } => {
                    // "Corrupt" this stream as strace didn't receive all the data necessary to recreate it.
                    let in_progress = pid_socket_fd_captures.get_mut(&(pid.clone(), fd.clone()));
                    if let Some(in_progress) = in_progress {
                        in_progress.state = SocketCaptureState::Incomplete;
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                Function::Close { pid, fd } => {
                    let socket_capture = pid_socket_fd_captures.remove(&(pid, fd));
                    if let Some(socket_capture) = socket_capture {
                        trace.add_socket_capture(socket_capture);
                    }
                    // No else case for warning if no socket present -- close(n) is used for file FDs which we're not
                    // capturing, so it will be common and normal for (pid, fd) to not be present.
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
            #[allow(clippy::question_mark)]
            if let Err(e) = Self::read_trace_file(&mut trace, tmp) {
                // Occasionally useful for debugging to keep a copy of all the strace output...
                // std::fs::copy(
                //     tmp,
                //     Path::new("/home/mfenniak/Dev/testtrim/broken-trace.txt"),
                // )?;
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
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        str::FromStr as _,
    };

    use crate::sys_trace::trace::UnifiedSocketAddr;

    use super::*;

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
        let trace_raw = include_bytes!("../../../tests/test_data/strace-multiproc-chdir.txt");

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok(), "expected ok, was: {res:?}");

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
        let trace_raw = include_bytes!("../../../tests/test_data/strace-connect.txt");

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok(), "expected OK, was {res:?}");

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
    fn sendto_read_trace_read() {
        // trace_raw contains an strace that was generated by running `curl https://www.google.com/` under an strace.
        //
        // Regenerating this file (if needed?) is done by...
        // - run: strace --follow-forks --trace=chdir,openat,clone,clone3,connect,sendto,close,read --string-limit=256
        //   --strings-in-hex=non-ascii-chars --output tests/test_data/strace-curl-nscd.txt curl https://www.google.com/
        let trace_raw = include_bytes!("../../../tests/test_data/strace-curl-nscd.txt");

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok(), "expected ok, was: {res:?}");

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
