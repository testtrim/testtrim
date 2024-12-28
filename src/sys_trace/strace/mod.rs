// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context as _, Result};
use funcs::{Function, FunctionExtractor, FunctionTrace, OpenPath, StringArgument};
use log::{info, warn};
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{read_dir, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command as SyncCommand, Output, Stdio},
    str::FromStr as _,
};
use tokio::process::Command;

use crate::{errors::SubcommandErrors, sys_trace::trace::SocketCaptureState};

use super::{
    trace::{DraftTrace, SocketCapture, SocketOperation, Trace},
    SysTraceCommand,
};

mod funcs;
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

    // Reading a trace has two modes, and one common function.
    //
    // Common: read_trace_file -- reads a specific trace file, updates a Trace object, returns child pids that were
    // spawned from that.
    //
    // Mode 1: read_all_pid_trace_files: For when testtrim started `strace --follow-forks
    // --output-separately=.../abc.strace`, the goal will be to read all the trace files that match `.../abc.strace.*`
    // (eg. all the subprocesses from the strace).  However it is necessary that they be read from the first process in
    // order to track the inherited current workdir for each child process.  In order to accomplish this, the process
    // files are read in PID order, and the first line is checked for execve -- the earliest process with an arg0 that
    // matches the command executed under strace will be identified as the root process, and then the rest will proceed
    // the same as mode 2.
    //
    // Mode 2: read_child_pid_trace_files: For when testtrim itself is running under strace already and we're trying to
    // spawn a child process for tracing.  It will be given a root and a specific process id, read
    // `.../abc.strace.{pid}` and update a Trace.  But then for all child processes that were spawned by that pid, it
    // will also read their trace.
    //
    // Mode 1 and Mode 2 seems like they could be the same codebase, but we don't know the pid of the first child when
    // we launch strace ourselves (just the pid of strace).

    fn read_all_pid_trace_files(
        trace: &mut DraftTrace,
        trace_file_root: &Path,
        cmdpath: &Path,
    ) -> Result<()> {
        let parent = trace_file_root.parent().unwrap();
        let trace_file_name = trace_file_root.file_name().unwrap();
        let trace_file_name = &*trace_file_name.to_string_lossy();

        let mut pid_and_file = vec![];

        for entry in read_dir(parent)? {
            let entry = entry?;
            let orig_filename = entry.file_name();
            let filename = orig_filename.to_string_lossy();
            if let Some(suffix) = filename.strip_prefix(trace_file_name) {
                // suffix will be "." followed by the pid.
                let pid = u32::from_str(&suffix[1..])?;
                pid_and_file.push((pid, entry.path()));
            }
        }

        pid_and_file.sort_by_key(|t| t.0);

        for (pid, filename) in pid_and_file {
            let mut extractor = FunctionExtractor::new();
            let file = File::open(&filename)
                .context(format!("failed to open strace output file {filename:?}"))?;
            let mut lines = BufReader::new(file).lines();
            let first_line = lines.next();
            let Some(first_line) = first_line else {
                continue;
            };
            let first_line = first_line?;
            let Some(first_line) = extractor.extract(&first_line).context(format!(
                "error parsing strace output first line: {first_line}"
            ))?
            else {
                continue;
            };
            let FunctionTrace::Function(function) = first_line else {
                continue;
            };
            let Function::Execve { arg0 } = function else {
                continue;
            };

            // Alright, this file has an execve on the first line...
            if arg0 == cmdpath {
                // And it's the program we ran.  Let's do the trace here.
                Self::read_child_pid_trace_files(trace, trace_file_root, pid, None)?;
                return Ok(());
            }
        }

        Err(anyhow!(
            "read_all_pid_trace_files: no strace output files were found"
        ))
    }

    fn read_child_pid_trace_files(
        trace: &mut DraftTrace,
        trace_file_root: &Path,
        trace_pid: u32,
        cwd: Option<PathBuf>,
    ) -> Result<()> {
        let file_path = trace_file_root.with_added_extension(trace_pid.to_string());
        for (child, inherited_cwd) in Self::read_trace_file(trace, &file_path, cwd)? {
            Self::read_child_pid_trace_files(trace, trace_file_root, child, inherited_cwd)?;
        }
        Ok(())
    }

    fn read_trace_file(
        trace: &mut DraftTrace,
        trace_file: &Path,
        mut cwd: Option<PathBuf>,
    ) -> Result<HashSet<(u32, Option<PathBuf>)>> {
        let file = File::open(trace_file)
            .context(format!("failed to open strace output file {trace_file:?}"))?;
        // FIXME: this assumes that the contents of the trace are UTF-8; this probably isn't right
        let lines = BufReader::new(file).lines();

        let mut child_pids: HashSet<(u32, Option<PathBuf>)> = HashSet::new();
        let mut pid_socket_fd_captures: HashMap<String, SocketCapture> = HashMap::new();

        let mut extractor = FunctionExtractor::new();

        let mut line_count = 0;
        for line in lines {
            let line = line?;
            line_count += 1;

            let Some(function_trace) = extractor.extract(&line).context(format!(
                "error parsing strace output line {line_count}: {line}"
            ))?
            else {
                continue;
            };

            if let FunctionTrace::Exit = function_trace {
                continue;
            }
            let FunctionTrace::Function(function) = function_trace else {
                // basically a match but keeping `function` in scope for remainder...
                unreachable!()
            };

            match function {
                Function::Openat { path: open_path } => {
                    if let OpenPath::RelativeToCwd(mut path) = open_path {
                        if let Some(ref cwd) = cwd {
                            path = cwd.join(path);
                        }
                        trace.add_open(path);
                    } else {
                        warn!("open path {:?} not yet supported for strace", open_path);
                    }
                }
                Function::Chdir { path } => {
                    let previous_path = cwd.unwrap_or(PathBuf::from(""));
                    let new_path = previous_path.join(path);
                    cwd = Some(new_path);
                }
                Function::Clone { child_pid } => {
                    // Inherit working directory
                    child_pids.insert((child_pid, cwd.clone()));
                }
                Function::Connect {
                    socket_fd,
                    socket_addr,
                } => {
                    // Insert a new SocketCaptureState into pid_socket_in_progress by the pid & socket_fd.  Because we
                    // don't parse connect in a very precise way -- eg. handling unfinished and errors -- it's possible
                    // that pid_socket_fd_captures could already contain the same pid & socket.  In that case this will
                    // be a reinitialization which should be fine; the expected case is we're just finished an
                    // incomplete or non-blocking connect.
                    pid_socket_fd_captures.insert(
                        socket_fd.to_owned(),
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
                    socket_fd,
                    data: StringArgument::Complete(mut data),
                } => {
                    let socket_capture = pid_socket_fd_captures.get_mut(socket_fd);
                    if let Some(socket_capture) = socket_capture {
                        if let SocketCaptureState::Complete(ref mut socket_operations) =
                            socket_capture.state
                        {
                            socket_operations.push(SocketOperation::Sent(data.take()));
                        }
                        // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                Function::Read {
                    fd,
                    data: StringArgument::Complete(mut data),
                }
                | Function::Recv {
                    socket_fd: fd,
                    data: StringArgument::Complete(mut data),
                } => {
                    let socket_capture = pid_socket_fd_captures.get_mut(fd);
                    if let Some(socket_capture) = socket_capture {
                        if let SocketCaptureState::Complete(ref mut socket_operations) =
                            socket_capture.state
                        {
                            socket_operations.push(SocketOperation::Read(data.take()));
                        }
                        // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                Function::Sendto {
                    socket_fd: fd,
                    data: StringArgument::Partial,
                }
                | Function::Read {
                    fd,
                    data: StringArgument::Partial,
                }
                | Function::Recv {
                    socket_fd: fd,
                    data: StringArgument::Partial,
                } => {
                    // "Corrupt" this stream as strace didn't receive all the data necessary to recreate it.
                    let in_progress = pid_socket_fd_captures.get_mut(fd);
                    if let Some(in_progress) = in_progress {
                        in_progress.state = SocketCaptureState::Incomplete;
                    }
                    // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                    // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                    // trace those, so we'll ignore any unrecognized sockets.
                }
                Function::Close { fd } => {
                    let socket_capture = pid_socket_fd_captures.remove(fd);
                    if let Some(socket_capture) = socket_capture {
                        trace.add_socket_capture(socket_capture);
                    }
                    // No else case for warning if no socket present -- close(n) is used for file FDs which we're not
                    // capturing, so it will be common and normal for (pid, fd) to not be present.
                }
                // Nothing to do with execve.
                Function::Execve { .. } => {}
            }
        }

        Ok(child_pids)
    }

    async fn trace_command_w_strace(
        &self,
        orig_cmd: Command,
        trace_path: &Path,
    ) -> Result<(Output, Trace)> {
        let mut new_cmd = Command::new("strace");
        new_cmd
            .env("__TESTTRIM_STRACE", trace_path)
            .arg("--follow-forks")
            .arg("--output-separately")
            // %process will guarantee that we get all process lifecycle syscalls, which helps guarentee that the
            // pid-filtering capability for sub-strace doesn't miss any subprocesses
            .arg("--trace=chdir,openat,clone,clone3,connect,sendto,close,read,recvfrom,%process")
            // 512 bytes should be sufficient for most DNS.  testtrim's integration tests are showing we're exceeding
            // this buffer at times, but until https://codeberg.org/testtrim/testtrim/issues/217 is fixed I'm not
            // confident that's really true -- a FD could be opened to a DNS server, closed on another thread, and then
            // reopened to another socket causing a false-positive.
            .arg("--string-limit=512")
            .arg("--strings-in-hex=non-ascii-chars")
            .arg("--output")
            .arg(trace_path);

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
            if let Err(e) = Self::read_all_pid_trace_files(
                &mut trace,
                trace_path,
                orig_cmd.as_std().get_program().as_ref(),
            ) {
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

    async fn trace_command_w_existing_file(
        &self,
        mut orig_cmd: Command,
        parent_strace_path: &Path,
    ) -> Result<(Output, Trace)> {
        let child = orig_cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| SubcommandErrors::UnableToStart {
                command: format!("{:?} ...", orig_cmd.as_std().get_program()).to_string(),
                error: e,
            })?;

        let Some(subprocess_id) = child.id() else {
            return Err(anyhow!("subprocess had no process id after spawn()"));
        };
        info!(
            "trace_command_w_existing_file: subprocess: {:?}",
            child.id()
        );

        let output = child.wait_with_output().await?;

        let mut trace = DraftTrace::new();
        if output.status.success() {
            Self::read_child_pid_trace_files(&mut trace, parent_strace_path, subprocess_id, None)?;
        }

        Ok((output, trace.try_into()?))
    }
}

impl SysTraceCommand for STraceSysTraceCommand {
    async fn trace_command(&self, orig_cmd: Command, tmp: &Path) -> Result<(Output, Trace)> {
        match env::var("__TESTTRIM_STRACE") {
            Ok(ref trace_path) => {
                self.trace_command_w_existing_file(orig_cmd, Path::new(trace_path))
                    .await
            }
            Err(_) => self.trace_command_w_strace(orig_cmd, tmp).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        net::{Ipv4Addr, SocketAddrV4},
        path::{Path, PathBuf},
    };

    use crate::sys_trace::{
        strace::STraceSysTraceCommand,
        trace::{DraftTrace, ResolvedSocketAddr, Trace, UnifiedSocketAddr},
    };

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
        // ```
        // rm tests/test_data/strace-multiproc-chdir.strace.*
        // strace --follow-forks --output-separately \
        // --trace=chdir,openat,clone,clone3,connect,sendto,close,read,recvfrom,%process \
        // --string-limit=512 --strings-in-hex=non-ascii-chars \
        // --output tests/test_data/strace-multiproc-chdir.strace python scripts/generate-strace-multiproc-chdir.py
        // ```

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_all_pid_trace_files(
            &mut trace,
            Path::new("tests/test_data/strace-multiproc-chdir.strace"),
            Path::new("/nix/store/zv1kaq7f1q20x62kbjv6pfjygw5jmwl6-python3-3.12.7/bin/python"),
        );
        assert!(res.is_ok(), "expected ok, was: {res:?}");

        let trace: Trace = trace.try_into().expect("DraftTrace -> Trace");

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
        // trace_raw contains an strace that was generated by running `curl https://www.google.ca/` under an strace.
        //
        // Regenerating this file (if needed?) is done by...
        // ```
        // rm tests/test_data/tests/test_data/strace-curl-google-without-nscd.strace.*
        // strace --follow-forks --output-separately \
        // --trace=chdir,openat,clone,clone3,connect,sendto,close,read,recvfrom,%process \
        // --string-limit=512 --strings-in-hex=non-ascii-chars \
        // --output tests/test_data/strace-curl-google-without-nscd.strace curl https://www.google.ca/
        // ```

        let mut trace = DraftTrace::new();

        let res = STraceSysTraceCommand::read_all_pid_trace_files(
            &mut trace,
            Path::new("tests/test_data/strace-curl-google-without-nscd.strace"),
            Path::new("/run/current-system/sw/bin/curl"),
        );
        assert!(res.is_ok(), "expected OK, was {res:?}");

        let trace: Trace = trace.try_into().expect("DraftTrace -> Trace");

        let sockets = trace.get_connect_sockets();

        assert!(sockets.contains(&ResolvedSocketAddr {
            address: UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket")),
            hostnames: BTreeSet::from([]),
        }));

        println!("sockets: {sockets:?}");
        assert!(sockets.contains(&ResolvedSocketAddr {
            address: UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(142, 250, 217, 67),
                443
            ))),
            hostnames: BTreeSet::from([String::from("www.google.ca")]),
        }));
    }
}
