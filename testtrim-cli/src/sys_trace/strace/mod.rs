// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context as _, Result, anyhow};
use funcs::{Function, FunctionTrace, OpenPath, StringArgument};
use log::{debug, error, trace};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use proc_synchronizer::ProcSynchronizer;
use shmem::{Receptionist, TraceClient};
use std::{
    collections::HashMap,
    env,
    fs::remove_file,
    os::fd::{FromRawFd as _, IntoRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::{Command as SyncCommand, Output},
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt as _, AsyncReadExt, AsyncWriteExt as _, BufReader, unix::AsyncFd},
    process::Command,
};

use crate::{errors::SubcommandErrors, sys_trace::trace::SocketCaptureState};

use super::{
    SysTraceCommand,
    trace::{DraftTrace, SocketCapture, SocketOperation, Trace},
};

mod funcs;
mod proc_synchronizer;
mod sequencer;
mod shmem;
mod tokenizer;

// These structs are to help differentiate `i32`'s with different meanings and avoid cross-use.  A `ThreadGroupId`
// matches the description in Linux documentation of a "thread group identifier", which is that all threads in the same
// process have the same thread group identifier; but each thread within the thread group will have a distinct process
// identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ThreadGroupId(i32);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProcessId(i32);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FileDescriptor(i32);

/// Implementation of `SysTraceCommand` that uses the `strace` command to trace all the relevant system calls.
pub struct STraceSysTraceCommand;

impl Default for STraceSysTraceCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl STraceSysTraceCommand {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    #[must_use]
    pub fn is_available() -> bool {
        let output = SyncCommand::new("strace").arg("--help").output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    async fn read_strace_output_from_reader(
        trace_path: PathBuf,
        receptionist_address: PathBuf,
    ) -> Result<Trace> {
        let receptionist = Receptionist::startup(receptionist_address)?;
        let file = File::open(&trace_path)
            .await
            .context(format!("failed to open strace output file {trace_path:?}"))?;
        let mut lines = BufReader::new(file).lines();
        let result = Self::read_strace_output(&mut lines, receptionist).await;
        if result.is_err() {
            // `trace_path` is presently going to be a fifo that strace is writing into.  If we encountered an error and
            // we stop reading from that fifo, then strace will be unable to write to it and might block and prevent the
            // completion of the process under trace.  To avoid that, in any exit condition, continue to read the file
            // to EOF.  (It's arguable that this responsibility is misplaced and should be done where the FIFO was
            // created, since this is unusual behavior for a method that just takes a path which could be a regular
            // file.  But we already have it open here.)
            //
            // If an error occurs in this read, we want to return the error from `result` because it occurred first, so
            // we'll just abort the loop on any error but not use `?` which would return with that error.
            while lines.next_line().await.is_ok_and(|line| line.is_some()) {}
        }
        result
    }

    async fn read_strace_output_from_trace_client(mut trace_client: TraceClient) -> Result<Trace> {
        // strace syscalls come either in a complete one-line, or in a "unfinished" and "resumed" line.  However, in the
        // case that we're picking up data from a `TraceClient`, we're going to be in a unique situation where the first
        // thing that child process does is resume the `read` syscall that is used on the parent/child pipe to
        // synchronize the processes.  This would normally cause an error because it is a resume without an "unfinished"
        // call to pair with it.  So, in order to avoid that error, before we start read_strace_output we're going to
        // pop that resumed syscall off the client.
        let first = trace_client.next_line().await?;
        match first {
            Some(first) => {
                // Expect to be one of these three, depending on exactly how the parent/child PIDs raced:
                //
                // - 40835 read(11,  <unfinished ...>
                // - 40835 <... read resumed>"\\x00", 1)      = 1
                // - 40835 read(11,  "\\x00", 1)      = 1
                //
                // But if it's "unfinished", then we're also going to need to consume the *second* line, because it will
                // contain the resumed line that we can't let go into the sequencer.
                if first.contains("read(") && first.contains("<unfinished") {
                    let second = trace_client.next_line().await?;
                    match second {
                        Some(second) if second.contains("read resumed") => {
                            // Great!
                        }
                        Some(second) => {
                            return Err(anyhow!(
                                "expected read resumed as second syscall line, but was: {second:?}"
                            ));
                        }
                        None => {
                            return Err(anyhow!(
                                "unexpected EOF from TraceClient on second response"
                            ));
                        }
                    }
                } else if first.contains("read(") || first.contains("read resumed") {
                    // Great!
                } else {
                    return Err(anyhow!(
                        "expected read resumed as first syscall; but was {first:?}"
                    ));
                }
            }
            None => {
                // Immediate EOF?
                return Err(anyhow!("unexpected EOF from TraceClient on first response"));
            }
        }

        let receptionist = NoopReceptionist {};
        let result = Self::read_strace_output(&mut trace_client, receptionist).await;
        if result.is_err() {
            // Similar to the logic in read_strace_output_from_reader -- if an error occurs in `read_strace_output`, and
            // we're reading trace data through the shared memory buffer, as a client if we don't continue reading that
            // data we might block the other side from writing and continuing its work.
            //
            // Dropping our client (or shutting it down) doesn't deregister it from the server -- that might be a better
            // way to handle this, but would add complexity by requiring bidirectional communication.
            //
            // If an error occurs in this read, we want to return the error from `result` because it occurred first, so
            // we'll just abort the loop on any error but not use `?` which would return with that error.
            while trace_client
                .next_line()
                .await
                .is_ok_and(|line| line.is_some())
            {}
        }
        trace_client.shutdown().await;
        result
    }

    async fn read_strace_output<Rd: LineReader, Rcpt: ReceptionistFacade>(
        reader: &mut Rd,
        receptionist: Rcpt,
    ) -> Result<Trace> {
        let mut trace = DraftTrace::new();
        let mut extractor = ProcSynchronizer::new();
        let mut pid_to_tgid: HashMap<ProcessId, ThreadGroupId> = HashMap::new();
        let mut tgid_cwd: HashMap<ThreadGroupId, PathBuf> = HashMap::new();
        let mut tgid_socket_fd_captures: HashMap<
            ThreadGroupId,
            HashMap<FileDescriptor, SocketCapture>,
        > = HashMap::new();
        let mut tgid_open_fd: HashMap<ThreadGroupId, HashMap<FileDescriptor, PathBuf>> =
            HashMap::new();

        let mut line_count = 0;
        while let Some(line) = reader.next_line().await? {
            line_count += 1;

            for function_extractor_output in extractor
                .extract(line)
                .context(format!("error parsing strace output line {line_count}"))?
            {
                // ProcSynchronizer may reorder syscalls for child processes -- in order to avoid sending an child's
                // syscall to the receptionist before we've sent the subprocess data to the receptionist, we need to
                // obey those reorderings (as opposed to doing peek_trace in the outer loop). This is a bit ugly since
                // it could involve multiple trace lines from the Sequencer, but here we extract whatever inputs were
                // used and pass them to the receptionist to peek them.
                let (line1, line2) = function_extractor_output
                    .borrow_sequencer_output()
                    .trace_lines();
                if let Some(line1) = line1 {
                    receptionist.peek_trace(line1.borrow_input()).await;
                }
                if let Some(line2) = line2 {
                    receptionist.peek_trace(line2.borrow_input()).await;
                }

                let Some(function_trace) = function_extractor_output.borrow_function_trace() else {
                    continue;
                };

                let (pid, function) = match function_trace {
                    FunctionTrace::Function { pid, function } => (*pid, function),
                    FunctionTrace::Exit { pid } => {
                        trace!("strace exit pid {pid:?}");
                        receptionist.remove_process(*pid);
                        continue;
                    }
                    FunctionTrace::ExitThreadGroup { pid } => {
                        // When a thread group exits, ensure that all the pids associated with it are cleaned up from
                        // the receptionist.  Technically we're missing other potentially useful cleanup here -- our
                        // other local hashmaps -- but the receptionist cleanup is the most important because it causes
                        // the EOF to be sent to the trace client and finish up its processes.
                        let pid = ProcessId(*pid);
                        let tgid = *pid_to_tgid
                            .entry(pid)
                            .or_insert_with(|| ThreadGroupId(pid.0));
                        trace!("strace exit thread group {tgid:?} {pid:?}");
                        for (other_pid, other_tgid) in &pid_to_tgid {
                            if *other_tgid == tgid {
                                receptionist.remove_process(other_pid.0);
                            }
                        }
                        continue;
                    }
                };
                let pid = ProcessId(pid);
                let tgid = pid_to_tgid
                    .entry(pid)
                    .or_insert_with(|| ThreadGroupId(pid.0));
                trace!("strace function: {tgid:?} {pid:?} {function:?}");

                match function {
                    Function::Openat {
                        path: open_path,
                        fd,
                    } => {
                        let accessed_path = match open_path {
                            OpenPath::RelativeToCwd(path_ref) => {
                                let mut path = path_ref.clone();
                                if let Some(cwd) = tgid_cwd.get(tgid) {
                                    path = cwd.join(path);
                                }
                                path
                            }
                            OpenPath::RelativeToOpenDirFD(path_ref, relative_fd) => {
                                let relative_fd = FileDescriptor(*relative_fd);
                                #[allow(clippy::single_match_else)]
                                match tgid_open_fd.entry(*tgid).or_default().get(&relative_fd) {
                                    Some(open_path) => open_path.join(path_ref),
                                    None => {
                                        // We're going to return an error indicating that the request to open relative
                                        // to `relative_fd` couldn't be handled because we don't know about the FD.  But
                                        // I'm not sure why this might happen, so, help diagnose a race condition in
                                        // output ordering by outputting recent and upcoming log lines:
                                        error!(
                                            "pid {pid:?} in tgid {tgid:?} accessed path {path_ref:?} relative to fd {relative_fd:?} which wasn't open"
                                        );
                                        error!("current known FDs is {tgid_open_fd:?}");
                                        let tgid = *tgid; // drop mutable borrow of pid_to_tgid
                                        error!("current known TGIDs is {pid_to_tgid:?}");
                                        return Err(anyhow!(
                                            "pid {pid:?} in tgid {tgid:?} accessed path {path_ref:?} relative to fd {relative_fd:?} which wasn't open"
                                        ));
                                    }
                                }
                            }
                        };
                        trace.add_open(accessed_path.clone());
                        tgid_open_fd
                            .entry(*tgid)
                            .or_default()
                            .insert(FileDescriptor(*fd), accessed_path);
                    }
                    Function::Chdir { path } => {
                        let default = PathBuf::from("");
                        let previous_path = tgid_cwd.get(tgid).unwrap_or(&default);
                        let new_path = previous_path.join(path);
                        tgid_cwd.insert(*tgid, new_path);
                    }
                    Function::Clone { child_pid, thread } => {
                        receptionist.add_subprocess(pid.0, *child_pid);
                        if *thread {
                            // Set the new `child_pid` to have the same `ThreadGroupId` as the spawning process.
                            let tgid = *tgid;
                            pid_to_tgid.insert(ProcessId(*child_pid), tgid);
                        } else {
                            // Inherit working directory for new subprocess.
                            if let Some(cwd) = tgid_cwd.get(tgid) {
                                tgid_cwd.insert(ThreadGroupId(*child_pid), (*cwd).clone());
                            }
                        }
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
                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        socket_fd_captures.insert(
                            FileDescriptor(*socket_fd),
                            SocketCapture {
                                socket_addr: socket_addr.clone(),
                                state: SocketCaptureState::Complete(Vec::new()),
                            },
                        );

                        // FIXME: in the near future we could probably remove add_connect and just use the SocketCapture
                        // data that is fed over to the trace when the socket is closed to extract all the connections.
                        trace.add_connect(socket_addr.clone());
                    }
                    Function::Sendto {
                        socket_fd,
                        data: StringArgument::Complete(data),
                    } => {
                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        let socket_capture =
                            socket_fd_captures.get_mut(&FileDescriptor(*socket_fd));
                        if let Some(socket_capture) = socket_capture {
                            if let SocketCaptureState::Complete(ref mut socket_operations) =
                                socket_capture.state
                            {
                                socket_operations
                                    .push(SocketOperation::Sent(data.decoded().clone()));
                            }
                            // (else, socket capture is already marked as Incomplete, no need to put any data into it)
                        }
                        // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                        // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                        // trace those, so we'll ignore any unrecognized sockets.
                    }
                    Function::Read {
                        fd,
                        data: StringArgument::Complete(data),
                    }
                    | Function::Recv {
                        socket_fd: fd,
                        data: StringArgument::Complete(data),
                    } => {
                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        let socket_capture = socket_fd_captures.get_mut(&FileDescriptor(*fd));
                        if let Some(socket_capture) = socket_capture {
                            if let SocketCaptureState::Complete(ref mut socket_operations) =
                                socket_capture.state
                            {
                                socket_operations
                                    .push(SocketOperation::Read(data.decoded().clone()));
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
                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        let in_progress = socket_fd_captures.get_mut(&FileDescriptor(*fd));
                        if let Some(in_progress) = in_progress {
                            in_progress.state = SocketCaptureState::Incomplete;
                        }
                        // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                        // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                        // trace those, so we'll ignore any unrecognized sockets.
                    }
                    Function::Close { fd } => {
                        tgid_open_fd
                            .entry(*tgid)
                            .or_default()
                            .remove(&FileDescriptor(*fd));

                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        let socket_capture = socket_fd_captures.remove(&FileDescriptor(*fd));
                        if let Some(socket_capture) = socket_capture {
                            trace.add_socket_capture(socket_capture);
                        }
                        // No else case for warning if no socket present -- close(n) is used for file FDs which we're not
                        // capturing, so it will be common and normal for (pid, fd) to not be present.
                    }
                    // Nothing to do with execve.
                    Function::Execve { .. } |
                    // ThreadSignal was once useful as a diagnostic, but currently is unhandled.
                    Function::ThreadSignal { .. } => {}
                }
            }
        }

        receptionist.shutdown().await;

        trace.try_into()
    }

    async fn trace_command_w_strace(
        &self,
        orig_cmd: Command,
        trace_path: &Path,
    ) -> Result<(Output, Trace)> {
        // We create a named-pipe for strace to write to, and start a tokio Task to begin reading from it and generating
        // our `Trace` object as data streams in.
        let _fifo = Fifo::create(trace_path);

        let receptionist_address = Receptionist::get_receptionist_address(trace_path);
        let pipe_reader = tokio::task::spawn(Self::read_strace_output_from_reader(
            trace_path.into(),
            receptionist_address.clone(),
        ));

        let mut new_cmd = Command::new("strace");
        new_cmd
            .env("__TESTTRIM_STRACE", receptionist_address)
            .arg("--follow-forks")
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

        let trace = pipe_reader.await??;

        Ok((output, trace))
    }

    fn pidfd_open(pid: nix::libc::pid_t) -> Result<OwnedFd> {
        let retval = unsafe {
            nix::libc::c_int::try_from(nix::libc::syscall(
                nix::libc::SYS_pidfd_open,
                pid,
                nix::libc::PIDFD_NONBLOCK,
            ))?
        };
        if retval == -1 {
            Err(anyhow!("pidfd_open fail"))
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(retval) })
        }
    }

    async fn trace_command_remotely(
        &self,
        orig_cmd: Command,
        receptionist_address: PathBuf,
    ) -> Result<(Output, Trace)> {
        // In this case we want to read our trace from the the out-of-process testtrim at receptionist_address.  In
        // order to do this without missing any events, we need to:
        // - fork this process
        // - in child, wait
        // - in the parent, connect to the receptionist and subscribe to the pid of the child, then release the child
        // - in the child, execve replacing ourselves with the `orig_cmd`
        // - in the parent, process the strace data, stdout/stderr, and exit code of the child.

        use nix::sys::wait::WaitStatus;
        use nix::unistd::{ForkResult, fork, pipe};
        use std::fs::File;
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        let (read_goahead_fd, write_goahead_fd) = pipe()?;
        let (stdout_read_fd, stdout_write_fd) = pipe()?;
        let (stderr_read_fd, stderr_write_fd) = pipe()?;

        match unsafe { fork()? } {
            ForkResult::Parent { child } => {
                debug!("trace_command_remotely spawned child {child:?}");
                let child = OwnedChildPid::from(child);

                drop(read_goahead_fd);
                drop(stdout_write_fd);
                drop(stderr_write_fd);

                // Subscribe to the syscall tracing of the child pid through TraceClient...
                let trace_client =
                    TraceClient::try_create(&receptionist_address, child.as_raw()).await?;
                let trace_reader =
                    tokio::task::spawn(Self::read_strace_output_from_trace_client(trace_client));

                // Now we can let the child know to move forward.
                let buf = [0u8; 1];
                let mut write_file = tokio::fs::File::from(File::from(write_goahead_fd));
                write_file.write_all(&buf).await?;
                drop(write_file);

                // Spawn tasks to read stdout & stderr; this should minimize the risk of any deadlocks between the
                // process finishing and pipes being writeable/full as they'll be flushed to the Vec's continually.
                let mut stdout_read_file =
                    unsafe { tokio::fs::File::from_raw_fd(stdout_read_fd.into_raw_fd()) };
                let mut stderr_read_file =
                    unsafe { tokio::fs::File::from_raw_fd(stderr_read_fd.into_raw_fd()) };
                let stdout_join = tokio::spawn(async move {
                    let mut stdout: Vec<u8> = Vec::with_capacity(4096);
                    stdout_read_file.read_to_end(&mut stdout).await?;
                    Ok::<_, anyhow::Error>(stdout)
                });
                let stderr_join = tokio::spawn(async move {
                    let mut stderr: Vec<u8> = Vec::with_capacity(4096);
                    stderr_read_file.read_to_end(&mut stderr).await?;
                    Ok::<_, anyhow::Error>(stderr)
                });

                // Create a pidfd that we can use with tokio to wait for the child process.
                let pidfd = Self::pidfd_open(child.as_raw())?;
                let pidfd = AsyncFd::new(pidfd)?;
                // AsyncFdReadyGuard is dropped without a care; we never read from this fd, just use it to identify if
                // the child pid is ready for a wait that won't block.
                let _ = pidfd.readable().await?;
                debug!("trace_command_remotely found pidfd readable");

                // This should be non-blocking because we only exited the loop above when the pidfd became readable.
                let wait_status = waitpid(child.take(), None)?;
                let WaitStatus::Exited(_, exit_code) = wait_status else {
                    return Err(anyhow!(
                        "expected WaitStatus::Exited, but was: {wait_status:?}"
                    ));
                };
                debug!("trace_command_remotely found child exit code: {exit_code:?}");

                // Finish collecting any output data
                let stdout = stdout_join.await??;
                let stderr = stderr_join.await??;

                debug!("completed subprocess!  exit_code = {exit_code:?}");
                let output = Output {
                    status: ExitStatus::from_raw(exit_code),
                    stdout,
                    stderr,
                };

                let trace = trace_reader.await??;

                Ok((output, trace))
            }
            ForkResult::Child => {
                // I don't think it's safe to use tokio/async in the Child branch... there should be no active tokio
                // runtime and everything should be blocking.  Hopefully!
                //
                // It's also important that this branch never return -- which means never using `?` operators.  If
                // something fails, we can panic so that the parent process notes our termination.

                // Wait until the parent has subscribed upstream to our process.  This should be the first syscall in
                // the child process because it will wait until the parent process has subscribed to the strace stream,
                // and, there's special handling in read_strace_output_from_trace_client for this syscall since the
                // trace may be incomplete.  syscalls following this don't require any special behavior.
                //
                // If the parent process failed to startup its trace client, we may wait here indefinitely.  In that
                // event, we're relying on the OwnedPid object in the parent to SIGTERM us when dropped.
                let mut buf = [0u8; 1];
                let mut read_file = File::from(read_goahead_fd);
                read_file.read_exact(&mut buf).expect("pipe read_exact()");
                drop(read_file);

                // Connect stdout, stderr to the pipes
                nix::unistd::close(0).expect("close(0)"); // stdin
                nix::unistd::dup2(&stdout_write_fd, &mut unsafe { OwnedFd::from_raw_fd(1) })
                    .expect("dup2(1)"); // stdout
                nix::unistd::dup2(&stderr_write_fd, &mut unsafe { OwnedFd::from_raw_fd(2) })
                    .expect("dup2(2)"); // stderr

                // Drop all the unused pipe ends.
                drop(write_goahead_fd);
                drop(stdout_read_fd);
                drop(stderr_read_fd);
                drop(stdout_write_fd); // because dup2'd into stdout already
                drop(stderr_write_fd); // because dup2'd into stderr already

                // Execute the target commend, replacing this child process.
                let exec_err = orig_cmd.into_std().exec();
                // We won't reach here.
                panic!("error in exec: {exec_err:?}");
            }
        }
    }
}

impl SysTraceCommand for STraceSysTraceCommand {
    async fn trace_command(&self, orig_cmd: Command, tmp: &Path) -> Result<(Output, Trace)> {
        match env::var("__TESTTRIM_STRACE") {
            Ok(ref receptionist_address) => {
                debug!(
                    "__TESTTRIM_STRACE is set to {receptionist_address:?}; beginning trace_command_remotely"
                );
                self.trace_command_remotely(orig_cmd, PathBuf::from(receptionist_address))
                    .await
            }
            Err(_) => self.trace_command_w_strace(orig_cmd, tmp).await,
        }
    }
}

struct Fifo(PathBuf);

impl Fifo {
    fn create(trace_path: &Path) -> Result<Self> {
        nix::unistd::mkfifo(
            trace_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )?;
        Ok(Self(trace_path.into()))
    }
}

impl Drop for Fifo {
    fn drop(&mut self) {
        remove_file(&self.0).expect("unable to cleanup FIFO");
    }
}

/// `OwnedChildPid` can be used to prevent zombie child process.  It guarantees that the child is `waitpid()`'d.
struct OwnedChildPid(Option<i32>);

impl OwnedChildPid {
    fn as_raw(&self) -> i32 {
        // Safety: will be Some(_) unless dropped or taken, which would prevent access here.
        self.0.unwrap()
    }

    fn take(mut self) -> Pid {
        // Safety: will be Some(_) unless dropped, not possible here.
        Pid::from_raw(self.0.take().unwrap())
    }
}

impl From<Pid> for OwnedChildPid {
    fn from(value: Pid) -> Self {
        OwnedChildPid(Some(value.as_raw()))
    }
}

impl Drop for OwnedChildPid {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            tokio::task::spawn_blocking(move || {
                let pid = Pid::from_raw(pid);
                let _ = kill(pid, Signal::SIGTERM); // Ignore error -- we're doing our best here.
                // Wait up to 5 seconds for graceful termination
                let start = std::time::Instant::now();
                loop {
                    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                        Ok(_) => return, // Child exited
                        Err(_) => {
                            if start.elapsed() >= std::time::Duration::from_secs(5) {
                                // Timeout reached, send SIGKILL
                                let _ = kill(pid, Signal::SIGKILL);
                                let _ = waitpid(pid, None);
                                return;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }
            });
        }
    }
}

trait ReceptionistFacade {
    async fn peek_trace(&self, trace_line: &str);
    fn add_subprocess(&self, parent_pid: i32, child_pid: i32);
    fn remove_process(&self, pid: i32);
    async fn shutdown(self);
}

struct NoopReceptionist {}

impl ReceptionistFacade for NoopReceptionist {
    async fn peek_trace(&self, _trace_line: &str) {}
    fn add_subprocess(&self, _parent_pid: i32, _child_pid: i32) {}
    fn remove_process(&self, _pid: i32) {}
    async fn shutdown(self) {}
}

trait LineReader {
    async fn next_line(&mut self) -> Result<Option<String>>;
}

impl LineReader for tokio::io::Lines<BufReader<File>> {
    async fn next_line(&mut self) -> Result<Option<String>> {
        Ok(self.next_line().await?)
    }
}

impl LineReader for TraceClient {
    async fn next_line(&mut self) -> Result<Option<String>> {
        let line = self.next_line().await?;
        Ok(line)
    }
}
