// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context as _, Result, anyhow};
use funcs::{Function, FunctionTrace, OpenPath, StringArgument};
use log::{debug, trace, warn};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use proc_synchronizer::ProcSynchronizer;
use shmem::{Receptionist, TraceClient};
use std::{
    collections::HashMap,
    env,
    fs::remove_file,
    os::fd::{AsRawFd, FromRawFd as _, IntoRawFd, OwnedFd},
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
        Self::read_strace_output(&mut lines, receptionist).await
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
        let trace = Self::read_strace_output(&mut trace_client, receptionist).await?;
        trace_client.shutdown().await;
        Ok(trace)
    }

    async fn read_strace_output<Rd: LineReader, Rcpt: ReceptionistFacade>(
        reader: &mut Rd,
        receptionist: Rcpt,
    ) -> Result<Trace> {
        let mut trace = DraftTrace::new();
        let mut extractor = ProcSynchronizer::new();
        let mut pid_to_tgid: HashMap<ProcessId, ThreadGroupId> = HashMap::new();
        let mut tgid_cwd: HashMap<ThreadGroupId, PathBuf> = HashMap::new();
        let mut tgid_socket_fd_captures: HashMap<ThreadGroupId, HashMap<String, SocketCapture>> =
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
                    Function::Openat { path: open_path } => {
                        if let OpenPath::RelativeToCwd(path_ref) = open_path {
                            let mut path = path_ref.clone();
                            if let Some(cwd) = tgid_cwd.get(tgid) {
                                path = cwd.join(path);
                            }
                            trace.add_open(path);
                        } else {
                            warn!("open path {:?} not yet supported for strace", open_path);
                        }
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
                        socket_fd_captures.insert((*socket_fd).to_string(), SocketCapture {
                            socket_addr: socket_addr.clone(),
                            state: SocketCaptureState::Complete(Vec::new()),
                        });

                        // FIXME: in the near future we could probably remove add_connect and just use the SocketCapture
                        // data that is fed over to the trace when the socket is closed to extract all the connections.
                        trace.add_connect(socket_addr.clone());
                    }
                    Function::Sendto {
                        socket_fd,
                        data: StringArgument::Complete(data),
                    } => {
                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        let socket_capture = socket_fd_captures.get_mut(*socket_fd);
                        if let Some(socket_capture) = socket_capture {
                            if let SocketCaptureState::Complete(ref mut socket_operations) =
                                socket_capture.state
                            {
                                // FIXME: any way I can use `take()` here?  It fails because `data.take` is a move out of a
                                // shared reference, but it's a reference to `function` that I'm about to drop anyway.
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
                        let socket_capture = socket_fd_captures.get_mut(*fd);
                        if let Some(socket_capture) = socket_capture {
                            if let SocketCaptureState::Complete(ref mut socket_operations) =
                                socket_capture.state
                            {
                                // FIXME: any way I can use `take()` here?  It fails because `data.take` is a move out of a
                                // shared reference, but it's a reference to `function` that I'm about to drop anyway.
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
                        let in_progress = socket_fd_captures.get_mut(*fd);
                        if let Some(in_progress) = in_progress {
                            in_progress.state = SocketCaptureState::Incomplete;
                        }
                        // sendto on a pid/socket that we don't know about will be normal/routine for any server-side
                        // sockets used by this test (eg. bind/accept), because we don't trace those.  We don't need to
                        // trace those, so we'll ignore any unrecognized sockets.
                    }
                    Function::Close { fd } => {
                        let socket_fd_captures = tgid_socket_fd_captures.entry(*tgid).or_default();
                        let socket_capture = socket_fd_captures.remove(*fd);
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

                // FIXME: the continual error handling with waitpid() here is necessary, but dumbly implemented --
                // should wrap child pid in a struct that would do this when dropped, and then "take" from it later --
                // cleaner and less prone to error from future changes.

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
                let mut buf = [0u8; 1];
                let mut read_file = File::from(read_goahead_fd);
                read_file.read_exact(&mut buf).expect("pipe read_exact()");
                drop(read_file);

                // Connect stdout, stderr to the pipes
                nix::unistd::close(0).expect("close(0)"); // stdin
                nix::unistd::dup2(stdout_write_fd.as_raw_fd(), 1).expect("dup2(1)"); // stdout
                nix::unistd::dup2(stderr_write_fd.as_raw_fd(), 2).expect("dup2(2)"); // stderr

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
            tokio::task::spawn_blocking(move || waitpid(Pid::from_raw(pid), None).unwrap());
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

        // "Some(\"25315 <... read resumed>\\\"\\\\x00\\\", 1)      = 1\")";
        trace!("LineReader for TraceClient: {line:?}");
        Ok(line)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::{
//         collections::BTreeSet,
//         net::{Ipv4Addr, SocketAddrV4},
//         path::{Path, PathBuf},
//     };

//     use crate::sys_trace::{
//         strace::STraceSysTraceCommand,
//         trace::{DraftTrace, ResolvedSocketAddr, Trace, UnifiedSocketAddr},
//     };

//     #[test]
//     fn multiprocess_cwd() {
//         // trace_raw contains an strace that was generated by running scripts/generate-strace-multiproc-chdir.py under
//         // strace.  This script accesses these files, but all in separate processes with `chdir` commands to the parent
//         // directories; this creates a test case for per-process cwd tracking:
//         //
//         // - "flake.nix" (from start process's cwd)
//         // - "/home/mfenniak/Dev/testtrim/README.md"
//         // - "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
//         // - "/home/mfenniak/.zsh_history"
//         // - "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
//         // - "/home/mfenniak/Dev/test.txt"
//         //
//         // The files listed above are not required to be present to make this test work; read_trace doesn't canonicalize
//         // the paths.
//         //
//         // Regenerating this file (if needed?) is done by...
//         // ```
//         // rm tests/test_data/strace-multiproc-chdir.strace.*
//         // strace --follow-forks --output-separately \
//         // --trace=chdir,openat,clone,clone3,connect,sendto,close,read,recvfrom,%process \
//         // --string-limit=512 --strings-in-hex=non-ascii-chars \
//         // --output tests/test_data/strace-multiproc-chdir.strace python scripts/generate-strace-multiproc-chdir.py
//         // ```

//         let mut trace = DraftTrace::new();

//         let res = STraceSysTraceCommand::read_all_pid_trace_files(
//             &mut trace,
//             Path::new("tests/test_data/strace-multiproc-chdir.strace"),
//             Path::new("/nix/store/zv1kaq7f1q20x62kbjv6pfjygw5jmwl6-python3-3.12.7/bin/python"),
//         );
//         assert!(res.is_ok(), "expected ok, was: {res:?}");

//         let trace: Trace = trace.try_into().expect("DraftTrace -> Trace");

//         let paths = trace.get_open_paths();
//         assert!(paths.contains(&PathBuf::from("flake.nix")));
//         assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/testtrim/README.md")));
//         assert!(paths.contains(&PathBuf::from(
//             "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
//         )));
//         assert!(paths.contains(&PathBuf::from("/home/mfenniak/.zsh_history")));
//         assert!(paths.contains(&PathBuf::from(
//             "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
//         )));

//         // test.txt is accessed in an unusual way compared to above cases; one process chdir's into /home/mfenniak/Dev,
//         // and then starts a subprocess which inherits that directory, and then accesses "test.txt".  So if this test
//         // case is failing, it's the inheritence of the cwd from parent processes that is to blame (probably).
//         assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/test.txt")));
//     }

//     #[test]
//     fn connect_trace_read() {
//         // trace_raw contains an strace that was generated by running `curl https://www.google.ca/` under an strace.
//         //
//         // Regenerating this file (if needed?) is done by...
//         // ```
//         // rm tests/test_data/tests/test_data/strace-curl-google-without-nscd.strace.*
//         // strace --follow-forks --output-separately \
//         // --trace=chdir,openat,clone,clone3,connect,sendto,close,read,recvfrom,%process \
//         // --string-limit=512 --strings-in-hex=non-ascii-chars \
//         // --output tests/test_data/strace-curl-google-without-nscd.strace curl https://www.google.ca/
//         // ```

//         let mut trace = DraftTrace::new();

//         let res = STraceSysTraceCommand::read_all_pid_trace_files(
//             &mut trace,
//             Path::new("tests/test_data/strace-curl-google-without-nscd.strace"),
//             Path::new("/run/current-system/sw/bin/curl"),
//         );
//         assert!(res.is_ok(), "expected OK, was {res:?}");

//         let trace: Trace = trace.try_into().expect("DraftTrace -> Trace");

//         let sockets = trace.get_connect_sockets();

//         assert!(sockets.contains(&ResolvedSocketAddr {
//             address: UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket")),
//             hostnames: BTreeSet::from([]),
//         }));

//         println!("sockets: {sockets:?}");
//         assert!(sockets.contains(&ResolvedSocketAddr {
//             address: UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(SocketAddrV4::new(
//                 Ipv4Addr::new(142, 250, 217, 67),
//                 443
//             ))),
//             hostnames: BTreeSet::from([String::from("www.google.ca")]),
//         }));
//     }
// }
