// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `strace` syscall tracing can't be nested -- you can't trace a process that is already being traced.  However,
//! testtrim runs `strace` based tests within its test suite, and testtrim is run under itself in CI, so we want nested
//! syscall tracing with strace.  This module facilitates that through inter-process communication.
//!
//! The key design constraint is that it is critical that the communication between the top-level process (which is
//! running strace) and any ancestor processes does not require syscalls for every message being passed.  This is
//! because the ancestor processes are being monitored by strace, so if they needed a syscall to get information from
//! the parent, they would loop infinitely as they kept generating more syscalls that needed to be read.

use std::{
    collections::HashSet,
    fs::remove_file,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::Result;
use dashmap::DashMap;
use log::warn;
use shared_mem_queue::{
    byte_queue::ByteQueue,
    msg_queue::{MqError, MsgQueue},
};
use shared_memory::{Shmem, ShmemConf};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::{JoinHandle, JoinSet},
};
use uuid::Uuid;

use super::{ReceptionistFacade, tokenizer::parse_pid};

/// A process ID, but one that is the root of a tree of processes being monitored.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct SubscriberRootPid(i32);

/// The `Receptionist` is the exterior entrypoint for subprocess tracing.
///
/// On the in-process side, it receives information from the syscall tracer about the processes being traced in order to
/// maintain a process tree, and is given access to the feed of syscalls to dispatch them to listeners.
///
/// On the out-of-process side, it creates a UNIX socket that allows clients to connect and subscribe to a subprocess to
/// trace.  All ancestors of that subprocess then have their syscalls communicated to that subscriber through a
/// shared-memory communication model.
pub struct Receptionist {
    address: PathBuf,
    subscribers: Arc<DashMap<SubscriberRootPid, DedicatedOperator>>,
    shutdown_request_tx: tokio::sync::oneshot::Sender<()>,
    shutdown_complete_rx: tokio::sync::oneshot::Receiver<()>,
}

impl Receptionist {
    pub fn get_receptionist_address(trace_path: &Path) -> PathBuf {
        let mut path = trace_path.with_extension("sock");
        // SUN_LEN is the max UNIX socket length, which is short...
        if path.as_os_str().len() > 107 {
            path.pop();
            path.push(&Uuid::new_v4().to_string()[0..5]);
        }
        path
    }

    pub fn startup(address: PathBuf) -> Result<Self> {
        let (shutdown_request_tx, mut shutdown_request_rx) = tokio::sync::oneshot::channel::<()>();
        let (shutdown_complete_tx, shutdown_complete_rx) = tokio::sync::oneshot::channel::<()>();

        let retval = Self {
            address,
            subscribers: Arc::new(DashMap::new()),
            shutdown_request_tx,
            shutdown_complete_rx,
        };

        let listener = UnixListener::bind(&retval.address)?;
        let subscribers = retval.subscribers.clone();
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    shutdown_event = (&mut shutdown_request_rx) => {
                        // Shutdown all subscribers cleanly.
                        let mut remove = vec![];
                        for subscriber in subscribers.iter() {
                            remove.push(subscriber.key().clone());
                        }
                        let mut set = JoinSet::new();
                        for rem in remove {
                            // safe: the only other modification paths to this map are not possible concurrently
                            let (_pid, subscriber) = subscribers.remove(&rem).unwrap();
                            set.spawn(subscriber.shutdown());
                        }
                        set.join_all().await;

                        // If Receptionist was dropped without a `shutdown()`, then shutdown_event could contain a
                        // RecvError, in which case we don't want to send the shutdown_complete_tx because there will be
                        // no receiver (resulting in an error).
                        if shutdown_event.is_ok() {
                            // only possible failure is if shutdown_complete_rx has been deallocated, which could happen
                            // if Receptionist was dropped without shutdown, but sending on this channel wouldn't matter
                            // then -- ignore Result failure.
                            let _ = shutdown_complete_tx.send(());
                        }
                        return;
                    },
                    stream = listener.accept() => {
                        let (mut stream, _addr) = match stream {
                            Ok(inner) => inner,
                            Err(err) => {
                                warn!("Receptionist listener.accept had error: {err:?}");
                                continue;
                            }
                        };
                        let subscribe_pid = SubscriberRootPid(
                            match stream.read_i32().await {
                                Ok(pid) => pid,
                                Err(err) => {
                                    warn!("Receptionist stream.read_i32 had error: {err:?}");
                                    continue;
                                }
                            }
                        );
                        let operator = match DedicatedOperator::startup(&subscribe_pid) {
                            Ok(operator) => operator,
                            Err(err) => {
                                warn!("DedicatedOperator startup failed: {err:?}");
                                // Seems reasonable to drop operator without shutdown if it didn't startup successfully
                                continue;
                            },
                        };
                        // Must store the operator, in order to begin getting events from peek_trace, before we tell the
                        // client the unique_id -- can't let the client think it's ready and then potentially miss an
                        // event.  On the other hand, have to tear down the operator if sending the ID fails, making
                        // this a little ugly in the error handling.
                        let unique_id = String::from(operator.unique_id());
                        let subscribe_pid_copy = subscribe_pid.clone();
                        subscribers.insert(subscribe_pid, operator);
                        if let Err(err) = stream.write_all(unique_id.as_bytes()).await {
                            warn!("Receptionist stream.write_all had error: {err:?}");
                            // theoretically remove_process could simultaneously remove
                            if let Some((_pid, operator)) = subscribers.remove(&subscribe_pid_copy) {
                                tokio::task::spawn(operator.shutdown());
                            }
                        }
                    }
                }
            }
        });

        Ok(retval)
    }
}

impl ReceptionistFacade for Receptionist {
    async fn peek_trace(&self, trace_line: &str) {
        if self.subscribers.is_empty() {
            return;
        }

        let mut tokenizer_input: &str = trace_line;
        let Ok(pid) = parse_pid(&mut tokenizer_input) else {
            warn!("peek_trace: parse_pid failed on input: {trace_line:?}");
            return;
        };
        let pid = i32::from_str(pid).unwrap(); // pretty safe: parser should guarantee it's numeric, and pid can't be not i32
        for subscribers in self.subscribers.iter() {
            subscribers.value().peek_trace(pid, trace_line).await;
        }
    }

    fn add_subprocess(&self, parent_pid: i32, child_pid: i32) {
        for mut subscriber in self.subscribers.iter_mut() {
            subscriber.value_mut().add_subprocess(parent_pid, child_pid);
        }
    }

    fn remove_process(&self, pid: i32) {
        let mut remove = vec![];
        for mut subscriber in self.subscribers.iter_mut() {
            if subscriber.value_mut().remove_process(pid) {
                remove.push(subscriber.key().clone());
            }
        }
        for rem in remove {
            // Theoretically teardown in an error handler in the spawned task could do this remove simultaneously, so
            // need to protect against trying to do it twice.
            if let Some((_pid, subscriber)) = self.subscribers.remove(&rem) {
                // shutdown is required for the transmission of the EOF marker... spawn is a bit of a strange approach
                // here because we could end up shutting down the Receptionist while there are still DedicatedOperator
                // instances that are now owned by the tokio spawn queue.  I guess that's OK?  The major problem is a
                // lack of error reporting if anything in the shutdown process goes wrong -- it seems to be done from
                // here, but might not be.  I could make remove_process async but run into errors with
                // FutureExtractorOutput not being `Send`, and, it adds async operations into the `read_strace_output`
                // which isn't ideal... but solving that error and making this async is probably the "right" thing to
                // do.
                tokio::spawn(subscriber.shutdown());
            }
        }
    }

    async fn shutdown(self) {
        self.shutdown_request_tx.send(()).unwrap(); // infallible -- shutdown_request_rx is stored in tokio task that is infallible so can't be deallocated
        let _ = self.shutdown_complete_rx.await; // should be infallible, but if an error occurs its because the task dealloced without a send which would be unimportant
        let _ = remove_file(self.address); // ok to fail, would just leave a socket in the tmpdir
    }
}

/// Responsible for managing communication to a specific client, about a set of process IDs spawned from one single
/// `SubscriberRootPid`.
struct DedicatedOperator {
    pid_set: HashSet<i32>,
    _shmem: ShmemWrapper, // never read, but kept around for cleanup
    unique_id: String,
    preshutdown_state: Option<DedicatedOperatorPreshutdownState>,
}

struct DedicatedOperatorPreshutdownState {
    shutdown_request_tx: tokio::sync::oneshot::Sender<()>,
    shutdown_complete_rx: tokio::sync::oneshot::Receiver<()>,
    trace_tx: tokio::sync::mpsc::Sender<String>,
    spawned_task: JoinHandle<()>,
}

// Wrapper to make our shared memory access safe
struct ShmemWrapper {
    _inner_shmem: Shmem,
    // inner_bytequeue: ByteQueue,
}

// We implement Send safely; although there are raw ptrs stored in `ShmemWrapper` which are considered `!Send`, they
// will be accessed safely in a single thread.
unsafe impl Send for ShmemWrapper {}
unsafe impl Sync for ShmemWrapper {}

impl DedicatedOperator {
    pub fn startup(pid: &SubscriberRootPid) -> Result<Self> {
        let (shutdown_request_tx, mut shutdown_request_rx) = tokio::sync::oneshot::channel::<()>();
        let (shutdown_complete_tx, shutdown_complete_rx) = tokio::sync::oneshot::channel::<()>();
        let (trace_tx, mut trace_rx) = tokio::sync::mpsc::channel::<String>(64);
        let unique_id = format!("testtrim-{}", Uuid::new_v4());

        let shmem = ShmemConf::new().size(65536).os_id(&unique_id).create()?;

        // ByteQueue needs to be created before any reader is ever attached, or else the reader might read uninitialized
        // memory.  So we'll create it immediately.
        let bytequeue = unsafe { ByteQueue::create(shmem.as_ptr(), shmem.len()) };

        let spawned_task = tokio::task::spawn(async move {
            let mut msg_queue = MsgQueue::new(bytequeue, b"TT", [0u8; 0]);

            loop {
                tokio::select! {
                    shutdown_event = (&mut shutdown_request_rx) => {
                        // Before we can shutdown, we need to ensure that the channel is clear.  We must assume that any
                        // necessary writes to the channel are already done before the shutdown begins, and that all
                        // `Sender` (which should just be the one) are dropped, allowing recv to just flush the buffer
                        // and not block.
                        while let Some(trace) = trace_rx.recv().await {
                            if let Err(err) = msg_queue.write_blocking(trace.as_ref()) {
                                warn!("msg_queue write error while flushing: {err:?}");
                                break;
                            }
                        }
                        // Write EOF signal
                        if let Err(err) = msg_queue.write_blocking(&[0u8]) {
                            warn!("msg_queue write error while writing EOF: {err:?}");
                        }
                        // If DedicatedOperator was dropped without a `shutdown()`, then shutdown_event could contain a
                        // RecvError, in which case we don't want to send the shutdown_complete_tx because there will be
                        // no receiver (resulting in an error).
                        if shutdown_event.is_ok() {
                            // only possible failure is if shutdown_complete_rx has been deallocated, which could happen
                            // if dropped without shutdown (presumably after the event was sent or else we wouldn't be
                            // inside this if), but sending on this channel wouldn't matter then -- ignore Result
                            // failure.
                            let _ = shutdown_complete_tx.send(());
                        }
                        return;
                    },
                    trace = trace_rx.recv() => {
                        let Some(trace) = trace else { continue; };
                        if let Err(err) = msg_queue.write_blocking(trace.as_ref()) {
                            warn!("msg_queue write error: {err:?}");
                            break;
                        }
                    },
                }
            }
        });

        let mut pid_set = HashSet::new();
        pid_set.insert(pid.0);
        Ok(DedicatedOperator {
            pid_set,
            _shmem: ShmemWrapper {
                _inner_shmem: shmem,
            },
            unique_id,
            preshutdown_state: Some(DedicatedOperatorPreshutdownState {
                shutdown_request_tx,
                shutdown_complete_rx,
                trace_tx,
                spawned_task,
            }),
        })
    }

    pub async fn peek_trace(&self, pid: i32, trace_line: &str) {
        if self.pid_set.contains(&pid) {
            if let Some(ref state) = self.preshutdown_state {
                if let Err(err) = state.trace_tx.send(String::from(trace_line)).await {
                    warn!("trace_tx write error: {err:?}");
                }
            } else {
                warn!("peek_trace: dropped interesting message due to shutdown in-progress");
            }
        }
    }

    pub fn add_subprocess(&mut self, parent_pid: i32, child_pid: i32) {
        if self.pid_set.contains(&parent_pid) {
            self.pid_set.insert(child_pid);
        }
    }

    pub fn remove_process(&mut self, pid: i32) -> bool {
        self.pid_set.remove(&pid);
        self.pid_set.is_empty()
    }

    pub async fn shutdown(mut self) {
        if let Some(state) = self.preshutdown_state.take() {
            drop(state.trace_tx); // important that we drop the `Sender` otherwise the `Receiver`'s `recv` future will wait for addt. messages.
            state.shutdown_request_tx.send(()).unwrap(); // infallible -- shutdown_request_rx is stored in tokio task that is infallible so can't be deallocated
            let _ = state.shutdown_complete_rx.await; // should be infallible, but if an error occurs its because the task dealloced without a send which would be unimportant
        }
    }

    pub fn unique_id(&self) -> &str {
        &self.unique_id
    }
}

impl Drop for DedicatedOperator {
    fn drop(&mut self) {
        if let Some(state) = self.preshutdown_state.take() {
            // We'll guarantee that our tokio::spawn task is cleaned up with this drop, but we won't be sure that all
            // data is transmitted to the subscriber and buffers are flushed.
            warn!(
                "Drop of DedicatedOperator without a `shutdown`; an incomplete trace may be sent to a subscriber"
            );
            drop(state.trace_tx);
            state.shutdown_request_tx.send(()).unwrap(); // infallible -- shutdown_request_rx is stored in tokio task that is infallible so can't be deallocated
            state.spawned_task.abort();
        }
    }
}

/// `TraceClient` connects to a parent testtrim app and subscribes to receive strace data from a process tree.
pub struct TraceClient {
    trace_rx: tokio::sync::mpsc::Receiver<String>,
    read_join_handle: Option<JoinHandle<Result<()>>>,
    shutdown_signal: Arc<AtomicBool>,
}

impl TraceClient {
    pub async fn try_create(receptionist_address: &Path, pid: i32) -> Result<Self> {
        let mut stream = UnixStream::connect(receptionist_address).await?;
        stream.write_i32(pid).await?;
        let mut unique_id = [0u8; 64];
        let unique_id_len = stream.read(&mut unique_id).await?;
        let unique_id = String::from_utf8(unique_id[..unique_id_len].to_vec())?;

        let (trace_tx, trace_rx) = tokio::sync::mpsc::channel::<String>(64);
        let shutdown_signal = Arc::new(AtomicBool::new(false));
        let shutdown_signal_inner = shutdown_signal.clone();

        let read_join_handle = tokio::task::spawn_blocking(move || {
            let shmem = ShmemConf::new().os_id(&unique_id).open()?;
            let bytequeue = unsafe { ByteQueue::attach(shmem.as_ptr(), shmem.len()) };
            let read_buffer = [0u8; 4096];
            let mut msgqueue = MsgQueue::new(bytequeue, b"TT", read_buffer);

            // Reminder: this loop must be free of any syscalls that are being traced, otherwise we generate more
            // syscall data in the parent strace as a result of reading the strace data, which has a risk of being an
            // infinite loop.
            loop {
                if shutdown_signal_inner.fetch_or(false, std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match msgqueue.read_or_fail() {
                    Ok(msg) => {
                        if msg.len() == 1 && msg[0] == 0 {
                            // EOF signal.
                            break;
                        }
                        let vec = msg.to_vec();
                        trace_tx.blocking_send(unsafe { String::from_utf8_unchecked(vec) })?;
                    }
                    Err(MqError::MqEmpty) => {
                        // This should be a safe syscall because we don't trace `sleep`.  The TraceClient works without
                        // this, but spins checking the shared memory constantly -- a very small "yield" sleep here
                        // prevents 100% CPU usage.
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(other) => {
                        return Err(other.into());
                    }
                }
            }
            anyhow::Result::<()>::Ok(())
        });

        Ok(TraceClient {
            trace_rx,
            read_join_handle: Some(read_join_handle),
            shutdown_signal,
        })
    }

    pub async fn next_line(&mut self) -> Result<Option<String>> {
        Ok(self.trace_rx.recv().await)
    }

    pub async fn shutdown(mut self) {
        self.shutdown_signal
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(read_join_handle) = self.read_join_handle.take() {
            // JoinHandle join should be infallible, unless the tokio spawn panic'd
            if let Err(err) = read_join_handle.await.unwrap() {
                // Possibly could fail from shmem access.
                warn!("failure in TraceClient spawn process: {err:?}");
            }
        }
    }
}

impl Drop for TraceClient {
    fn drop(&mut self) {
        self.shutdown_signal
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::sys_trace::strace::{
        ReceptionistFacade as _,
        shmem::{Receptionist, TraceClient},
    };
    use anyhow::Result;
    use tokio::time::timeout;
    use uuid::Uuid;

    #[tokio::test]
    async fn receptionist_basic_read_write() -> Result<()> {
        let address = PathBuf::from(format!("receptionist.sock-{}", Uuid::new_v4()));
        let receptionist = Receptionist::startup(address.clone())?;
        let mut client = TraceClient::try_create(&address, 100).await?;

        receptionist.peek_trace("100 close(3) = 0").await;
        assert_eq!(
            Some(String::from("100 close(3) = 0")),
            client.next_line().await?
        );
        receptionist.peek_trace("100 close(5) = 0").await;
        assert_eq!(
            Some(String::from("100 close(5) = 0")),
            client.next_line().await?
        );

        client.shutdown().await;
        receptionist.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    async fn receptionist_filter_pid() -> Result<()> {
        let address = PathBuf::from(format!("receptionist.sock-{}", Uuid::new_v4()));
        let receptionist = Receptionist::startup(address.clone())?;
        let mut client = TraceClient::try_create(&address, 100).await?;

        // To keep this test simple and not be relying on the timeout case, send data that should be filtered out, and
        // then data that should be included, and check that only the second line is transmitted:
        receptionist.peek_trace("101 close(3) = 0").await;
        receptionist.peek_trace("100 close(3) = 0").await;
        let next_line = timeout(std::time::Duration::from_millis(100), client.next_line())
            .await
            .expect("timeout on client.next_line()")?;
        assert_eq!(Some(String::from("100 close(3) = 0")), next_line);

        client.shutdown().await;
        receptionist.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    async fn receptionist_filter_subprocess() -> Result<()> {
        let address = PathBuf::from(format!("receptionist.sock-{}", Uuid::new_v4()));
        let receptionist = Receptionist::startup(address.clone())?;
        let mut client = TraceClient::try_create(&address, 100).await?;

        receptionist.add_subprocess(100, 103);

        // To keep this test simple and not be relying on the timeout case, send data that should be filtered out, and
        // then data that should be included, and check that only the second line is transmitted:
        receptionist.peek_trace("101 close(3) = 0").await;
        receptionist.peek_trace("100 close(3) = 0").await;
        let next_line = timeout(std::time::Duration::from_millis(100), client.next_line())
            .await
            .expect("timeout on client.next_line()")?;
        assert_eq!(Some(String::from("100 close(3) = 0")), next_line);

        receptionist.peek_trace("103 close(5) = 0").await;
        let next_line = timeout(std::time::Duration::from_millis(100), client.next_line())
            .await
            .expect("timeout on client.next_line()")?;
        assert_eq!(Some(String::from("103 close(5) = 0")), next_line);

        client.shutdown().await;
        receptionist.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    async fn receptionist_auto_shutdown() -> Result<()> {
        let address = PathBuf::from(format!("receptionist.sock-{}", Uuid::new_v4()));
        let receptionist = Receptionist::startup(address.clone())?;
        let mut client = TraceClient::try_create(&address, 100).await?;

        receptionist.peek_trace("100 close(3) = 0").await;
        assert_eq!(
            Some(String::from("100 close(3) = 0")),
            client.next_line().await?
        );

        receptionist.remove_process(100);
        let next_line = timeout(std::time::Duration::from_millis(100), client.next_line())
            .await
            .expect("timeout on client.next_line()")?;
        assert_eq!(None, next_line);

        client.shutdown().await;
        receptionist.shutdown().await;

        Ok(())
    }
}
