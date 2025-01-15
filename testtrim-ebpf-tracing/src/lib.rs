// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![feature(once_cell_try)]

use std::ffi::OsStr;
use std::ffi::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::OnceLock;

use aya::{
    Ebpf, EbpfError,
    maps::{HashMap, MapData, MapError, RingBuf},
    programs::{ProgramError, TracePoint},
};
use log::{debug, warn};
use testtrim_ebpf_common::{Event, EventData};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::signal;

static MEMLOCK: OnceLock<()> = OnceLock::new();

#[derive(Error, Debug)]
pub enum EbpfTracerError {
    #[error("remove limit on locked memory failed, ret is: {0}")]
    MemlockLimit(c_int),

    #[error(transparent)]
    EbpfError(#[from] EbpfError),

    #[error(transparent)]
    EbpfLoggingError(#[from] aya_log::Error),

    #[error(transparent)]
    EbpfProgramError(#[from] ProgramError),

    #[error("eBPF program `{0}` could not be found")]
    EbpfProgramMissing(String),

    #[error("eBPF map `{0}` could not be found")]
    EbpfMapMissing(String),

    #[error(transparent)]
    EbpfMapError(#[from] MapError),
}

pub struct EbpfTracer {
    ebpf: Ebpf,
    monitored_pids: HashMap<MapData, u32, u32>,
    trace_events: RingBuf<MapData>,
    monitor_events: RingBuf<MapData>,
}

impl EbpfTracer {
    pub fn new() -> Result<Self, EbpfTracerError> {
        MEMLOCK.get_or_try_init(|| {
            // Bump the memlock rlimit. This is needed for older kernels that don't use the new memcg based accounting, see
            // https://lwn.net/Articles/837122/
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
            if ret != 0 {
                Err(EbpfTracerError::MemlockLimit(ret))
            } else {
                Ok(())
            }
        })?;

        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/testtrim-ebpf-program-output"
        )))?;
        // This can happen if you remove all log statements from your eBPF program; maybe shouldn't be treated as an
        // error but it's a good start.
        aya_log::EbpfLogger::init(&mut ebpf)?;

        let program: &mut TracePoint = ebpf
            .program_mut("sys_enter_openat")
            .ok_or_else(|| EbpfTracerError::EbpfProgramMissing(String::from("sys_enter_openat")))?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_openat")?;

        let program: &mut TracePoint = ebpf
            .program_mut("sched_process_fork")
            .ok_or_else(|| EbpfTracerError::EbpfProgramMissing(String::from("sched_process_fork")))?
            .try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_fork")?;

        let program: &mut TracePoint = ebpf
            .program_mut("sched_process_exit")
            .ok_or_else(|| EbpfTracerError::EbpfProgramMissing(String::from("sched_process_exit")))?
            .try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exit")?;

        let monitored_pids = HashMap::try_from(
            ebpf.take_map("MONITORED_PIDS")
                .ok_or_else(|| EbpfTracerError::EbpfMapMissing(String::from("MONITORED_PIDS")))?,
        )?;

        let trace_events = RingBuf::try_from(
            ebpf.take_map("EVENTS")
                .ok_or_else(|| EbpfTracerError::EbpfMapMissing(String::from("EVENTS")))?,
        )?;

        let monitor_events =
            RingBuf::try_from(ebpf.take_map("MONITORING_EVENTS").ok_or_else(|| {
                EbpfTracerError::EbpfMapMissing(String::from("MONITORING_EVENTS"))
            })?)?;

        Ok(EbpfTracer {
            ebpf,
            monitored_pids,
            trace_events,
            monitor_events,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // env_logger::init();
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default())?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the new memcg based accounting, see
    // https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at runtime. This approach is
    // recommended for most real-world use cases. If you would like to specify the eBPF program at runtime rather than
    // at compile-time, you can reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/testtrim-ebpf-program-output"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // FIXME: not sure if there's a side-effect to dropping program, but I assume there is -- so for multiple
    // tracepoints I'm storing them in separate variables to keep them in-scope.  There might be a better way to do this
    // -- can one program be attached to multiple traces?
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    let program2: &mut TracePoint = ebpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program2.load()?;
    program2.attach("sched", "sched_process_fork")?;
    let program3: &mut TracePoint = ebpf.program_mut("sched_process_exit").unwrap().try_into()?;
    program3.load()?;
    program3.attach("sched", "sched_process_exit")?;

    let mut monitored_pids: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut("MONITORED_PIDS").expect("map MONITORED_PIDS"))?;

    // Fork the subprocess, and then insert the subprocess's PID into the monitored_pids map referring to itself as the
    // "root" process that we're monitoring.
    // FIXME: unwrap
    fork_me(|pid| {
        monitored_pids
            .insert(pid.as_raw() as u32, pid.as_raw() as u32, 0)
            .unwrap()
    })?;
    let mut count_pids = 1;

    let trace_events: RingBuf<_> = RingBuf::try_from(ebpf.take_map("EVENTS").expect("map EVENTS"))?;
    let mut trace_events_fd = AsyncFd::new(trace_events)?;

    let monitor_events: RingBuf<_> = RingBuf::try_from(
        ebpf.take_map("MONITORING_EVENTS")
            .expect("map MONITORING_EVENTS"),
    )?;
    let mut monitor_events_fd = AsyncFd::new(monitor_events)?;

    let mut timer = pin!(tokio::time::sleep(std::time::Duration::from_secs(10)));
    let mut ctrl_c = pin!(signal::ctrl_c());
    println!("Waiting for Ctrl-C...");
    'outer: loop {
        tokio::select! {
            _ = &mut timer => {
                println!("Exiting after pause!");
                break;
            }
            _ = &mut ctrl_c => {
                println!("Exiting with Ctrl-C!");
                break;
            }
            guard = trace_events_fd.readable_mut() => {
                let mut guard = guard.unwrap();
                let trace_events: &mut aya::maps::RingBuf<_> = guard.get_inner_mut();
                while let Some(item) = trace_events.next() {
                    let bytes: &[u8] = &item;
                    // println!("bytes: {bytes:?}");
                    let event = unsafe { &*(bytes.as_ptr() as *const Event) };
                    // println!("event: {event:?}");
                    match event.event_data {
                        EventData::OpenAt { dirfd, filename, filename_len, } => {
                            let pathname = PathBuf::from(OsStr::from_bytes(&filename[..filename_len]));
                            println!("dirfd: {}, pathname: {:?}", dirfd, pathname);
                        }
                    }
                }
                guard.clear_ready();
            }
            guard = monitor_events_fd.readable_mut() => {
                let mut guard = guard.unwrap();
                let monitor_events: &mut aya::maps::RingBuf<_> = guard.get_inner_mut();
                while let Some(item) = monitor_events.next() {
                    let bytes: &[u8] = &item;
                    let signal = bytes[0] as i8;
                    println!("got MONITORING_EVENT: {bytes:?} {signal:?}");

                    match signal {
                        1 => { count_pids += 1 },
                        -1 => {
                            count_pids -= 1;
                            if count_pids == 0 {
                                println!("count_pids is now 0; exiting");
                                // FIXME: there could still be data in the EVENTS ringbuffer that hasn't been read -- we
                                // should ensure it is "read to end" before tearing down the eBPF program
                                break 'outer;
                            }
                        }
                        other => {
                            println!("unexpected signal {other:?}");
                        }
                    }
                }
                guard.clear_ready();

            }
        }
    }
    // timer.await?;
    // ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

use nix::unistd::Pid;

fn fork_me<F>(do_stuff: F) -> anyhow::Result<()>
where
    F: FnOnce(Pid),
{
    use nix::unistd::{ForkResult, fork, pipe};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let (read_fd, write_fd) = pipe()?;
    // let (mut tx, mut rx) = channel();

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            drop(read_fd);

            // Child spawned; do the needful for the eBPF tracer...
            do_stuff(child);

            // Now we can let the child know to move forward.
            let buf = [0u8; 1];
            let mut write_file = File::from(write_fd);
            loop {
                let bytes_written = write_file.write(&buf)?;
                if bytes_written != 0 {
                    break;
                }
            }
            drop(write_file);

            Ok(())
        }
        ForkResult::Child => {
            // FIXME: will need to add stderr/stdout/stdin management here to capture that output
            drop(write_fd);

            // using ptrace here for
            println!("[CHILD]: Child started; waiting for message from parent");
            // ptrace::traceme()?;
            let mut buf = [0u8; 1];
            let mut read_file = File::from(read_fd);
            loop {
                // FIXME: unwrap -- not sure what will happen for any error handling in this child fork.  Will need to
                // figure out a real way to report erros -- I guess with the stderr and exit code.
                let bytes_read = read_file.read(&mut buf).unwrap();
                if bytes_read != 0 {
                    break;
                }
            }
            println!("[CHILD]: Child moving forward");
            drop(read_file);

            // Execute a test command
            // FIXME: unwrap
            // let exec_err =
            //     Command::new("/home/mfenniak/Dev/testtrim-test-projects/go-micro-app/go-micro-app")
            //         .arg("--version")
            //         .exec();
            let exec_err = Command::new("/run/current-system/sw/bin/curl")
                .arg("https://google.ca/")
                .exec();
            // We won't reach here as exec replaces the process
            panic!("error in exec: {exec_err:?}");
        }
    }
}
