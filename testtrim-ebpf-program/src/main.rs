// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_NO_PREALLOC,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::{error, info};
use core::{
    ffi::{c_char, c_long},
    mem,
};
use testtrim_ebpf_common::{Event, EventData};

// mod openat;

/// Stores the actual trace data that we want to stream back to the user-space process -- eg. information about openat
/// calls, etc.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(4096, 0);

/// Mostly an internal map of the PIDs that are being monitored, but also primed externally for the first PID to start
/// tracing.  The key is a PID of any process being monitored; the value is the root PID that we were asked to monitor
/// which may be the same as the key, or may be a subprocess of the key.
///
/// FIXME:: in order to support monitoring multiple process-trees with one eBPF program, we'll have to change
/// MONITORED_PIDS into a map of (monitored_pid, original_pid) and emit events with the actual pid (for CWD and FD
/// tracking), actual tgid, and original monitored PID; the later of which can be used to split up the event stream into
/// the separate process trees.
#[map]
pub static MONITORED_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

/// Stream back events in the form of +1 and -1 which represent the total count of monitored processes.  u8.
///
/// The user-space process will want to "stop" it's work once all the processes exit.  There are enough limitations in
/// the eBPF module that it doesn't seem to be possible to identify this on the eBPF side -- eg. we can't read the
/// number of items remaining in MONITORED_PIDS, we can't use spinlocks so we can't maintain a count here safely, and we
/// don't have any other atomic operations available to maintain that count.  So we stream "+1" for "added" and "-1" for
/// "removed" and let the user-space process track the remaining tasks.
///
/// FIXME: We can also use this to report back any error conditions -- eg. provide a -2 (which will never happen
/// otherwise) to indicate that the EVENTS RingBuf ran out of space.  Should be pretty safe because we'll have a lot of
/// spare space in this buf.  Not currently implemented.
#[map]
pub static MONITORING_EVENTS: RingBuf = RingBuf::with_byte_size(4096, 0); // FIXME: can't be any smaller, right?  1 page size min?

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ▶ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// name: sys_enter_openat
// ID: 717
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
//
//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:int dfd;  offset:16;      size:8; signed:0;
//         field:const char * filename;    offset:24;      size:8; signed:0;
//         field:int flags;        offset:32;      size:8; signed:0;
//         field:umode_t mode;     offset:40;      size:8; signed:0;
//
// print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
//
// Although dfd (directory filedescriptor) is clearly described as an unsigned 8-byte (i64), this doesn't seem to
// reflect reality correctly.  (a) The most common value for this parameter is "-100" (AT_FDCWD), which is signed.  (b)
// When inspecting the syscall data, I'm most often getting 0x9CFFFFFF00000000 which is an i32 value of -100 with four
// zero bytes following it.  So; I'll treat this as an i32 and ignore the following four bytes as this seems correct?

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> c_long {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<c_long, c_long> {
    let pid = ctx.pid(); // u32 = (bpf_get_current_pid_tgid() >> 32) as u32;
    let root_pid = match unsafe { MONITORED_PIDS.get(&pid) } {
        Some(root_pid) => root_pid,
        None => {
            return Ok(0);
        }
    };

    #[repr(C)]
    struct OpenatSyscallArgs {
        dirfd: i32,
        _skipped_bytes: i32,
        pathname: *const c_char,
        flags: i64,
    }
    let args = unsafe { ctx.read_at::<OpenatSyscallArgs>(16) }?;

    match EVENTS.reserve::<Event>(0) {
        Some(mut reserved) => {
            unsafe {
                let event_ptr = reserved.as_mut_ptr();

                // let ptr = (*event.as_mut_ptr());
                (*event_ptr).root_pid = *root_pid;
                (*event_ptr).actual_pid = pid;
                (*event_ptr).actual_tgid = ctx.tgid();

                // Get the pointer to where the EventData will be stored
                let event_data_ptr = &mut (*event_ptr).event_data;
                let event_data_raw_ptr = event_data_ptr as *mut EventData;

                // Enum discriminant which allows differentiation between different enum values in EventData
                let discriminant = event_data_raw_ptr as *mut u8;
                *discriminant = 0; // FIXME: ideally we could pull this through std::mem::discriminant rather than hard-coding, but no_std...

                // Write dirfd - it comes right after the discriminant.  Even though the discriminant is a u8, the next
                // field is 8 bytes later for the required alignment of the i32.  FIXME: this is probably
                // platform-specific (x86-64) and may need tweaks in any other platform.
                let dirfd_ptr = (discriminant as *mut u64).byte_add(8);
                *(dirfd_ptr as *mut i32) = args.dirfd;

                // Write filename - comes after dirfd
                let filename_ptr =
                    (dirfd_ptr as *mut u8).byte_add(mem::size_of::<i32>()) as *mut [u8; 256];
                let bytes_read = match bpf_probe_read_user_str_bytes(
                    args.pathname as *const u8,
                    &mut *filename_ptr,
                ) {
                    Ok(slice) => slice.len(),
                    Err(e) => {
                        reserved.discard(0);
                        return Err(e);
                    }
                };

                // Write filename_len - comes after the filename array.  It's after the 256 byte filename, but also
                // needs +4 bytes to reach required alignment for the usize (as dirfd was i32).  FIXME: this is probably
                // platform-specific (x86-64) and may need tweaks in any other platform.
                let filename_len_ptr = (filename_ptr as *mut u8).add(256 + 4) as *mut usize;
                *filename_len_ptr = bytes_read;
            }
            reserved.submit(0);
        }
        None => {
            // we're in a bad space if we don't have buffer space for these events... it probably indicates that the
            // user-space program crashed uncleanrly and didn't cleanup (if that's possible?).  We'll write to the log
            // if possible but probably will be fuller than this buffer was.
            error!(&ctx, "can't acquire space in EVENTS ringbuf");
        }
    }

    info!(&ctx, "tracepoint sys_enter_openat called from PID {}", pid);
    Ok(0)
}

// ▶ sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
// name: sched_process_fork
// ID: 324
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
//
//         field:char parent_comm[16];     offset:8;       size:16;        signed:0;
//         field:pid_t parent_pid; offset:24;      size:4; signed:1;
//         field:char child_comm[16];      offset:28;      size:16;        signed:0;
//         field:pid_t child_pid;  offset:44;      size:4; signed:1;
//
// print fmt: "comm=%s pid=%d child_comm=%s child_pid=%d", REC->parent_comm, REC->parent_pid, REC->child_comm, REC->child_pid

const PARENT_PID_OFFSET: usize = 24;
const CHILD_PID_OFFSET: usize = 44;

#[tracepoint]
fn sched_process_fork(ctx: TracePointContext) -> c_long {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<c_long, c_long> {
    let parent_pid: u32 = unsafe { ctx.read_at(PARENT_PID_OFFSET)? };
    let root_pid = match unsafe { MONITORED_PIDS.get(&parent_pid) } {
        Some(root_pid) => root_pid,
        None => {
            return Ok(0);
        }
    };

    let child_pid: u32 = unsafe { ctx.read_at(CHILD_PID_OFFSET)? };

    info!(
        &ctx,
        "tracepoint handle_fork found parent {} spawned child PID {}", parent_pid, child_pid
    );
    MONITORED_PIDS.insert(&child_pid, root_pid, 0)?;

    // FIXME: future - will need root_pid in order to send to MONITORING_EVENTS the root pid for each counter change
    match MONITORING_EVENTS.reserve::<i8>(0) {
        Some(mut buf) => {
            buf.write(1);
            buf.submit(0);
        }
        None => {
            // we're in a bad space if we don't have buffer space for these events... it probably indicates that the
            // user-space program crashed uncleanrly and didn't cleanup (if that's possible?).  We'll write to the log
            // if possible but probably will be fuller than this buffer was.
            error!(&ctx, "can't acquire space in monitor ringbuf");
        }
    }

    Ok(0)
}

// sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
// name: sched_process_exit
// ID: 327
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
//
//         field:char comm[16];    offset:8;       size:16;        signed:0;
//         field:pid_t pid;        offset:24;      size:4; signed:1;
//         field:int prio; offset:28;      size:4; signed:1;
//
// print fmt: "comm=%s pid=%d prio=%d", REC->comm, REC->pid, REC->prio

#[tracepoint]
fn sched_process_exit(ctx: TracePointContext) -> c_long {
    match try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exit(ctx: TracePointContext) -> Result<c_long, c_long> {
    let pid: u32 = unsafe { ctx.read_at(24)? };
    // FIXME: future - will need root_pid in order to send to MONITORING_EVENTS the root pid for each counter change
    let _root_pid = match unsafe { MONITORED_PIDS.get(&pid) } {
        Some(root_pid) => root_pid,
        None => {
            return Ok(0);
        }
    };

    info!(
        &ctx,
        "tracepoint sched_process_exit found exit of PID {}", pid
    );
    MONITORED_PIDS.remove(&pid)?;

    match MONITORING_EVENTS.reserve::<i8>(0) {
        Some(mut buf) => {
            buf.write(-1);
            buf.submit(0);
        }
        None => {
            // we're in a bad space if we don't have buffer space for these events... it probably indicates that the
            // user-space program crashed uncleanrly and didn't cleanup (if that's possible?).  We'll write to the log
            // if possible but probably will be fuller than this buffer was.
            error!(&ctx, "can't acquire space in monitor ringbuf");
        }
    }

    Ok(0)
}
