// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::{HashMap, HashSet}, os::fd::AsRawFd as _, process::ExitCode};

use anyhow::Result;
use nix::{libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_O_EXITKILL, SIGTRAP}, sys::signal::Signal, unistd::Pid};
use testtrim::cmd::cli::run_cli;

// #[tokio::main]
// async fn main() -> ExitCode {
//     run_cli().await
// }

// #[test]
// #[tokio::main]
fn main() -> Result<()> {
    use nix::sys::ptrace;
    use nix::sys::wait::{WaitStatus, wait};
    use nix::unistd::{ForkResult, close, fork, pipe, read};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let (read_fd, write_fd) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Parent { child: original_child } => {
            println!("[PARENT]: Parent process tracing child PID: {}", original_child);

            // Close write end in parent
            drop(write_fd);

            // Spawn a thread to handle reading from pipe
            // let read_fd = read_fd;
            let reader_thread = std::thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                loop {
                    match read(read_fd.as_raw_fd(), &mut buffer) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            println!("[PARENT]: child said: {:?}", &buffer[0..n]);
                            match String::from_utf8((&buffer[0..n]).to_vec()) {
                                Ok(str) => println!("[PARENT]: in str: {:?}", str),
                                Err(_) => todo!(),
                            }
                        }
                        Err(e) => {
                            eprintln!("Read error: {}", e);
                            break;
                        }
                    }
                }
                drop(read_fd);
            });

            // sync with exec
            let _ = wait()?;

            // Note: I considered, at one point, splitting the tracer into multiple threads so that each thread could
            // trace one subprocess.  The thought was that this would allow multiple processes to be suspended
            // simultaneously without blocking on each other by being part of the same "wait" syscall.  However, the
            // kernel maps the tracer process and the tracee process, and you can't make any tracing syscalls from
            // another pid (eg. another thread).  It would still be theoretically possible to do this if we could avoid
            // using P_TRACE_O_TRACE{FORK/VFORK/CLONE} which automatically attaches to the same process -- but I'm not
            // sure if there's another feasible way to trace subprocesses (intercept syscalls and PTRACE_ME within the
            // new processes somehow?).  Anyway, we'll have to just maximize efficiency in other means, as there's no
            // reason to believe this would have worked well anyway -- the context switches would've still been present
            // (or worse).
            ptrace::setoptions(
                original_child,
                ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE
            )?;
            ptrace::syscall(original_child, None)?; // restart after setting options

            let mut traced_pids = HashSet::new();
            traced_pids.insert(original_child);

            // // Wait for child to be ready for tracing
            // match wait()? {
            //     WaitStatus::Stopped(_, _) => {
            //         println!("[PARENT]: Child stopped and ready for tracing");
            //     }
            //     _ => panic!("Unexpected wait status"),
            // }


            // let mut in_syscall = false;
            let mut in_syscall: HashMap<Pid, bool> = HashMap::new();
            // in_syscall.insert(original_child, false);

            // Main tracing loop
            loop {
                match wait()? {
                    WaitStatus::PtraceEvent(child_pid, _signal, e @ PTRACE_EVENT_FORK)
                    | WaitStatus::PtraceEvent(child_pid, _signal, e @ PTRACE_EVENT_CLONE)
                    | WaitStatus::PtraceEvent(child_pid, _signal, e @ PTRACE_EVENT_VFORK) => {
                        // println!("[PARENT]: New child: ({}, {})", child_pid, e);
                        traced_pids.insert(child_pid);
                        ptrace::syscall(child_pid, None)?; // allow child to continue
                    }
                    WaitStatus::PtraceEvent(child_pid, signal, e) => {
                        // println!("[PARENT]: PtraceEvent other {child_pid:?}, {signal:?}, {e:?}");
                        ptrace::syscall(child_pid, None)?; // allow child to continue
                    }
                    WaitStatus::Exited(pid, _) => {
                        // println!("[PARENT]: Child {pid} exited");
                        if !traced_pids.remove(&pid) {
                            // println!(
                            //     "[PARENT]: Disaster!  Exited({pid}) but that pid was not in traced_pids!"
                            // );
                        }
                        if pid == original_child {
                            // println!("[PARENT]: original child exited; remaining pids are {traced_pids:?}");
                            break;
                        }
                        if traced_pids.is_empty() {
                            break;
                        }
                    }
                    WaitStatus::PtraceSyscall(pid) => {
                        // let entry = in_syscall.entry(pid);
                        // let pid_in_syscall = entry.or_insert(false); // in_syscall.get(&pid).unwrap_or(&false);

                        // if !*pid_in_syscall {
                        //     // Get the syscall number from the registers
                        //     let regs = ptrace::getregs(pid)?;
                        //     // println!("[PARENT]: Syscall began in pid {pid:?}: {}", regs.orig_rax);
                        //     *pid_in_syscall = true;
                        //     // [A more complete strace would know which arguments are pointers and use
                        //     // process_vm_readv(2) to read those buffers from the tracee in order to print them
                        //     // appropriately.]
                        // } else {
                        //     let regs = ptrace::getregs(pid)?;
                        //     // println!("[PARENT]: Syscall finished in pid {pid:?}: = {}", regs.rax);
                        //     *pid_in_syscall = false;
                        // }

                        // Restart the child and stop at the next syscall
                        ptrace::syscall(pid, None)?;
                    }
                    WaitStatus::Stopped(pid, signal) => {
                        // println!("[PARENT]: stopped received {pid:?} w/ signal {signal:?}");
                        if signal == Signal::SIGTRAP {
                            // FIXME: cloning lurk's logic without understanding
                            ptrace::syscall(pid, None)?;
                        } else if signal == Signal::SIGSTOP {
                            // FIXME: cloning lurk's logic without understanding
                            ptrace::syscall(pid, None)?;
                        } else if signal == Signal::SIGCHLD {
                            // FIXME: cloning lurk's logic without understanding
                            ptrace::syscall(pid, Some(signal))?;
                        } else {
                            ptrace::cont(pid, signal)?;
                        }
                    }
                    other => {
                        // println!("[PARENT]: wait received {other:?}");
                    }
                }
            }

            // // Continue the child process
            // ptrace::cont(child, None)?;

            /*
            Performance notes, running the "go-micro-app" which reads all files in the CWD:
            on testtrim directory:
            raw:
            3.483
            2.852
            3.416

            rust ptrace v1:
            8.208
            7.980
            8.505

            strace:
            6.468
            6.262
            6.173

            // This is disappointing... and this has all println!() removed... so I'm not sure what possible difference
            // in performance there is here that degrades when compared to strace. :-(  This needs to be at least in the
            // same range before this is even feasible.

            */

            // // Wait for child to finish
            // let _ = wait()?;
            println!("[PARENT]: All child processes completed");

            reader_thread.join().unwrap();
        }
        ForkResult::Child => {
            // Close read end in child
            drop(read_fd);
            // Duplicate write_fd to stdout
            // if write_fd != 1 {
            // 1 is stdout
            nix::unistd::dup2(write_fd.as_raw_fd(), 1)?; // stdout
            nix::unistd::dup2(write_fd.as_raw_fd(), 2)?; // stderr
            // close(write_fd)?;
            // }

            println!("[CHILD]: Child started");
            // Tell parent we're ready to be traced
            ptrace::traceme()?;
            println!("[CHILD]: Child invoked traceme");

            // Execute a test command
            return Err(Command::new("/home/mfenniak/Dev/testtrim-test-projects/go-micro-app/go-micro-app").arg("--version").exec().into());
            // // We won't reach here as exec replaces the process
            // unreachable!();
        }
    }

    Ok(())
}
