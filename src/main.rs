// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{os::fd::AsRawFd as _, process::ExitCode};

use anyhow::Result;
use nix::libc::PTRACE_O_EXITKILL;
use testtrim::cmd::cli::run_cli;

// #[tokio::main]
// async fn main() -> ExitCode {
//     run_cli().await
// }



// #[test]
fn main() -> Result<()> {
    use nix::sys::ptrace;
    use nix::sys::wait::{wait, WaitStatus};
    use nix::unistd::{close, fork, pipe, read, ForkResult};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let (read_fd, write_fd) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("[PARENT]: Parent process tracing child PID: {}", child);

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
            ptrace::setoptions(child, ptrace::Options::PTRACE_O_EXITKILL)?;

            // // Wait for child to be ready for tracing
            // match wait()? {
            //     WaitStatus::Stopped(_, _) => {
            //         println!("[PARENT]: Child stopped and ready for tracing");
            //     }
            //     _ => panic!("Unexpected wait status"),
            // }

            let mut in_syscall = false;

            // Main tracing loop
            loop {
                // Restart the child and stop at the next syscall
                ptrace::syscall(child, None)?;

                match wait()? {
                    WaitStatus::Exited(_, _) => {
                        println!("[PARENT]: Child exited");
                        break;
                    }
                    WaitStatus::Stopped(pid, _signal) => {
                        if !in_syscall {
                            // Get the syscall number from the registers
                            let regs = ptrace::getregs(pid)?;
                            println!("[PARENT]: Syscall began: {}", regs.orig_rax);
                            in_syscall = true;

                            // [A more complete strace would know which arguments are pointers and use
                            // process_vm_readv(2) to read those buffers from the tracee in order to print them
                            // appropriately.]
                        } else {
                            let regs = ptrace::getregs(pid)?;
                            println!("[PARENT] Syscall finished: = {}", regs.rax);
                            in_syscall = false;
                        }
                    }
                    other => {
                        println!("[PARENT]: wait received {other:?}");
                    }
                }
            }

            // // Continue the child process
            // ptrace::cont(child, None)?;

            // // Wait for child to finish
            // let _ = wait()?;
            println!("[PARENT]: Child process completed");

            reader_thread.join().unwrap();
        }
        ForkResult::Child => {
            // Close read end in child
            drop(read_fd);
            // Duplicate write_fd to stdout
            // if write_fd != 1 {
            // 1 is stdout
            nix::unistd::dup2(write_fd.as_raw_fd(), 1)?;
            // close(write_fd)?;
            // }

            println!("[CHILD]: Child started");
            // Tell parent we're ready to be traced
            ptrace::traceme()?;
            println!("[CHILD]: Child invoked traceme");

            // Execute a test command
            return Err(Command::new("echo")
                .arg("Hello from traced process!")
                .exec()
                .into());
            // // We won't reach here as exec replaces the process
            // unreachable!();
        }
    }

    Ok(())
}
