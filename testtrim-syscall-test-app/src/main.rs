// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs::File,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    thread::{self},
    time::Duration,
};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Temporary no-operation command
    Noop,

    /// Access files with a small variety of different syscalls.
    AccessFiles,

    /// Access files with relative paths, from subprocesses with inherited working-directories from the parent process.
    AccessFilesWithInheritedChdir,

    /// Access a variety of network addresses, including with DNS resolution.
    AccessNetwork,

    /// Access network resources while free-threading and sharing the network sockets; intended to exercise DNS
    /// resolution cases documented in https://codeberg.org/testtrim/testtrim/issues/234, but in short, where the
    /// address of a socket is identifiable only in tracing on one thread, and the network traffic is identified on
    /// another thread, requiring understanding of shared thread file-descriptors and context.
    AccessNetworkMultithreaded,
}

/// This application exists to be a syscall tracing target for testtrim's internal tests.  It performs work in a small
/// variety of different modes which testtrim's tests will exercise under syscall tracing, and verify that the tracing
/// results are as-expected.
fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Noop => {}
        Commands::AccessFiles => access_files().expect("access_files"),
        Commands::AccessFilesWithInheritedChdir => {
            access_files_inherited().expect("access_files_inherited")
        }
        Commands::AccessNetwork => access_network().expect("access_network"),
        Commands::AccessNetworkMultithreaded => todo!(),
    }
}

/// Accesses test files with slight syscall tweaks.
///
/// - test-file-1.txt - straightforward Rust file access
/// - test-file-2.txt - lower-level or alternate syscall
/// - test-file-3.txt - open a parent directory, open file relative to parent (FIXME: not supported by strace syscall
///   tracing; maybe this should be a different disabled test case?)
/// - test-file-4.txt - change working directory, access via relative path to new working dir
fn access_files() -> Result<(), std::io::Error> {
    {
        // Linux: openat(AT_FDCWD, "testtrim-syscall-test-app/test-file-1.txt", O_RDONLY|O_CLOEXEC) = 3
        let _f = File::open("testtrim-syscall-test-app/test-file-1.txt")?;
    }

    {
        // Linux: openat(AT_FDCWD, "testtrim-syscall-test-app/test-file-2.txt", O_RDONLY) = 3
        let fd = nix::fcntl::open(
            "testtrim-syscall-test-app/test-file-2.txt",
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::S_IRUSR,
        )?;
        nix::unistd::close(fd)?;
    }

    {
        // Linux:
        // openat(AT_FDCWD, "testtrim-syscall-test-app/", O_RDONLY) = 3
        // openat(3, "test-file-3.txt", O_RDONLY)  = 4
        let dirfd = nix::fcntl::open(
            "testtrim-syscall-test-app/",
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::S_IRUSR,
        )?;
        let fd = nix::fcntl::openat(
            Some(dirfd),
            "test-file-3.txt",
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::S_IRUSR,
        )?;
        nix::unistd::close(fd)?;
        nix::unistd::close(dirfd)?;
    }

    {
        // Linux:
        // openat(AT_FDCWD, "testtrim-syscall-test-app/", O_RDONLY) = 3
        // openat(3, "test-file-3.txt", O_RDONLY)  = 4
        let dirfd = nix::fcntl::open(
            "testtrim-syscall-test-app/",
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::S_IRUSR,
        )?;
        let fd = nix::fcntl::openat(
            Some(dirfd),
            "test-file-3.txt",
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::S_IRUSR,
        )?;
        nix::unistd::close(fd)?;
        nix::unistd::close(dirfd)?;
    }

    {
        // Linux:
        // chdir("testtrim-syscall-test-app")      = 0
        // openat(AT_FDCWD, "test-file-4.txt", O_RDONLY|O_CLOEXEC) = 3
        // chdir("../")
        std::env::set_current_dir("testtrim-syscall-test-app")?;
        let _f = File::open("test-file-4.txt")?;
        std::env::set_current_dir("../")?;
    }

    Ok(())
}

/// Accesses test files with subprocesses that have inherited the CWD from the parent process.
///
/// - test-file-1.txt - accessed w/ subprocess that inherited parent's CWD, but same CWD as this process was started
///   with.
/// - test-file-2.txt - accessed w/ subprocess after this process's CWD was changed.
/// - test-file-3.txt - accessed from a spawned thread, where the process CWD has changed in a different thread and the
///   shared-state of the CWD must be understood. (FIXME: not supported by strace syscall tracing; maybe this should be
///   a different disabled test case?)
fn access_files_inherited() -> Result<(), std::io::Error> {
    // test-file-1.txt
    {
        let (read_fd, write_fd) = nix::unistd::pipe()?;
        match unsafe { nix::unistd::fork()? } {
            nix::unistd::ForkResult::Parent { child: _ } => {
                // Wait for child to write to the pipe indicating its work is done.
                drop(write_fd);
                let mut buf = [0u8; 1];
                let mut read_file = File::from(read_fd);
                loop {
                    let bytes_read = read_file.read(&mut buf).unwrap();
                    if bytes_read != 0 {
                        break;
                    }
                }
                drop(read_file);
            }
            nix::unistd::ForkResult::Child => {
                // Do work in child.
                let _f = File::open("testtrim-syscall-test-app/test-file-1.txt")?;
                drop(_f);

                // Signal parent that it can complete.
                drop(read_fd);
                let buf = [0u8; 1];
                let mut write_file = File::from(write_fd);
                loop {
                    let bytes_written = write_file.write(&buf)?;
                    if bytes_written != 0 {
                        break;
                    }
                }
                drop(write_file);
            }
        }
    }

    // test-file-2.txt
    {
        std::env::set_current_dir("testtrim-syscall-test-app")?;
        let (read_fd, write_fd) = nix::unistd::pipe()?;
        match unsafe { nix::unistd::fork()? } {
            nix::unistd::ForkResult::Parent { child: _ } => {
                // Wait for child to write to the pipe indicating its work is done.
                drop(write_fd);
                let mut buf = [0u8; 1];
                let mut read_file = File::from(read_fd);
                loop {
                    let bytes_read = read_file.read(&mut buf).unwrap();
                    if bytes_read != 0 {
                        break;
                    }
                }
                drop(read_file);
            }
            nix::unistd::ForkResult::Child => {
                // Do work in child.
                let _f = File::open("test-file-2.txt")?;
                drop(_f);

                // Signal parent that it can complete.
                drop(read_fd);
                let buf = [0u8; 1];
                let mut write_file = File::from(write_fd);
                loop {
                    let bytes_written = write_file.write(&buf)?;
                    if bytes_written != 0 {
                        break;
                    }
                }
                drop(write_file);
            }
        }
        std::env::set_current_dir("../")?;
    }

    // test-file-3.txt
    {
        // Even though this CWD happens in thread, CWD state should be shared between threads:
        thread::spawn(|| std::env::set_current_dir("testtrim-syscall-test-app").unwrap())
            .join()
            .unwrap();
        let _f = File::open("test-file-3.txt")?;
        std::env::set_current_dir("../")?;
    }

    Ok(())
}

/// Accesses network addresses, including with DNS resolution.
///
/// - 127.0.0.1:9999
/// - `[::1]:9999`
/// - /tmp/test.sock
/// - example.com:80
///
/// In all these cases we don't care about successful network access.  But we do care about successful DNS resolution
/// for example.com.
fn access_network() -> Result<(), std::io::Error> {
    // TCP connection to localhost - direct IPv4 address
    let _ = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], 9999)),
        Duration::from_millis(100),
    );

    // TCP connection to localhost - direct IPv6 address
    let _ = TcpStream::connect_timeout(
        &SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 9999)),
        Duration::from_millis(100),
    );

    // Unix domain socket attempt
    let _ = std::os::unix::net::UnixStream::connect("/tmp/test.sock");

    // DNS resolution + connection attempt
    let _ = TcpStream::connect("example.com:80");

    Ok(())
}
