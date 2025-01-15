// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    env,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::Result;
use tempdir::TempDir;
use testtrim::sys_trace::{
    SysTraceCommand as _, SysTraceCommandDispatch,
    strace::STraceSysTraceCommand,
    trace::{Trace, UnifiedSocketAddr},
};
use tokio::process::Command;

fn get_test_binary() -> PathBuf {
    // When running tests, CARGO_BIN_EXE_testtrim-syscall-test-app will be set to the path of the binary
    let env_var_name = "CARGO_BIN_EXE_testtrim-syscall-test-app";
    if let Ok(path) = std::env::var(env_var_name) {
        return PathBuf::from(path);
    }

    // Fallback: construct the path manually (useful for IDE testing)
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let target_dir = Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("testtrim-syscall-test-app");

    if !target_dir.exists() {
        panic!(
            "Test binary not found. First attempt was {:?}, fallback was {:?}",
            std::env::var(env_var_name),
            target_dir,
        );
    }

    target_dir
}

async fn run_test_binary(trace_command: &SysTraceCommandDispatch, arg: &str) -> Result<Trace> {
    let tmp_dir = TempDir::new("testtrim-test")?;
    let trace_file = tmp_dir.path().join(format!("test_{}.trace", arg));
    let mut cmd = Command::new(get_test_binary());
    cmd.arg(arg);
    let cwd = env::current_dir()?;
    let repo_root = cwd.parent().unwrap(); // Run app in `testtrim` root for consistent path access
    println!(
        "will run testtrim-syscall-test-app in the working directory: {:?}",
        repo_root
    );
    cmd.current_dir(repo_root);
    let (output, trace) = trace_command.trace_command(cmd, &trace_file).await?;
    if !output.status.success() {
        panic!("failed to run subcommand: {output:?}");
    }
    Ok(trace)
}

async fn test_noop(trace_command: &SysTraceCommandDispatch) -> Result<()> {
    let trace = run_test_binary(trace_command, "noop").await?;

    // Not many assertions for the `noop` arg, of course:
    // Local testing shows access to libgcc_s.so.1, libc.so.6, and /proc/self/maps
    for path in trace.get_open_paths() {
        println!("open path: {path:?}");
    }
    assert!(
        !trace.get_open_paths().is_empty(),
        "expect at least some file was accessed"
    );
    for socket in trace.get_connect_sockets() {
        println!("open socket: {socket:?}");
    }
    assert!(
        trace.get_connect_sockets().is_empty(),
        "expect no socket access"
    );

    Ok(())
}

#[tokio::test]
async fn test_noop_strace() -> Result<()> {
    test_noop(&STraceSysTraceCommand::new().into()).await
}

fn has_relative_path(open_paths: &HashSet<PathBuf>, filename: &str) -> bool {
    let path = Path::new(filename);
    if open_paths.contains(path) {
        return true;
    }
    // On some systems, running the testtrim-syscall-test-app app will result in strace capturing a chdir() to the
    // working directory of the process with a fully-qualified path, then an execve.  In this case, the strace module
    // will capture all the open calls and make them relative to the chdir, making them fully-qualified.  This is
    // technically correct, and those paths could be fully qualified and sitll be valid syscall traces.  So we inspect
    // all the paths looking for anything where, if we strip the repo root, it's the path we're looking for.  It would
    // be ideal of the syscall tracing output was a little more consistent, but both relative and absolute path accesses
    // are completely valid syscalls so normalizing them at the syscall trace layer doesn't seem like the right thing to
    // do.
    let cwd = env::current_dir().unwrap();
    let repo_root = cwd.parent().unwrap();
    open_paths.iter().any(|p| {
        p.strip_prefix(repo_root)
            .map(|suffix| suffix == path)
            .unwrap_or(false)
    })
}

async fn test_access_files(trace_command: &SysTraceCommandDispatch) -> Result<()> {
    let trace = run_test_binary(trace_command, "access-files").await?;

    for path in trace.get_open_paths() {
        println!("open path: {path:?}");
    }
    assert!(has_relative_path(
        trace.get_open_paths(),
        "testtrim-syscall-test-app/test-file-1.txt"
    ));
    assert!(has_relative_path(
        trace.get_open_paths(),
        "testtrim-syscall-test-app/test-file-2.txt"
    ));
    // FIXME: Accessing relative paths from an open directory is not currently supported by our strace implementation --
    // https://codeberg.org/testtrim/testtrim/issues/132
    // assert!(has_relative_path(
    //     trace.get_open_paths(),
    //     "testtrim-syscall-test-app/test-file-3.txt"
    // ));
    assert!(has_relative_path(
        trace.get_open_paths(),
        "testtrim-syscall-test-app/test-file-4.txt"
    ));

    assert!(
        trace.get_connect_sockets().is_empty(),
        "expect no socket access"
    );

    Ok(())
}

#[tokio::test]
async fn test_access_files_strace() -> Result<()> {
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Trace, simplelog::Config::default())
        .expect("must config logging");
    test_access_files(&STraceSysTraceCommand::new().into()).await
}

async fn test_access_files_chdir_inherit(trace_command: &SysTraceCommandDispatch) -> Result<()> {
    let trace = run_test_binary(trace_command, "access-files-with-inherited-chdir").await?;

    for path in trace.get_open_paths() {
        println!("open path: {path:?}");
    }
    assert!(has_relative_path(
        trace.get_open_paths(),
        "testtrim-syscall-test-app/test-file-1.txt"
    ));
    assert!(has_relative_path(
        trace.get_open_paths(),
        "testtrim-syscall-test-app/test-file-2.txt"
    ));
    // FIXME: Changing working directory in a thread is not currently supported by our strace implementation --
    // https://codeberg.org/testtrim/testtrim/issues/287
    // assert!(has_relative_path(
    //     trace.get_open_paths(),
    //     "testtrim-syscall-test-app/test-file-3.txt"
    // ));

    assert!(
        trace.get_connect_sockets().is_empty(),
        "expect no socket access"
    );

    Ok(())
}

#[tokio::test]
async fn test_access_files_chdir_inherit_strace() -> Result<()> {
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Trace, simplelog::Config::default())
        .expect("must config logging");
    test_access_files_chdir_inherit(&STraceSysTraceCommand::new().into()).await
}

async fn test_access_network(trace_command: &SysTraceCommandDispatch) -> Result<()> {
    let trace = run_test_binary(trace_command, "access-network").await?;

    for socket in trace.get_connect_sockets() {
        println!("open socket: {socket:?}");
    }

    assert!(trace.get_connect_sockets().iter().any(|s| match s.address {
        UnifiedSocketAddr::Inet(SocketAddr::V4(sock_addr)) =>
            sock_addr.ip() == &Ipv4Addr::new(127, 0, 0, 1) && sock_addr.port() == 9999,
        _ => false,
    } && s.hostnames.contains("localhost")));

    assert!(trace.get_connect_sockets().iter().any(|s| match s.address {
        UnifiedSocketAddr::Inet(SocketAddr::V6(sock_addr)) =>
            sock_addr.ip() == &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1) && sock_addr.port() == 9999,
        _ => false,
    } && s.hostnames.contains("localhost")));

    assert!(trace.get_connect_sockets().iter().any(|s| match s.address {
        UnifiedSocketAddr::Inet(SocketAddr::V4(sock_addr)) => sock_addr.port() == 80,
        UnifiedSocketAddr::Inet(SocketAddr::V6(sock_addr)) => sock_addr.port() == 80,
        _ => false,
    } && s.hostnames.contains("example.com")));

    assert!(
        trace
            .get_connect_sockets()
            .iter()
            .any(|s| match &s.address {
                UnifiedSocketAddr::Unix(path) => *path == PathBuf::from("/tmp/test.sock"),
                _ => false,
            })
    );

    Ok(())
}

#[tokio::test]
async fn test_access_network_strace() -> Result<()> {
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Trace, simplelog::Config::default())
        .expect("must config logging");
    test_access_network(&STraceSysTraceCommand::new().into()).await
}
