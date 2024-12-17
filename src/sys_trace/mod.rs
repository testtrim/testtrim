// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use enum_dispatch::enum_dispatch;
use lazy_static::lazy_static;
use log::warn;
use std::{path::Path, process::Output};
#[cfg(target_os = "linux")]
use strace::STraceSysTraceCommand;
use tokio::process::Command;
use trace::Trace;

#[cfg(target_os = "linux")]
mod strace;
pub mod trace;

/// Allows execution of a command in a manner that traces relevant system calls and provides access to the trace for
/// analysis.
#[enum_dispatch]
pub trait SysTraceCommand {
    /// Run the command `cmd` under syscall tracing, utilizing the file path `tmp` as temporary storage if necessary.
    ///
    /// The caller will cleanup `tmp`.  It is questionable for it to be managed externally, but allows for more
    /// contextual information about the temp storage path which is useful for testing and diagnostics.
    async fn trace_command(&self, cmd: Command, tmp: &Path) -> Result<(Output, Trace)>;
}

pub struct SysTraceCommandUnsupported;

impl SysTraceCommand for SysTraceCommandUnsupported {
    async fn trace_command(&self, mut cmd: Command, _tmp: &Path) -> Result<(Output, Trace)> {
        Ok((cmd.output().await?, Trace::new()))
    }
}

#[enum_dispatch(SysTraceCommand)]
pub enum SysTraceCommandDispatch {
    SysTraceCommandUnsupported,
    #[cfg(target_os = "linux")]
    STraceSysTraceCommand,
}

lazy_static! {
    pub static ref sys_trace_command: SysTraceCommandDispatch = get_trace_command();
}

#[cfg(target_os = "linux")]
fn get_trace_command() -> SysTraceCommandDispatch {
    if STraceSysTraceCommand::is_available() {
        STraceSysTraceCommand::new().into()
    } else {
        warn!("syscall tracing not supported; unable to `strace` on this Linux system");
        SysTraceCommandUnsupported {}.into()
    }
}

#[cfg(not(target_os = "linux"))]
fn get_trace_command() -> SysTraceCommandDispatch {
    warn!("syscall tracing only supported on Linux at the moment");
    SysTraceCommandUnsupported {}.into()
}
