// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use lazy_static::lazy_static;
use log::warn;
use std::{
    path::Path,
    process::{Command, Output},
};
use trace::Trace;

mod strace;
pub mod trace;

/// Allows execution of a command in a manner that traces relevant system calls and provides access to the trace for
/// analysis.
pub trait SysTraceCommand {
    /// Run the command `cmd` under syscall tracing, utilizing the file path `tmp` as temporary storage if necessary.
    ///
    /// The caller will cleanup `tmp`.  It is questionable for it to be managed externally, but allows for more
    /// contextual information about the temp storage path which is useful for testing and diagnostics.
    fn trace_command(&self, cmd: Command, tmp: &Path) -> Result<(Output, Trace)>;
}

struct SysTraceCommandUnsupported;

impl SysTraceCommand for SysTraceCommandUnsupported {
    fn trace_command(&self, mut cmd: Command, _tmp: &Path) -> Result<(Output, Trace)> {
        Ok((cmd.output()?, Trace::new()))
    }
}

lazy_static! {
    pub static ref sys_trace_command: Box<dyn SysTraceCommand + Send + Sync> = get_trace_command();
}

#[cfg(target_os = "linux")]
fn get_trace_command() -> Box<dyn SysTraceCommand + Send + Sync> {
    use strace::STraceSysTraceCommand;

    if STraceSysTraceCommand::is_available() {
        Box::new(STraceSysTraceCommand::new())
    } else {
        warn!("syscall tracing not supported; unable to `strace` on this Linux system");
        Box::new(SysTraceCommandUnsupported {})
    }
}

#[cfg(not(target_os = "linux"))]
fn get_trace_command() -> Box<dyn SysTraceCommand + Send + Sync> {
    warn!("syscall tracing only supported on Linux at the moment");
    Box::new(SysTraceCommandUnsupported {})
}
