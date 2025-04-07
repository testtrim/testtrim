// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use enum_dispatch::enum_dispatch;
use log::warn;
use std::{path::Path, process::Output, sync::LazyLock};
#[cfg(target_os = "linux")]
use strace::STraceSysTraceCommand;
use tokio::process::Command;
use trace::{DraftTrace, Trace};

use crate::errors::SubcommandErrors;

#[cfg(target_os = "linux")]
pub mod strace;
pub mod trace;

/// Allows execution of a command in a manner that traces relevant system calls and provides access to the trace for
/// analysis.
#[enum_dispatch]
#[allow(async_fn_in_trait)] // should be fine to the extent that this is only used internally to this project
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
        Ok((
            cmd.output()
                .await
                .map_err(|e| SubcommandErrors::UnableToStart {
                    command: format!("{:?} ...", cmd.as_std().get_program()).to_string(),
                    error: e,
                })?,
            DraftTrace::new()
                .try_into()
                .expect("empty DraftTrace->Trace should be infallible"),
        ))
    }
}

#[enum_dispatch(SysTraceCommand)]
pub enum SysTraceCommandDispatch {
    SysTraceCommandUnsupported,
    #[cfg(target_os = "linux")]
    STraceSysTraceCommand,
}

pub static SYS_TRACE_COMMAND: LazyLock<SysTraceCommandDispatch> = LazyLock::new(get_trace_command);

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
