// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use log::debug;

use crate::sys_trace::strace::funcs::Function;

use super::funcs::{FunctionExtractor, FunctionExtractorOutput, FunctionTrace};

/// `ProcSynchronizer` is a layer above the `FunctionExtractor` which ensures that the results of process-creation
/// syscalls (Clone) are processed before any syscalls that occur from within those processes.
///
/// For example, we can get a series of syscalls like this:
///
/// - `25979 clone3([snip] <unfinished ...>`
/// - `26006 (some random syscall as process 26006 starts...)`
/// - `25979 <... clone3 resumed> => {parent_tid=[26006]}, 88) = 26006`
///
/// The parent process is starting a thread or subprocess, but there's no guarantee that the syscall with that PID is
/// returned to the parent *before* the new child (26006) starts to execute.  This would prevent any syscalls from the
/// child from being processed with the right context that should be inherited from the parent -- for example, its
/// working directory.
///
/// To workaround this:
/// - Keep a `HashSet` of all the pids that we are tracing.
/// - If we receive a syscall with a pid that isn't in the `HashSet`, store it in a temporary buffer.
/// - When we receive a Clone response, after performing the clone handling, flush that buffer for any pids that are now
///   registered and process those syscalls.
///
/// This technically reorders syscalls in a way that might affect order-specific issues in the future... but since it
/// should only happen for pids that are returned from a clone shortly, I think it should be safe.
pub struct ProcSynchronizer {
    extractor: FunctionExtractor,
    primed: bool,
    known_pids: HashSet<i32>,
    suppressed: HashMap<i32, Vec<FunctionExtractorOutput>>,
}

impl ProcSynchronizer {
    #[must_use]
    pub fn new() -> Self {
        ProcSynchronizer {
            extractor: FunctionExtractor::new(),
            primed: false,
            known_pids: HashSet::new(),
            suppressed: HashMap::new(),
        }
    }

    /// Typically returns one event, but can return 0 if a trace line is suppressed waiting for a clone response, or
    /// multiple after a clone response is received and suppressed lines are released.
    pub fn extract(&mut self, input: String) -> Result<Vec<FunctionExtractorOutput>> {
        let output = self.extractor.extract(input)?;

        let Some(function_trace) = output.borrow_function_trace() else {
            return Ok(vec![output]);
        };

        match function_trace {
            FunctionTrace::Function { pid, function } => {
                if !self.primed {
                    self.known_pids.insert(*pid);
                    self.primed = true;
                }

                if !self.known_pids.contains(pid) {
                    // Received a function call from a process that we don't recognize; store for later release.
                    debug!("suppressing syscall: {output:?}");
                    self.suppressed.entry(*pid).or_default().push(output);
                    return Ok(vec![]);
                }

                if let Function::Clone { child_pid, .. } = function {
                    // FIXME: may be a bug here, if the child process exits before the clone resumes in the parent
                    // process.  We'd get a FunctionTrace::Exit and we'd remove the known pid, but then we'd re-add it
                    // here... but when since we already processed the child exit we're not expecting any more syscalls
                    // from it unless the pid is reused, which would be exceedingly unlikely.
                    self.known_pids.insert(*child_pid);

                    let suppressed = self.suppressed.remove(child_pid);
                    let mut retval = vec![output];
                    if let Some(suppressed) = suppressed {
                        debug!("releasing {} suppressed syscalls", suppressed.len());
                        retval.extend(suppressed);
                    }
                    Ok(retval)
                } else {
                    Ok(vec![output])
                }
            }
            FunctionTrace::Exit { pid } => {
                self.known_pids.remove(pid);
                Ok(vec![output])
            }
            FunctionTrace::ExitThreadGroup { pid: _ } => {
                // FIXME: probably ideal to cleanup known_pids here, but we don't know the pids that are relevant unless
                // we moved thread group tracking here.  It isn't really important to cleanup ProcSynchronizer's state
                // unless pids are reused though.
                Ok(vec![output])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::sys_trace::strace::funcs::{Function, FunctionTrace};

    use super::ProcSynchronizer;

    #[test]
    fn passthrough() -> Result<()> {
        let mut fe = ProcSynchronizer::new();

        let t = fe.extract(String::from(r"1234321 close(3)                        = 0"))?;
        assert_eq!(t.len(), 1);
        let t = &t[0];
        assert_eq!(
            t.borrow_function_trace(),
            &Some(FunctionTrace::Function {
                pid: 1_234_321,
                function: Function::Close { fd: "3" }
            })
        );

        Ok(())
    }

    #[test]
    fn clone_emitted() -> Result<()> {
        let mut fe = ProcSynchronizer::new();

        // Allow sequencer to recognize 15615 as an active pid (automatic for first trace response)
        let t = fe.extract(String::from(r"15615 close(3)                        = 0"))?;
        assert_eq!(t.len(), 1);

        let t = fe.extract(String::from(r"15615 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f67099ff990, parent_tid=0x7f67099ff990, exit_signal=0, stack=0x7f67091ff000, stack_size=0x7fff80, tls=0x7f67099ff6c0} => {parent_tid=[0]}, 88) = 15620"))?;
        assert_eq!(t.len(), 1);

        let t = fe.extract(String::from(r"15620 close(3)                        = 0"))?;
        // This syscall should be emitted since 15620 was noted in the previous clone
        assert_eq!(t.len(), 1);

        Ok(())
    }

    #[test]
    fn clone_incomplete() -> Result<()> {
        let mut fe = ProcSynchronizer::new();

        // Allow sequencer to recognize 15615 as an active pid (automatic for first trace response)
        let t = fe.extract(String::from(r"15615 close(3)                        = 0"))?;
        assert_eq!(t.len(), 1);

        let t = fe.extract(String::from(r"15615 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f67099ff990, parent_tid=0x7f67099ff990, exit_signal=0, stack=0x7f67091ff000, stack_size=0x7fff80, tls=0x7f67099ff6c0} <unfinished ...>"))?;
        assert_eq!(t.len(), 1);

        let t = fe.extract(String::from(r"15620 close(3)                        = 0"))?;
        // This syscall should be suppressed since we haven't returned child pid 15620 from clone3 yet...
        assert_eq!(t.len(), 0);

        let t = fe.extract(String::from(
            r"15615 <... clone3 resumed> => {parent_tid=[0]}, 88) = 15620",
        ))?;
        assert_eq!(t.len(), 2);
        let syscall = &t[0];
        assert_eq!(
            syscall.borrow_function_trace(),
            &Some(FunctionTrace::Function {
                pid: 15615,
                function: Function::Clone {
                    child_pid: 15620,
                    thread: true
                }
            })
        );
        let syscall = &t[1];
        assert_eq!(
            syscall.borrow_function_trace(),
            &Some(FunctionTrace::Function {
                pid: 15620,
                function: Function::Close { fd: "3" }
            })
        );

        Ok(())
    }
}
