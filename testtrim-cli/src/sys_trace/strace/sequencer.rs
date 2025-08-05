// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Can't attach this specifically to the `TwolineSyscall` struct because the relevant field is part of the macro output.
#![allow(clippy::ref_option)]

use std::collections::HashMap;

use anyhow::Result;
use ouroboros::self_referencing;

use super::tokenizer::{
    Argument, CallOutcome, ProcessExit, Retval, SyscallSegment, TokenizerOutput, tokenize,
};

#[self_referencing]
#[derive(Debug, PartialEq)]
pub struct TraceLine {
    pub input: String,
    #[borrows(input)]
    #[covariant]
    pub output: TokenizerOutput<'this>,
}

#[self_referencing]
#[derive(Debug, PartialEq)]
pub struct TraceLineProcessExit {
    trace_line: TraceLine,
    #[borrows(trace_line)]
    #[covariant]
    process_exit: &'this ProcessExit<'this>,
}

impl TraceLineProcessExit {
    fn make(trace_line: TraceLine) -> Self {
        TraceLineProcessExit::new(trace_line, |trace_line| match trace_line.borrow_output() {
            TokenizerOutput::Exit(process_exit) => process_exit,
            _ => panic!(
                "TraceLineProcessExit must be constructed with a TokenizerOutput::Exit, but was: {trace_line:?}"
            ),
        })
    }

    pub fn pid(&self) -> &str {
        self.borrow_process_exit().pid
    }
}

pub trait DebugOriginalTraceOutput {
    fn original_trace_output(&self) -> String;
}

pub trait CompleteSyscall: DebugOriginalTraceOutput {
    fn pid(&self) -> &str;
    fn function(&self) -> &str;
    fn arguments(&self) -> &Vec<&Argument<'_>>;
    fn retval(&self) -> &Retval<'_>;
}

#[self_referencing]
#[derive(Debug, PartialEq)]
pub struct OnelineSyscall {
    pub complete: TraceLine,
    #[borrows(complete)]
    #[covariant]
    arguments: Vec<&'this Argument<'this>>,
}

impl OnelineSyscall {
    fn make(complete: TraceLine) -> Self {
        OnelineSyscall::new(complete, |complete| match complete.borrow_output() {
            TokenizerOutput::Syscall(SyscallSegment {
                arguments,
                outcome: CallOutcome::Complete { .. },
                ..
            }) => {
                let mut ret = Vec::with_capacity(arguments.len());
                for a in arguments {
                    ret.push(a);
                }
                ret
            }
            _ => panic!(
                "OnelineSyscall must be constructored with a Complete SyscallSegment, but was: {complete:?}"
            ),
        })
    }
}

impl DebugOriginalTraceOutput for OnelineSyscall {
    fn original_trace_output(&self) -> String {
        self.borrow_complete().borrow_input().clone()
    }
}

impl CompleteSyscall for OnelineSyscall {
    fn pid(&self) -> &str {
        self.borrow_complete().with_output(|tokenizer_output| match tokenizer_output {
            TokenizerOutput::Syscall(SyscallSegment {
                pid,
                outcome: CallOutcome::Complete { .. },
                ..
            }) => pid,
            _ => panic!("OnelineSyscall should never be constructed with tokenizer output that isn't a complete syscall; but was: {tokenizer_output:?}"),
        })
    }

    fn function(&self) -> &str {
        self.borrow_complete().with_output(|tokenizer_output| match tokenizer_output {
            TokenizerOutput::Syscall(SyscallSegment {
                function,
                outcome: CallOutcome::Complete { .. },
                ..
            }) => function,
            _ => panic!("OnelineSyscall should never be constructed with tokenizer output that isn't a complete syscall; but was: {tokenizer_output:?}"),
        })
    }

    fn arguments(&self) -> &Vec<&Argument<'_>> {
        self.borrow_arguments()
    }

    fn retval(&self) -> &Retval<'_> {
        self.borrow_complete().with_output(|tokenizer_output| match tokenizer_output {
            TokenizerOutput::Syscall(SyscallSegment {
                outcome: CallOutcome::Complete { retval },
                ..
            }) => retval,
            _ => panic!("OnelineSyscall should never be constructed with tokenizer output that isn't a complete syscall; but was: {tokenizer_output:?}"),
        })
    }
}

#[self_referencing]
#[derive(Debug, PartialEq)]
pub struct TwolineSyscall {
    unfinished: TraceLine,
    resumed: TraceLine,
    #[borrows(unfinished, resumed)]
    #[covariant]
    written_structure: Option<Argument<'this>>,
    #[borrows(unfinished, resumed, written_structure)]
    #[covariant]
    arguments: Vec<&'this Argument<'this>>,
}

impl TwolineSyscall {
    fn make(unfinished: TraceLine, resumed: TraceLine) -> Self {
        TwolineSyscall::new(
            unfinished,
            resumed,
            // written_structure is populated as Some(x) when the first argument in the "resumed" syscall is a write
            // argument (eg. "=> {..}"). In this case we create our own owned Argument, referencing the two original
            // structures, which we'll put into `arguments` later in place of the two partial arguments.
            |unfinished, resumed| match (unfinished.borrow_output(), resumed.borrow_output()) {
                (
                    TokenizerOutput::Syscall(SyscallSegment {
                        arguments: first_arguments,
                        outcome: CallOutcome::Unfinished,
                        ..
                    }),
                    TokenizerOutput::Syscall(SyscallSegment {
                        arguments: second_arguments,
                        outcome: CallOutcome::Resumed { .. },
                        ..
                    }),
                ) => {
                    if first_arguments.is_empty() || second_arguments.is_empty() {
                        return None;
                    }
                    match (first_arguments.last(), second_arguments.first()) {
                        (Some(original), Some(Argument::WrittenArgumentResumed(update))) => {
                            Some(Argument::WrittenArgumentReference(original, update))
                        }
                        _ => None,
                    }
                }
                (_, _) => panic!(
                    "TwolineSyscall must be constructored with an Unfinished and Resumed SyscallSegment"
                ),
            },
            |unfinished, resumed, written_structure| {
                match (unfinished.borrow_output(), resumed.borrow_output()) {
                    (
                        TokenizerOutput::Syscall(SyscallSegment {
                            arguments: first_arguments,
                            outcome: CallOutcome::Unfinished,
                            ..
                        }),
                        TokenizerOutput::Syscall(SyscallSegment {
                            arguments: second_arguments,
                            outcome: CallOutcome::Resumed { .. },
                            ..
                        }),
                    ) => {
                        let mut ret =
                            Vec::with_capacity(first_arguments.len() + second_arguments.len());
                        for a in first_arguments {
                            ret.push(a);
                        }
                        for a in second_arguments {
                            ret.push(a);
                        }
                        // Slip written_structure in the middle of the arguments if present.
                        if let Some(written_structure) = written_structure {
                            ret[first_arguments.len() - 1] = written_structure;
                            ret.remove(first_arguments.len());
                        }
                        ret
                    }
                    (_, _) => panic!(
                        "TwolineSyscall must be constructored with an Unfinished and Resumed SyscallSegment"
                    ),
                }
            },
        )
    }
}

impl DebugOriginalTraceOutput for TwolineSyscall {
    fn original_trace_output(&self) -> String {
        format!(
            "line1: {:?}, line2: {:?}",
            self.borrow_unfinished().borrow_input().clone(),
            self.borrow_resumed().borrow_input().clone(),
        )
    }
}

impl CompleteSyscall for TwolineSyscall {
    fn pid(&self) -> &str {
        self.borrow_unfinished().with_output(|tokenizer_output| match tokenizer_output {
            TokenizerOutput::Syscall(SyscallSegment {
                pid,
                outcome: CallOutcome::Unfinished,
                ..
            }) => pid,
            _ => panic!("TwolineSyscall cannot be constructed with 0 tokenizer output that isn't a syscall; but was: {tokenizer_output:?}"),
        })
    }

    fn function(&self) -> &str {
        self.borrow_unfinished().with_output(|tokenizer_output| match tokenizer_output {
            TokenizerOutput::Syscall(SyscallSegment {
                function,
                outcome: CallOutcome::Unfinished,
                ..
            }) => function,
            _ => panic!("TwolineSyscall cannot be constructed with 0 tokenizer output that isn't a syscall; but was: {tokenizer_output:?}"),
        })
    }

    fn arguments(&self) -> &Vec<&Argument<'_>> {
        self.borrow_arguments()
    }

    fn retval(&self) -> &Retval<'_> {
        self.borrow_resumed().with_output(|tokenizer_output| match tokenizer_output {
            TokenizerOutput::Syscall(SyscallSegment {
                outcome: CallOutcome::Resumed { retval },
                ..
            }) => retval,
            _ => panic!("TwolineSyscall cannot be constructed with 1 tokenizer output that isn't a syscall; but was: {tokenizer_output:?}"),
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum SequencerOutput {
    /// An strace line that included both invocation and completion of the syscall.
    OnelineSyscall(OnelineSyscall),
    /// A pair of strace lines representing the invocation, and then completion, of the syscall.
    TwolineSyscall(TwolineSyscall),
    /// An strace line that started a syscall that hasn't been completed.
    IncompleteSyscall,
    ProcessExit(TraceLineProcessExit),
    Junk(TraceLine),
}

impl SequencerOutput {
    pub fn trace_lines(&self) -> (Option<&TraceLine>, Option<&TraceLine>) {
        match self {
            SequencerOutput::OnelineSyscall(one) => (Some(one.borrow_complete()), None),
            SequencerOutput::TwolineSyscall(two) => {
                (Some(two.borrow_unfinished()), Some(two.borrow_resumed()))
            }
            SequencerOutput::IncompleteSyscall => (None, None),
            SequencerOutput::ProcessExit(exit) => (Some(exit.borrow_trace_line()), None),
            SequencerOutput::Junk(trace_line) => (Some(trace_line), None),
        }
    }
}

/// Sequencer tokenizes lines in an strace output file and merges together the arguments of "unfinished" and "resumed"
/// syscalls, providing an output which, through the `CompleteSyscall` trait, can be used the same whether the syscall
/// was interrupted during tracing or not.
pub struct Sequencer {
    unfinished: HashMap<String, TraceLine>,
}

impl Sequencer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            unfinished: HashMap::new(),
        }
    }

    pub fn tokenize(&mut self, input: String) -> Result<SequencerOutput> {
        let trace_line = TraceLine::try_new(input, |input| {
            let mut tokenizer_input: &str = input;
            tokenize(&mut tokenizer_input)
        })?;

        match trace_line.borrow_output() {
            TokenizerOutput::Syscall(SyscallSegment {
                outcome: CallOutcome::Complete { .. },
                ..
            }) => Ok(SequencerOutput::OnelineSyscall(OnelineSyscall::make(
                trace_line,
            ))),
            TokenizerOutput::Syscall(SyscallSegment {
                pid,
                outcome: CallOutcome::Unfinished,
                ..
            }) => {
                self.unfinished.insert((*pid).to_string(), trace_line);
                Ok(SequencerOutput::IncompleteSyscall)
            }
            TokenizerOutput::Syscall(SyscallSegment {
                pid,
                outcome: CallOutcome::Resumed { .. },
                ..
            }) => {
                if let Some(unfinished) = self.unfinished.remove(*pid) {
                    Ok(SequencerOutput::TwolineSyscall(TwolineSyscall::make(
                        unfinished, trace_line,
                    )))
                } else {
                    Err(anyhow::anyhow!(
                        "Found resumed syscall without matching unfinished call; content was: {:?}",
                        trace_line.borrow_input()
                    ))
                }
            }
            TokenizerOutput::Exit(_) => Ok(SequencerOutput::ProcessExit(
                TraceLineProcessExit::make(trace_line),
            )),
            TokenizerOutput::Signal(_)
            | TokenizerOutput::Syscall(SyscallSegment {
                outcome: CallOutcome::ResumedUnfinished,
                ..
            }) => Ok(SequencerOutput::Junk(trace_line)),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::sys_trace::strace::{
        sequencer::CompleteSyscall as _,
        tokenizer::{Argument, ArgumentStructure, Retval},
    };

    use super::{Sequencer, SequencerOutput};

    #[test]
    fn complete() -> Result<()> {
        let mut seq = Sequencer::new();

        let t = seq.tokenize(String::from(r"2177902 close(3)                        = 0"))?;
        let SequencerOutput::OnelineSyscall(t) = t else {
            panic!("expected OnelineSyscall; was {t:?}");
        };
        assert_eq!(t.pid(), "2177902");
        assert_eq!(t.function(), "close");
        assert_eq!(*t.arguments(), vec![&Argument::Numeric("3")]);
        assert_eq!(*t.retval(), Retval::Success(0));

        Ok(())
    }

    #[test]
    fn sequence() -> Result<()> {
        let mut seq = Sequencer::new();

        // 337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>
        // 337653 openat(AT_FDCWD, "/dev/null", O_RDONLY|O_CLOEXEC) = 9
        // 337651 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654

        let t = seq.tokenize(String::from(r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>"))?;
        assert_eq!(t, SequencerOutput::IncompleteSyscall);

        let t = seq.tokenize(String::from(
            r"337651 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654",
        ))?;
        let SequencerOutput::TwolineSyscall(t) = t else {
            panic!("expected TwolineSyscall; was {t:?}");
        };
        assert_eq!(t.pid(), "337651");
        assert_eq!(t.function(), "clone");
        assert_eq!(
            *t.arguments(),
            vec![
                &Argument::Named("child_stack", Box::new(Argument::Null)),
                &Argument::Named(
                    "flags",
                    Box::new(Argument::Enum(
                        "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD"
                    ))
                ),
                &Argument::Named(
                    "child_tidptr",
                    Box::new(Argument::Pointer("0x7f9f93f88a10"))
                ),
            ]
        );
        assert_eq!(*t.retval(), Retval::Success(337_654));

        Ok(())
    }

    #[test]
    fn sequence_structure_write_merge() -> Result<()> {
        let mut seq = Sequencer::new();

        let t = seq.tokenize(String::from(r"337652 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f67099ff990, parent_tid=0x7f67099ff990, exit_signal=0, stack=0x7f67091ff000, stack_size=0x7fff80, tls=0x7f67099ff6c0} <unfinished ...>"))?;
        assert_eq!(t, SequencerOutput::IncompleteSyscall);

        let t = seq.tokenize(String::from(
            r"337652 <... clone3 resumed> => {parent_tid=[0]}, 88) = 15620",
        ))?;
        let SequencerOutput::TwolineSyscall(t) = t else {
            panic!("expected TwolineSyscall; was {t:?}");
        };
        assert_eq!(t.pid(), "337652");
        assert_eq!(t.function(), "clone3");
        assert_eq!(
            *t.arguments(),
            vec![
                &Argument::WrittenArgumentReference(
                    &Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Named(
                            "flags",
                            Box::new(Argument::Enum(
                                "CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID"
                            ))
                        ),
                        Argument::Named("child_tid", Box::new(Argument::Pointer("0x7f67099ff990"))),
                        Argument::Named(
                            "parent_tid",
                            Box::new(Argument::Pointer("0x7f67099ff990"))
                        ),
                        Argument::Named("exit_signal", Box::new(Argument::Numeric("0"))),
                        Argument::Named("stack", Box::new(Argument::Pointer("0x7f67091ff000"))),
                        Argument::Named("stack_size", Box::new(Argument::Pointer("0x7fff80"))),
                        Argument::Named("tls", Box::new(Argument::Pointer("0x7f67099ff6c0"))),
                    ])),
                    &Argument::Structure(ArgumentStructure::new(vec![Argument::Named(
                        "parent_tid",
                        Box::new(Argument::Structure(ArgumentStructure::new(vec![
                            Argument::Numeric("0")
                        ])))
                    )])),
                ),
                &Argument::Numeric("88"),
            ]
        );
        assert_eq!(*t.retval(), Retval::Success(15_620));

        Ok(())
    }
}
