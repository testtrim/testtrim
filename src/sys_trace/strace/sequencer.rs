// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{borrow::Cow, collections::HashMap};

use anyhow::{anyhow, ensure, Result};

use super::tokenizer::{
    tokenize, Argument, CallOutcome, ProcessExit, Retval, SyscallSegment, TokenizerOutput,
};

/// In the sequencers, we're going to be combining data from multiple parse invocations (eg. an "unfinished" and a
/// "resumed").  The tokenizer's return data is all tied to the lifetime of the string being parsed, which will be
/// discarded after the "unfinished" line.  So, to keep the argument data around in this case, we clone it into an owned
/// version of the same structure.
///
/// I guess it's not as clone-efficient as I thought it might be when writing the tokenizer.  Maybe a future iteration
/// we could have the sequencer take ownership of the strings and cache them, allowing the lifetime of arguments to
/// be... well, it still doesn't seem like it makes sense because it would clone *more* data, and you can't get owned
/// references out without an Rc or something.
///
/// See `Tokenizer::Argument` for any docs.
#[derive(Debug, PartialEq, Clone)]
pub enum OwnedArgument {
    String(Vec<u8>),
    PartialString(Vec<u8>),
    Numeric(String),
    Pointer(String),
    PointerWithComment(String, String),
    Structure(String),
    WrittenStructure(String, String),
    Enum(String),
    Null,
    Named(String, Box<OwnedArgument>),
}

impl Argument<'_> {
    pub fn into_owned(self) -> OwnedArgument {
        match self {
            Argument::String(bytes) => OwnedArgument::String(bytes),
            Argument::PartialString(bytes) => OwnedArgument::PartialString(bytes),
            Argument::Numeric(s) => OwnedArgument::Numeric(s.to_string()),
            Argument::Pointer(s) => OwnedArgument::Pointer(s.to_string()),
            Argument::PointerWithComment(s1, s2) => {
                OwnedArgument::PointerWithComment(s1.to_string(), s2.to_string())
            }
            Argument::Structure(s) => OwnedArgument::Structure(s.to_string()),
            Argument::WrittenStructure(s1, s2) => {
                OwnedArgument::WrittenStructure(s1.to_string(), s2.to_string())
            }
            Argument::Enum(s) => OwnedArgument::Enum(s.to_string()),
            Argument::Null => OwnedArgument::Null,
            Argument::Named(name, arg) => {
                OwnedArgument::Named(name.to_string(), Box::new(arg.into_owned()))
            }
            // Sequencer must merge this with a previous Structure into a WrittenStructure; it should never be exposed
            // past the sequencer.
            Argument::WrittenStructureResumed(_) => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TraceOutput<'a> {
    Syscall(Syscall<'a>),
    Exit(ProcessExit<'a>),
}

#[derive(Debug, PartialEq)]
pub struct Syscall<'a> {
    pub function: Cow<'a, str>,
    pub arguments: Vec<OwnedArgument>,
    pub retval: Retval<'a>,
}

struct UnfinishedCall<'a> {
    function: Cow<'a, str>,
    arguments: Vec<OwnedArgument>,
}

/// Sequencer tokenizes lines in an strace output file and merges together the arguments of "unfinished" and "resumed"
/// syscalls, providing the same output whether the syscall was interrupted during tracing or not.
pub struct Sequencer<'cache> {
    unfinished: HashMap<String, UnfinishedCall<'cache>>,
}

impl<'cache> Sequencer<'cache> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            unfinished: HashMap::new(),
        }
    }

    pub fn tokenize<'a>(&mut self, input: &'a str) -> Result<Option<TraceOutput<'a>>>
    where
        'cache: 'a,
    {
        Ok(match tokenize(input)? {
            TokenizerOutput::Syscall(SyscallSegment {
                function,
                arguments,
                outcome: CallOutcome::Complete { retval },
            }) => Some(TraceOutput::Syscall(Syscall {
                function: Cow::Borrowed(function),
                arguments: arguments.into_iter().map(Argument::into_owned).collect(),
                retval,
            })),
            TokenizerOutput::Syscall(SyscallSegment {
                outcome: CallOutcome::ResumedUnfinished,
                ..
            }) => {
                // Trace interrupted, resumed, and then interrupted again -- no new data here to consolidate
                None
            }
            TokenizerOutput::Syscall(SyscallSegment {
                function,
                arguments,
                outcome: CallOutcome::Unfinished,
            }) => {
                // Store the unfinished call, converting values to owned where needed
                let previous = self.unfinished.insert(
                    "1000".to_string(), // FIXME: after transition from single-file to multi-file strace, this entire sequencer is a relic that should be removed -- but for now we don't have a pid so just hacking this
                    UnfinishedCall {
                        function: Cow::Owned(function.to_string()),
                        arguments: arguments.into_iter().map(Argument::into_owned).collect(),
                    },
                );
                ensure!(
                    previous.is_none(),
                    "sequencer.unfinished(1000) already had a value when new value was inserted"
                );
                None
            }
            TokenizerOutput::Syscall(SyscallSegment {
                function,
                arguments,
                outcome: CallOutcome::Resumed { retval },
            }) => {
                // Retrieve the unfinished call
                if let Some(mut unfinished) = self.unfinished.remove("1000") {
                    // Assert that the functions match
                    ensure!(
                        unfinished.function.as_ref() == function,
                        "Resumed syscall function doesn't match unfinished syscall"
                    );
                    // Combine arguments from both the unfinished and resumed call traces
                    for (idx, arg) in arguments.into_iter().enumerate() {
                        if idx == 0
                            && let Argument::WrittenStructureResumed(upd) = arg
                        {
                            match unfinished.arguments.pop() {
                                Some(OwnedArgument::Structure(orig)) => unfinished
                                    .arguments
                                    .push(OwnedArgument::WrittenStructure(orig, String::from(upd))),
                                Some(v) => {
                                    return Err(anyhow!("strace parse: WrittenStructureResumed token found but previous final argument was not structure; was: {v:?}"));
                                }
                                None => {
                                    return Err(anyhow!("strace parse: WrittenStructureResumed token found but there was no previous final argument"));
                                }
                            }
                        } else {
                            unfinished.arguments.push(arg.into_owned());
                        }
                    }
                    Some(TraceOutput::Syscall(Syscall {
                        function: unfinished.function,
                        arguments: unfinished.arguments,
                        retval,
                    }))
                } else {
                    // Handle error case - resumed without matching unfinished
                    return Err(anyhow::anyhow!(
                        "Found resumed syscall without matching unfinished call"
                    ));
                }
            }
            TokenizerOutput::Exit(exit) => Some(TraceOutput::Exit(exit)),
            TokenizerOutput::Signal(_) => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        io::{BufRead as _, BufReader},
    };

    use anyhow::Result;

    use crate::sys_trace::strace::{
        sequencer::{OwnedArgument, Syscall, TraceOutput},
        tokenizer::Retval,
    };

    use super::Sequencer;

    #[test]
    fn complete() -> Result<()> {
        let mut seq = Sequencer::new();

        let t = seq.tokenize(r"close(3)                        = 0")?;
        assert_eq!(
            t,
            Some(TraceOutput::Syscall(Syscall {
                function: Cow::Borrowed("close"),
                arguments: vec![OwnedArgument::Numeric("3".to_string())],
                retval: Retval::Success(0)
            }))
        );

        Ok(())
    }

    #[test]
    fn sequence() -> Result<()> {
        let mut seq = Sequencer::new();

        // 337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>
        // 337653 openat(AT_FDCWD, "/dev/null", O_RDONLY|O_CLOEXEC) = 9
        // 337651 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654

        let t = seq.tokenize(r"clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>")?;
        assert_eq!(t, None);

        let t = seq.tokenize(r"<... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654")?;
        assert_eq!(
            t,
            Some(TraceOutput::Syscall(Syscall {
                function: Cow::Borrowed("clone"),
                arguments: vec![
                    OwnedArgument::Named("child_stack".to_string(), Box::new(OwnedArgument::Null)),
                    OwnedArgument::Named(
                        "flags".to_string(),
                        Box::new(OwnedArgument::Enum(
                            "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD".to_string()
                        ))
                    ),
                    OwnedArgument::Named(
                        "child_tidptr".to_string(),
                        Box::new(OwnedArgument::Pointer("0x7f9f93f88a10".to_string()))
                    ),
                ],
                retval: Retval::Success(337_654)
            }))
        );

        Ok(())
    }

    #[test]
    fn sequence_structure_write_merge() -> Result<()> {
        let mut seq = Sequencer::new();

        let t = seq.tokenize(r"clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f67099ff990, parent_tid=0x7f67099ff990, exit_signal=0, stack=0x7f67091ff000, stack_size=0x7fff80, tls=0x7f67099ff6c0} <unfinished ...>")?;
        assert_eq!(t, None);

        let t = seq.tokenize(r"<... clone3 resumed> => {parent_tid=[0]}, 88) = 15620")?;
        assert_eq!(
            t,
            Some(TraceOutput::Syscall(Syscall {
                function: Cow::Borrowed("clone3"),
                arguments: vec![
                    OwnedArgument::WrittenStructure(
                        String::from("{flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f67099ff990, parent_tid=0x7f67099ff990, exit_signal=0, stack=0x7f67091ff000, stack_size=0x7fff80, tls=0x7f67099ff6c0}"),
                        String::from("{parent_tid=[0]}")
                    ),
                    OwnedArgument::Numeric(String::from("88")),
                ],
                retval: Retval::Success(15_620)
            }))
        );

        Ok(())
    }

    #[test]
    fn sequencer_realworld_errorfree() -> Result<()> {
        // Regenerating this file (if needed?) -- see strace mod.rs
        let trace_raw =
            include_bytes!("../../../tests/test_data/strace-multiproc-chdir.strace.4086638");
        let lines = BufReader::new(&trace_raw[..]).lines();

        let mut seq = Sequencer::new();

        for line in lines {
            let line = line?;
            // The main assertion of this test is that every line can be tokenized and sequenced without errors.
            seq.tokenize(&line)?;
        }
        // And that there's nothing left in the sequencer afterwards.
        assert_eq!(seq.unfinished.len(), 0, "sequencer should be empty");

        Ok(())
    }
}
