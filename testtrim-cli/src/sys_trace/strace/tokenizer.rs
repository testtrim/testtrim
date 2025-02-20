// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use winnow::ascii::{dec_int, digit1, hex_digit1, multispace1};
use winnow::combinator::{alt, delimited, opt, preceded, repeat, separated, trace};
use winnow::token::{literal, one_of, rest, take_until};
use winnow::token::{take_till, take_while};
use winnow::{ModalResult, Parser};

#[derive(Debug, PartialEq)]
pub struct EncodedString<'a> {
    pub encoded: &'a str,
    decoded: OnceLock<Vec<u8>>,
}

impl<'a> EncodedString<'a> {
    pub(crate) fn new(encoded: &'a str) -> Self {
        EncodedString {
            encoded,
            decoded: OnceLock::new(),
        }
    }

    fn do_decode(&self) -> Vec<u8> {
        let mut tmp_ref = self.encoded;
        match parse_encoded_string(&mut tmp_ref) {
            Ok(vec) => vec,
            Err(_) => unreachable!(
                "parse_encoded_string must not be able to fail for a string in EncodedString; encoded was: {:?}",
                self.encoded
            ),
        }
    }

    #[must_use]
    pub fn decoded(&self) -> &Vec<u8> {
        self.decoded.get_or_init(|| self.do_decode())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, PartialEq)]
pub enum Argument<'a> {
    /// Argument in the form of double-quote delimited string, eg. "contents".  The value is the interior of the string
    /// decoded into a u8 vector.  This is likely usable as a `CStr`, but could also be a data buffer that can contain
    /// null bytes.
    String(EncodedString<'a>),
    /// String(_) which has been truncated due to limited "--string-limit"; ref is to the interior of the partial string
    /// same as String(_).
    PartialString(EncodedString<'a>),
    /// Numeric value, eg. "3"
    Numeric(&'a str),
    /// Pointer: 0x...
    Pointer(&'a str),
    /// A pointer (0x...) with some comment following it; eg. "0x7ffdf2244ed8 /* 218 vars */"
    PointerWithComment(&'a str, &'a str),
    /// Structure: {...} or [...].
    Structure(ArgumentStructure<'a>),
    /// Structure: [...], which was prefixed with ~ when it is a bitset which is "so full that printing out the unset
    /// elements is more valuable".
    InverseStructure(ArgumentStructure<'a>),
    /// This represents a value that was passed into a syscall and then modified by the syscall; strace represents it as
    /// {...} => {...} where the first part is the input and the second is the changes made.
    WrittenArgument(Box<Argument<'a>>, Box<Argument<'a>>),
    /// Same logical meaning as `WrittenArgument` but with a different storage, used for a non-owned Argument which
    /// combines an `Argument` and a `WrittenArgumentResumed` in Sequencer.
    WrittenArgumentReference(&'a Argument<'a>, &'a Argument<'a>),
    /// In the event that a `WrittenStructure` and a `CallOutcome::Resumed` occur at the same time, only the "=> {..}"
    /// part of the argument will be present in the resumed strace line.
    ///
    /// This is an awkward case because it will represent one more argument in the resumed case than in the standard
    /// syscall case -- to compensate for this, the `Sequencer` must merge any Structure arguments followed by a
    /// `WrittenStructureResumed` argument.  At this time I don't know if multiple of these are possible at once which
    /// would be more confusing; but I've only seen a case for a signle.
    WrittenArgumentResumed(Box<Argument<'a>>),
    /// Enum: `MSG_NOSIGNAL|MSG_NOSIGNAL`
    Enum(&'a str),
    //. Just "NULL"
    Null,
    /// Named argument; eg. `child_tidptr=0x7f9f93f88a10`, arg name will be tuple 0, value 1.
    Named(&'a str, Box<Argument<'a>>),
    /// Function argument, eg. `inet_addr(\"127.0.0.1\")`, where `inet_addr` would be the name of the function that the
    /// argument is decorated with.  The two fields are the function name and the entire argument range; arguments are
    /// not exposed one-by-one currently.
    FunctionArgument(&'a str, ArgumentStructure<'a>),
    /// Argument in the form of `&sin6_addr` in the strace output.
    VariableReference(&'a str),
    /// The `wait4` syscall returns the status of the waited process in a format that describes which flags are set,
    /// that looks like `[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]`.  This indicates that the process exited and had a
    /// status code of 0.  I don't know if this format of strace output is used anywhere else... so naming it pretty
    /// specifically...
    WaitFlags(&'a str),
    /// Some syscalls are output with arguments that are made easier to read, presumably when they must be made
    /// multiples of a constant.  Example is `rlimit_cur=8192*1024`.  Matches the entire text since we don't currently
    /// need to split it apart.
    NumericWithConstant(&'a str),
    /// Represents the output of `sched_getaffinity`, which contains a cpu set in the form `[0 1 2 3 4 5]`.
    CpuSet(&'a str),
}

impl<'a> Argument<'a> {
    pub fn named(&'a self, expected_name: &str) -> Result<&'a Argument<'a>> {
        match self {
            Argument::Named(actual_name, value) if *actual_name == expected_name => Ok(value),
            Argument::Named(actual_name, _) => Err(anyhow!(
                "expected to access named value {expected_name}, but had name {actual_name}"
            )),
            other => Err(anyhow!(
                "expected to access named value {expected_name}, but was {other:?}"
            )),
        }
    }

    pub fn enum_v(&'a self) -> Result<&'a str> {
        if let Argument::Enum(v) = self {
            Ok(v)
        } else {
            Err(anyhow!(
                "expected value to be Argument::Enum, but was {self:?}"
            ))
        }
    }

    pub fn path(&'a self) -> Result<PathBuf> {
        if let Argument::String(v) = self {
            Ok(PathBuf::from(OsStr::from_bytes(v.decoded())))
        } else {
            Err(anyhow!(
                "expected value to be Argument::String, but was {self:?}"
            ))
        }
    }

    pub fn func(&'a self, expected_name: &str) -> Result<&'a ArgumentStructure<'a>> {
        match self {
            Argument::FunctionArgument(actual_name, value) if *actual_name == expected_name => {
                Ok(value)
            }
            Argument::FunctionArgument(actual_name, _) => Err(anyhow!(
                "expected to access named value {expected_name}, but had name {actual_name}"
            )),
            other => Err(anyhow!(
                "expected to access named value {expected_name}, but was {other:?}"
            )),
        }
    }

    pub fn numeric(&self) -> Result<i32> {
        match self {
            Argument::Numeric(v) => Ok(i32::from_str(v)?),
            v => Err(anyhow!("argument was not numeric; it was {v:?}")),
        }
    }

    pub fn string(&'a self) -> Result<&'a EncodedString<'a>> {
        match self {
            Argument::String(v) => Ok(v),
            v => Err(anyhow!("argument was not numeric; it was {v:?}")),
        }
    }

    pub fn structure(&'a self) -> Result<&'a ArgumentStructure<'a>> {
        match self {
            Argument::WrittenArgument(orig, _) => match &**orig {
                Argument::Structure(structure) => Ok(structure),
                other => Err(anyhow!(
                    "expected argument to be Structure, but was {other:?}"
                )),
            },
            Argument::WrittenArgumentReference(orig, _) => match orig {
                Argument::Structure(structure) => Ok(structure),
                other => Err(anyhow!(
                    "eexpected argument to be Structure, but was {other:?}"
                )),
            },
            Argument::Structure(v) => Ok(v),
            v => Err(anyhow!("argument was not structure; it was {v:?}")),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ArgumentStructure<'a> {
    args: Vec<Argument<'a>>,
}

impl<'a> ArgumentStructure<'a> {
    pub fn new(args: Vec<Argument<'a>>) -> Self {
        ArgumentStructure { args }
    }

    pub fn index(&'a self, index: usize) -> Result<&'a Argument<'a>> {
        match self.args.get(index) {
            Some(arg) => Ok(arg),
            None => Err(anyhow!(
                "expected to access struct index {index}, but could not; struct was {self:?}"
            )),
        }
    }
}

pub trait ArgumentCollection<'a> {
    fn index(&'a self, index: usize) -> Result<&'a Argument<'a>>;
}

impl<'a> ArgumentCollection<'a> for &'a [&'a Argument<'a>] {
    fn index(&'a self, index: usize) -> Result<&'a Argument<'a>> {
        match self.get(index) {
            Some(arg) => Ok(arg),
            None => Err(anyhow!(
                "expected to access argument at index {index}, but could not; arguments were {self:?}"
            )),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Retval<'a> {
    Success(i32),
    Failure(i32, &'a str),   // retval and error code
    Restart(&'a str),        // "? ERESTARTSYS"
    SuccessPointer(&'a str), // = 0x55ad8bba6000
}

#[derive(Debug, PartialEq)]
pub enum CallOutcome<'a> {
    /// syscall that was completed while traced.
    Complete { retval: Retval<'a> },
    /// While a syscall occurred on one pid, another started on a different pid; strace dumps the original to the log as
    /// an "unfinished" call.
    Unfinished,
    /// After an "unfinished" call, tracing the call was resumed and finished.  The complete arguments and return value
    /// for this call require combining data from the Unfinished and Resumed trace.
    Resumed { retval: Retval<'a> },
    /// After an "unfinished" call, tracing the call was resumed, and then tracing was interrupted by another pid's
    /// syscall again.  This trace message doesn't have any additional data to combine.
    ResumedUnfinished,
}

#[derive(Debug, PartialEq)]
pub enum TokenizerOutput<'a> {
    Syscall(SyscallSegment<'a>),
    Exit(ProcessExit<'a>),
    Signal(SignalRecv<'a>),
}

#[derive(Debug, PartialEq)]
pub struct SyscallSegment<'a> {
    pub pid: &'a str,
    pub function: &'a str,
    pub arguments: Vec<Argument<'a>>,
    pub outcome: CallOutcome<'a>,
}

#[derive(Debug, PartialEq)]
pub struct ProcessExit<'a> {
    pub pid: &'a str,
    pub exit_code: &'a str,
}

#[derive(Debug, PartialEq)]
pub struct SignalRecv<'a> {
    pub pid: &'a str,
    pub signal: &'a str,
}

pub fn tokenize<'i>(input: &mut &'i str) -> Result<TokenizerOutput<'i>> {
    internal_tokenize
        .parse(input)
        .map_err(|e| anyhow!("error occurred in strace tokenize: {e:?}"))
}

fn internal_tokenize<'i>(input: &mut &'i str) -> ModalResult<TokenizerOutput<'i>> {
    alt((
        Parser::map(parse_syscall, TokenizerOutput::Syscall),
        Parser::map(parse_proc_exit, TokenizerOutput::Exit),
        Parser::map(parse_proc_killed, TokenizerOutput::Exit),
        Parser::map(parse_signal, TokenizerOutput::Signal),
    ))
    .parse_next(input)
}

fn parse_proc_exit<'i>(input: &mut &'i str) -> ModalResult<ProcessExit<'i>> {
    let pid = parse_pid(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("+++ exited with ").parse_next(input)?;
    let exit_code = digit1(input)?;
    let _ = literal(" +++").parse_next(input)?;
    Ok(ProcessExit { pid, exit_code })
}

fn parse_proc_killed<'i>(input: &mut &'i str) -> ModalResult<ProcessExit<'i>> {
    let pid = parse_pid(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("+++ killed by ").parse_next(input)?;
    let _ = rest(input)?;
    Ok(ProcessExit {
        pid,
        exit_code: "-1",
    })
}

fn parse_signal<'i>(input: &mut &'i str) -> ModalResult<SignalRecv<'i>> {
    alt((parse_signal_format1, parse_signal_format2)).parse_next(input)
}

fn parse_signal_format1<'i>(input: &mut &'i str) -> ModalResult<SignalRecv<'i>> {
    let pid = parse_pid(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("---").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let signal = take_while(1.., |c: char| c.is_ascii_uppercase()).parse_next(input)?;
    // pretty lazy here but we don't do anything with signals yet, and may never
    let _ = take_while(0.., |_| true).parse_next(input)?;
    Ok(SignalRecv { pid, signal })
}

fn parse_signal_format2<'i>(input: &mut &'i str) -> ModalResult<SignalRecv<'i>> {
    let pid = parse_pid(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("--- stopped by ").parse_next(input)?;
    let signal = take_while(1.., |c: char| c.is_ascii_uppercase()).parse_next(input)?;
    let _ = literal(" ---").parse_next(input)?;
    Ok(SignalRecv { pid, signal })
}

#[cfg(test)]
fn tokenize_syscall<'i>(input: &mut &'i str) -> Result<SyscallSegment<'i>> {
    parse_syscall
        .parse(input)
        .map_err(|e| anyhow!("error occurred in strace parse_syscall: {e:?}"))
}

fn parse_syscall<'i>(input: &mut &'i str) -> ModalResult<SyscallSegment<'i>> {
    let pid = parse_pid(input)?;
    let _ = consume_whitespace(input)?;
    let line_type = parse_line_type(input)?;

    match line_type {
        InternalLineType::Started {
            function_name,
            arguments,
            outcome,
        }
        | InternalLineType::Resumed {
            function_name,
            arguments,
            outcome,
        } => Ok(SyscallSegment {
            pid,
            function: function_name,
            arguments,
            outcome,
        }),
        InternalLineType::ResumedUnfinished { function_name } => Ok(SyscallSegment {
            pid,
            function: function_name,
            arguments: Vec::new(),
            outcome: CallOutcome::ResumedUnfinished,
        }),
    }
}

enum InternalLineType<'a> {
    Started {
        function_name: &'a str,
        arguments: Vec<Argument<'a>>,
        outcome: CallOutcome<'a>,
    },
    Resumed {
        function_name: &'a str,
        arguments: Vec<Argument<'a>>,
        outcome: CallOutcome<'a>,
    },
    ResumedUnfinished {
        function_name: &'a str,
    },
}

fn parse_line_type<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    alt((
        parse_started_call,
        parse_resumed_call,
        parse_resumed_unfinished_call,
    ))
    .parse_next(input)
}

fn parse_started_call<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    let function_name = parse_function_name(input)?;
    let _ = literal("(").parse_next(input)?;
    let arguments = separated(0.., parse_argument, literal(", ")).parse_next(input)?;
    let outcome = parse_started_call_outcome(input)?;
    Ok(InternalLineType::Started {
        function_name,
        arguments,
        outcome,
    })
}

fn parse_resumed_call<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    let _ = literal("<... ").parse_next(input)?;
    let function_name = parse_function_name(input)?;
    let _ = literal(" resumed>").parse_next(input)?;
    let _ = opt(literal(", ")).parse_next(input)?; // sometimes "resumed>, ", somtimes straight into args -- can't quite see why it would be one or the other right now
    let resumed = opt((parse_written_argument_resumed, opt(literal(", ")))).parse_next(input)?;
    let mut arguments: Vec<Argument> =
        separated(0.., parse_argument, literal(", ")).parse_next(input)?;
    if let Some((resumed_arg, _)) = resumed {
        // handles uncommon case of a structure write after a resumed; don't love inserting into the head of a vec but
        // it's probably OK given the rarity.
        // 15615 <... clone3 resumed> => {parent_tid=[0]}, 88) = 15620
        arguments.insert(0, resumed_arg);
    }
    let outcome = parse_complete_outcome(input)?;
    let outcome = match outcome {
        CallOutcome::Complete { retval } => CallOutcome::Resumed { retval },
        CallOutcome::ResumedUnfinished => CallOutcome::ResumedUnfinished,
        _ => unreachable!(),
    };
    Ok(InternalLineType::Resumed {
        function_name,
        arguments,
        outcome,
    })
}

fn parse_resumed_unfinished_call<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    alt((
        parse_terminating_process_case1,
        parse_terminating_process_case2,
        parse_terminating_process_case3,
        parse_terminating_process_case4,
    ))
    .parse_next(input)
}

fn parse_terminating_process_case1<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    let _ = literal("<... ").parse_next(input)?;
    let function_name = alt((parse_function_name, literal("???"))).parse_next(input)?;
    let _ = literal(" resumed>").parse_next(input)?;
    let _ = alt((
        Parser::take((
            consume_whitespace,
            literal("<unfinished ...>)"),
            consume_whitespace,
            literal("= ?"),
        )),
        Parser::take((literal(")"), consume_whitespace, literal("= ?"))),
    ))
    .parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished { function_name })
}

fn parse_terminating_process_case2<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    let _ = literal("???( <unfinished ...>").parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished {
        function_name: "???",
    })
}

fn parse_terminating_process_case3<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    let _ = literal("???()").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("= ?").parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished {
        function_name: "???",
    })
}

fn parse_terminating_process_case4<'i>(input: &mut &'i str) -> ModalResult<InternalLineType<'i>> {
    let function_name = parse_function_name(input)?;
    let _ = literal("(").parse_next(input)?;
    let _: Vec<Argument> = separated(0.., parse_argument, literal(", ")).parse_next(input)?;
    let _ = literal(", )").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("= ? <unavailable>").parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished { function_name })
}

fn consume_whitespace<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    multispace1(input)
}

pub fn parse_pid<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    digit1(input)
}

pub fn hex_address<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    (literal("0x"), hex_digit1).take().parse_next(input)
}

pub fn enum_flags<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    (
        one_of(|c: char| c.is_ascii_uppercase() || c == '_'),
        take_while(1.., |c: char| {
            c.is_ascii_uppercase() || c == '_' || c == '|' || c.is_numeric()
        }),
    )
        .take()
        .parse_next(input)
}

fn parse_function_name<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    trace("parse_function_name", |input: &mut _| {
        take_while(1.., |c: char| c.is_alphanumeric() || c == '_').parse_next(input)
    })
    .parse_next(input)
}

fn parse_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_argument", |input: &mut _| {
        alt((parse_written_argument, parse_argument_without_write)).parse_next(input)
    })
    .parse_next(input)
}

fn parse_argument_without_write<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_argument_without_write", |input: &mut _| {
        alt((
            parse_named_argument,
            parse_null_argument,
            parse_enum_argument,
            parse_pointer_with_comment_argument,
            parse_pointer_argument,
            parse_numeric_with_constant_argument,
            parse_numeric_argument,
            parse_partial_string_argument,
            parse_string_argument,
            parse_cpuset_argument,
            parse_structure_argument,
            parse_function_argument,
            parse_variable_reference_argument,
            parse_wait_flags_argument,
        ))
        .parse_next(input)
    })
    .parse_next(input)
}

fn parse_named_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_named_argument", |input: &mut _| {
        let name = take_while(1.., |c: char| {
            c.is_ascii_lowercase() || c.is_numeric() || c == '_'
        })
        .parse_next(input)?;
        let _ = literal("=").parse_next(input)?;
        let arg = parse_argument_without_write(input)?;
        Ok(Argument::Named(name, Box::new(arg)))
    })
    .parse_next(input)
}

fn parse_null_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let _ = literal("NULL").parse_next(input)?;
    Ok(Argument::Null)
}

fn parse_enum_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let arg = enum_flags(input)?;
    Ok(Argument::Enum(arg))
}

fn parse_numeric_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let arg = (opt(literal("-")), digit1).take().parse_next(input)?;
    Ok(Argument::Numeric(arg))
}

fn parse_string_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let contents = extract_encoded_string(input)?;
    Ok(Argument::String(contents))
}

fn parse_partial_string_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let contents = parse_string_argument(input)?;
    let _ = literal("...").parse_next(input)?;
    let Argument::String(inner_str) = contents else {
        unreachable!()
    };
    Ok(Argument::PartialString(inner_str))
}

fn parse_pointer_with_comment_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let pointer = hex_address(input)?;
    let _ = consume_whitespace(input)?;
    let comment = (literal("/*"), take_until(1.., "*/"), literal("*/"))
        .take()
        .parse_next(input)?;
    Ok(Argument::PointerWithComment(pointer, comment))
}

fn parse_pointer_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let something = hex_address(input)?;
    Ok(Argument::Pointer(something))
}

fn parse_written_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let orig_argument = parse_argument_without_write(input)?;
    let Argument::WrittenArgumentResumed(upd_argument) = parse_written_argument_resumed(input)?
    else {
        unreachable!()
    };
    Ok(Argument::WrittenArgument(
        Box::new(orig_argument),
        upd_argument,
    ))
}

fn parse_written_argument_resumed<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let _ = literal(" => ").parse_next(input)?;
    let upd_argument = parse_argument_without_write(input)?;
    Ok(Argument::WrittenArgumentResumed(Box::new(upd_argument)))
}

fn parse_structure_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    let inverse = opt(literal("~")).parse_next(input)?;
    let structure = alt((nested_brackets, nested_braces)).parse_next(input)?;
    Ok(if inverse.is_some() {
        Argument::InverseStructure(ArgumentStructure::new(structure))
    } else {
        Argument::Structure(ArgumentStructure::new(structure))
    })
}

fn nested_brackets<'i>(input: &mut &'i str) -> ModalResult<Vec<Argument<'i>>> {
    trace("nested_brackets", |input: &mut _| {
        delimited(
            literal("["),
            separated::<_, _, Vec<_>, _, _, _, _>(0.., parse_argument, literal(", ")),
            literal("]"),
        )
        .parse_next(input)
    })
    .parse_next(input)
}

fn nested_braces<'i>(input: &mut &'i str) -> ModalResult<Vec<Argument<'i>>> {
    trace("nested_braces", |input: &mut _| {
        let (args, _opt) = delimited(
            literal("{"),
            (
                separated::<_, _, Vec<_>, _, _, _, _>(
                    0..,
                    parse_argument_without_write,
                    literal(", "),
                ),
                opt(literal(", ...")),
            ),
            literal("}"),
        )
        .parse_next(input)?;
        Ok(args)
    })
    .parse_next(input)
}

fn parse_function_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_function_argument", |input: &mut _| {
        let name = parse_function_name(input)?;
        let args = delimited(
            literal("("),
            separated::<_, _, Vec<_>, _, _, _, _>(0.., parse_argument, literal(", ")),
            literal(")"),
        )
        .parse_next(input)?;
        Ok(Argument::FunctionArgument(
            name,
            ArgumentStructure::new(args),
        ))
    })
    .parse_next(input)
}

fn parse_variable_reference_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_variable_reference_argument", |input: &mut _| {
        let arg = (literal("&"), parse_function_name)
            .take()
            .parse_next(input)?;
        Ok(Argument::VariableReference(arg))
    })
    .parse_next(input)
}

fn parse_wait_flags_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_wait_flags_argument", |input: &mut _| {
        let arg = alt((
            (
                literal("[{WIFEXITED(s) && WEXITSTATUS(s) == "),
                digit1,
                literal("}]"),
            ),
            (
                literal("[{WIFSIGNALED(s) && WTERMSIG(s) == "),
                enum_flags,
                literal("}]"),
            ),
        ))
        .take()
        .parse_next(input)?;
        Ok(Argument::WaitFlags(arg))
    })
    .parse_next(input)
}

fn parse_numeric_with_constant_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_numeric_with_constant_argument", |input: &mut _| {
        let arg = (digit1, literal("*"), digit1).take().parse_next(input)?;
        Ok(Argument::NumericWithConstant(arg))
    })
    .parse_next(input)
}

fn parse_cpuset_argument<'i>(input: &mut &'i str) -> ModalResult<Argument<'i>> {
    trace("parse_cpuset_argument", |input: &mut _| {
        let arg = delimited(
            literal("["),
            // must be 2.. in order to ensure that this parse path is unique from nested_braces
            separated::<_, _, Vec<_>, _, _, _, _>(2.., parse_numeric_argument, literal(" ")),
            literal("]"),
        )
        .take()
        .parse_next(input)?;
        Ok(Argument::CpuSet(arg))
    })
    .parse_next(input)
}

fn parse_started_call_outcome<'i>(input: &mut &'i str) -> ModalResult<CallOutcome<'i>> {
    alt((parse_complete_outcome, parse_unfinished_outcome)).parse_next(input)
}

fn parse_complete_outcome<'i>(input: &mut &'i str) -> ModalResult<CallOutcome<'i>> {
    let _ = literal(")").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("=").parse_next(input)?;

    alt((parse_end_with_retval, parse_end_with_qmark)).parse_next(input)
}

fn parse_end_with_retval<'i>(input: &mut &'i str) -> ModalResult<CallOutcome<'i>> {
    let _ = consume_whitespace(input)?;
    let retval = parse_retval(input)?;
    Ok(CallOutcome::Complete { retval })
}

fn parse_end_with_qmark<'i>(input: &mut &'i str) -> ModalResult<CallOutcome<'i>> {
    let _ = consume_whitespace(input)?;
    let _ = literal("?").parse_next(input)?;
    Ok(CallOutcome::ResumedUnfinished)
}

fn parse_retval<'i>(input: &mut &'i str) -> ModalResult<Retval<'i>> {
    alt((
        parse_success_pointer,
        parse_error_retval,
        parse_success_retval,
        parse_restart_retval,
    ))
    .parse_next(input)
}

fn parse_success_retval<'i>(input: &mut &'i str) -> ModalResult<Retval<'i>> {
    let arg = dec_int(input)?;
    Ok(Retval::Success(arg))
}

fn parse_error_retval<'i>(input: &mut &'i str) -> ModalResult<Retval<'i>> {
    let value = dec_int(input)?;
    let _ = consume_whitespace(input)?;
    let err = rest(input)?;
    Ok(Retval::Failure(value, err))
}

fn parse_restart_retval<'i>(input: &mut &'i str) -> ModalResult<Retval<'i>> {
    let _ = literal("? ").parse_next(input)?;
    let rem = rest(input)?;
    Ok(Retval::Restart(rem))
}

fn parse_success_pointer<'i>(input: &mut &'i str) -> ModalResult<Retval<'i>> {
    let pointer = (
        hex_address,
        opt((literal(" (flags "), enum_flags, literal(")"))),
    )
        .take()
        .parse_next(input)?;
    Ok(Retval::SuccessPointer(pointer))
}

fn parse_unfinished_outcome<'i>(input: &mut &'i str) -> ModalResult<CallOutcome<'i>> {
    // sometimes the last argument has a ",", then whitespace, then "<unfinished ...>".  Not sure why -- have observed
    // (and have test case covering) `read` doing this.
    let _ = opt(literal(",")).parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("<unfinished ...>").parse_next(input)?;
    let opt = opt((literal(")"), consume_whitespace, literal("= ?"))).parse_next(input)?;
    match opt {
        Some(_) => Ok(CallOutcome::ResumedUnfinished),
        None => Ok(CallOutcome::Unfinished),
    }
}

fn extract_encoded_string<'i>(input: &mut &'i str) -> ModalResult<EncodedString<'i>> {
    let matched = delimited(
        one_of('"'),
        Parser::take(repeat::<_, _, Vec<_>, _, _>(
            0..,
            alt((extract_str_literal, extract_str_escape)),
        )),
        one_of('"'),
    )
    .parse_next(input)?;
    Ok(EncodedString::new(matched))
}

// Two string escape methods; "extract" will just return the range of the string for fast parsing, and "parse" will
// convert to u8 when the actual data is needed.  The separation is because often the data isn't really needed.
fn extract_str_escape<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    preceded(
        one_of('\\'),
        alt((
            // hex: \x00
            extract_hex_byte,
            // `man strace` -> \t, \n, \v, \f, \r are all possible
            one_of('t'),  // Tab
            one_of('n'),  // Newline
            one_of('v'),  // Vertical tab
            one_of('f'),  // form feed page break
            one_of('r'),  // Carriage return
            one_of('"'),  // Escaped double-quote
            one_of('\\'), // Backslash escaped
        )),
    )
    .take()
    .parse_next(input)
}

/// Parse an escaped character: \n, \t, \r, \u{00AC}, etc.
fn parse_escaped_char(input: &mut &str) -> ModalResult<u8> {
    preceded(
        one_of('\\'),
        alt((
            // hex: \x00
            parse_hex_byte,
            // `man strace` -> \t, \n, \v, \f, \r are all possible
            one_of('t').value(b'\t'),  // Tab
            one_of('n').value(b'\n'),  // Newline
            one_of('v').value(0x0b),   // Vertical tab
            one_of('f').value(0x0c),   // form feed page break
            one_of('r').value(b'\r'),  // Carriage return
            one_of('"').value(b'"'),   // Escaped double-quote
            one_of('\\').value(b'\\'), // Backslash escaped
        )),
    )
    .parse_next(input)
}

fn extract_hex_byte(input: &mut &str) -> ModalResult<char> {
    let parse_hex = take_while(2..=2, |c: char| c.is_ascii_hexdigit());
    preceded(one_of('x'), parse_hex)
        .map(|_| ' ')
        .parse_next(input)
}

fn parse_hex_byte(input: &mut &str) -> ModalResult<u8> {
    let parse_hex = take_while(2..=2, |c: char| c.is_ascii_hexdigit());
    let parse_delimited_hex = preceded(one_of('x'), parse_hex);
    let mut parse_u8 = Parser::try_map(parse_delimited_hex, move |hex| u8::from_str_radix(hex, 16));
    parse_u8.parse_next(input)
}

fn extract_str_literal<'i>(input: &mut &'i str) -> ModalResult<&'i str> {
    let not_quote_slash = take_till(1.., |c| c == '"' || c == '\\');
    not_quote_slash
        .verify(|s: &str| !s.is_empty())
        .parse_next(input)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringFragment<'a> {
    Literal(&'a str),
    EscapedChar(u8),
}

fn parse_str_fragment<'i>(input: &mut &'i str) -> ModalResult<StringFragment<'i>> {
    alt((
        Parser::map(extract_str_literal, StringFragment::Literal),
        Parser::map(parse_escaped_char, StringFragment::EscapedChar),
    ))
    .parse_next(input)
}

fn parse_encoded_string(input: &mut &str) -> ModalResult<Vec<u8>> {
    repeat(0.., parse_str_fragment)
        .fold(
            || Vec::<u8>::with_capacity(input.len()), // capacity guess
            |mut bytes, fragment| {
                match fragment {
                    StringFragment::Literal(s) => bytes.extend(s.as_bytes()),
                    StringFragment::EscapedChar(c) => bytes.push(c),
                }
                bytes
            },
        )
        .parse_next(input)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::sys_trace::strace::tokenizer::{
        Argument, ArgumentStructure, CallOutcome, EncodedString, ProcessExit, Retval, SignalRecv,
        SyscallSegment, TokenizerOutput, extract_encoded_string, nested_braces,
        parse_encoded_string, parse_proc_killed, parse_signal, tokenize, tokenize_syscall,
    };

    use super::{
        nested_brackets, parse_escaped_char, parse_pointer_with_comment_argument, parse_proc_exit,
    };

    #[test]
    fn start_all_retval_states() -> Result<()> {
        let strace = String::from(r"1316971 close(3)                                = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "close",
                arguments: vec![Argument::Numeric("3")],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            r"1316971 close(3)                        = -1 EBADF (Bad file descriptor)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "close",
                arguments: vec![Argument::Numeric("3")],
                outcome: CallOutcome::Complete {
                    retval: Retval::Failure(-1, "EBADF (Bad file descriptor)"),
                }
            }
        );

        let strace = String::from(r"1435293 close(17 <unfinished ...>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1435293",
                function: "close",
                arguments: vec![Argument::Numeric("17")],
                outcome: CallOutcome::Unfinished,
            }
        );

        let strace = String::from(r"34187 read(7,  <unfinished ...>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "34187",
                function: "read",
                arguments: vec![Argument::Numeric("7")],
                outcome: CallOutcome::Unfinished,
            }
        );

        let strace = String::from(
            r"1316971 close(3)                        = ? ERESTARTSYS (To be restarted)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "close",
                arguments: vec![Argument::Numeric("3")],
                outcome: CallOutcome::Complete {
                    retval: Retval::Restart("ERESTARTSYS (To be restarted)"),
                }
            }
        );

        let strace = String::from("299986 brk(NULL)                        = 0x55ad8bba6000");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "299986",
                function: "brk",
                arguments: vec![Argument::Null],
                outcome: CallOutcome::Complete {
                    retval: Retval::SuccessPointer("0x55ad8bba6000"),
                }
            }
        );

        let strace =
            String::from("374970 fcntl(11, F_GETFD)               = 0x1 (flags FD_CLOEXEC)");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "374970",
                function: "fcntl",
                arguments: vec![Argument::Numeric("11"), Argument::Enum("F_GETFD")],
                outcome: CallOutcome::Complete {
                    retval: Retval::SuccessPointer("0x1 (flags FD_CLOEXEC)"),
                }
            }
        );

        // The cases where I've seen this behavior -- "resumed> <unfinished...>" AND "resumed>) = ?" have both occurred
        // right before the process exited.  I'm combining both of these into one "ResumedUnfinished" state because, at
        // least for now, it doesn't seem like I need to do anything differently with them.
        let strace = String::from(r"1316971 <... read resumed> <unfinished ...>) = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        let strace = String::from(r"1316971 <... openat resumed>)           = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "openat",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        let strace = String::from(r"1316971 read(3,  <unfinished ...>)              = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![Argument::Numeric("3")],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        let strace =
            String::from(r"1316971 read(7, )                               = ? <unavailable>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                // ResumedUnfinished doesn't bother providing args back because the outcome of the syscall is undefined
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished,
            }
        );

        // Another unrecognizable mess right before a process exit.  Again since ResumedUnfinished is just suppressed at
        // the sequencer layer, I'll output it like that... but maybe "ResumedUnfinished" is just becoming "terminated
        // during process exit"?
        let strace = String::from(r"1316971 ???( <unfinished ...>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "???",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        let strace = String::from(r"1316971 ???()                                   = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "???",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        let strace = String::from(r"33453 <... ??? resumed>)                = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "33453",
                function: "???",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        // basically anything ending with a ? seems to happen at the end of a process... even a completed call?
        let strace = String::from(
            r#"1316971 openat(AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY|O_CLOEXEC) = ?"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "openat",
                arguments: vec![
                    Argument::Enum("AT_FDCWD"),
                    Argument::String(EncodedString::new("/proc/sys/vm/overcommit_memory")),
                    Argument::Enum("O_RDONLY|O_CLOEXEC"),
                ],
                outcome: CallOutcome::ResumedUnfinished
            }
        );

        let strace = String::from(r"1316971 exit_group(0)                           = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "exit_group",
                arguments: vec![Argument::Numeric("0"),],
                outcome: CallOutcome::ResumedUnfinished
            }
        );

        Ok(())
    }

    #[test]
    fn resumed_all_retval_states() -> Result<()> {
        let strace = String::from(r"189532 <... chdir resumed>)             = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "189532",
                function: "chdir",
                arguments: vec![],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            r"189531 <... chdir resumed>)             = -1 ENOENT (No such file or directory)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "189531",
                function: "chdir",
                arguments: vec![],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Failure(-1, "ENOENT (No such file or directory)")
                }
            }
        );

        Ok(())
    }

    #[test]
    fn various_arguments() -> Result<()> {
        let strace = String::from(r#"1316971 read(3, "", 4096)               = 0"#);
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::String(EncodedString::new("")),
                    Argument::Numeric("4096"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            r"1316971 wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG, NULL) = 4187946",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "wait4",
                arguments: vec![
                    Argument::Numeric("-1"),
                    Argument::WaitFlags("[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]"),
                    Argument::Enum("WNOHANG"),
                    Argument::Null,
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(4_187_946)
                }
            }
        );

        let strace = String::from(
            r"86718 <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 1}], __WALL, NULL) = 86722",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "86718",
                function: "wait4",
                arguments: vec![
                    Argument::WaitFlags("[{WIFEXITED(s) && WEXITSTATUS(s) == 1}]"),
                    Argument::Enum("__WALL"),
                    Argument::Null,
                ],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(86_722)
                }
            }
        );

        let strace = String::from(
            r"42167 <... wait4 resumed>[{WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL}], WNOHANG, NULL) = 42357",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "42167",
                function: "wait4",
                arguments: vec![
                    Argument::WaitFlags("[{WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL}]"),
                    Argument::Enum("WNOHANG"),
                    Argument::Null,
                ],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(42_357)
                }
            }
        );

        let strace = String::from(r#"1316971 read(3, ""..., 4096)               = 0"#);
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::PartialString(EncodedString::new("")),
                    Argument::Numeric("4096"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            r#"1316971 sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00\\", 20, MSG_NOSIGNAL, NULL, 0) = 20"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "sendto",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::String(EncodedString::new(
                        "\\x02\\x00\\x00\\x00\\v\\x00\\x00\\x00\\x07\\x00\\x00\\x00passwd\\x00\\\\"
                    )),
                    Argument::Numeric("20"),
                    Argument::Enum("MSG_NOSIGNAL"),
                    Argument::Null,
                    Argument::Numeric("0"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(20)
                }
            }
        );

        let strace = String::from(r"1316971 tgkill(4143934, 4144060, SIGUSR1)       = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "tgkill",
                arguments: vec![
                    Argument::Numeric("4143934"),
                    Argument::Numeric("4144060"),
                    Argument::Enum("SIGUSR1"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            "1316971 openat(AT_FDCWD, \"/nix/store/ixq7chmml361204anwph16ll2njcf19d-curl-8.11.0/lib/glibc-hwcaps/x86-64-v4/libcurl.so.4\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "openat",
                arguments: vec![
                    Argument::Enum("AT_FDCWD"),
                    Argument::String(EncodedString::new(
                        "/nix/store/ixq7chmml361204anwph16ll2njcf19d-curl-8.11.0/lib/glibc-hwcaps/x86-64-v4/libcurl.so.4"
                    )),
                    Argument::Enum("O_RDONLY|O_CLOEXEC"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Failure(-1, "ENOENT (No such file or directory)")
                }
            }
        );

        let strace = String::from(
            r"1316971 read(17, 0x7fb0f00111d6, 122)   = -1 EAGAIN (Resource temporarily unavailable)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![
                    Argument::Numeric("17"),
                    Argument::Pointer("0x7fb0f00111d6"),
                    Argument::Numeric("122"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Failure(-1, "EAGAIN (Resource temporarily unavailable)")
                }
            }
        );

        let strace = String::from(
            r#"1316971 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "connect",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Named("sa_family", Box::new(Argument::Enum("AF_UNIX"))),
                        Argument::Named(
                            "sun_path",
                            Box::new(Argument::String(EncodedString::new("/var/run/nscd/socket")))
                        )
                    ])),
                    Argument::Numeric("110"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            r"1316971 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "clone",
                arguments: vec![
                    Argument::Named("child_stack", Box::new(Argument::Null)),
                    Argument::Named(
                        "flags",
                        Box::new(Argument::Enum(
                            "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD"
                        ))
                    ),
                    Argument::Named(
                        "child_tidptr",
                        Box::new(Argument::Pointer("0x7f9f93f88a10"))
                    ),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(337_653)
                }
            }
        );

        let strace = String::from(
            r"1316971 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f4223fff990, parent_tid=0x7f4223fff990, exit_signal=0, stack=0x7f42237ff000, stack_size=0x7fff80, tls=0x7f4223fff6c0} => {parent_tid=[1343642]}, 88) = 1343642",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "clone3",
                arguments: vec![
                    Argument::WrittenArgument(
                        Box::new(Argument::Structure(ArgumentStructure::new(vec![
                            Argument::Named(
                                "flags",
                                Box::new(Argument::Enum(
                                    "CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID"
                                ))
                            ),
                            Argument::Named(
                                "child_tid",
                                Box::new(Argument::Pointer("0x7f4223fff990"))
                            ),
                            Argument::Named(
                                "parent_tid",
                                Box::new(Argument::Pointer("0x7f4223fff990"))
                            ),
                            Argument::Named("exit_signal", Box::new(Argument::Numeric("0"))),
                            Argument::Named("stack", Box::new(Argument::Pointer("0x7f42237ff000"))),
                            Argument::Named("stack_size", Box::new(Argument::Pointer("0x7fff80"))),
                            Argument::Named("tls", Box::new(Argument::Pointer("0x7f4223fff6c0"))),
                        ]))),
                        Box::new(Argument::Structure(ArgumentStructure::new(vec![
                            Argument::Named(
                                "parent_tid",
                                Box::new(Argument::Structure(ArgumentStructure::new(vec![
                                    Argument::Numeric("1343642")
                                ])))
                            )
                        ]))),
                    ),
                    Argument::Numeric("88"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(1_343_642)
                }
            }
        );

        let strace = String::from(
            r#"1316971 execve("/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7", ["/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7", "--exact", "basic_ops::tests::test_add"], 0x7ffdf2244ed8 /* 218 vars */) = 0"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "execve",
                arguments: vec![
                    Argument::String(EncodedString::new(
                        "/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7"
                    )),
                    Argument::Structure(ArgumentStructure::new(vec![
                        Argument::String(EncodedString::new(
                            "/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7"
                        )),
                        Argument::String(EncodedString::new("--exact")),
                        Argument::String(EncodedString::new("basic_ops::tests::test_add")),
                    ])),
                    Argument::PointerWithComment("0x7ffdf2244ed8", "/* 218 vars */"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            r"1316971 waitid(P_PIDFD, 184, {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=85784, si_uid=1000, si_status=0, si_utime=0, si_stime=0}, WEXITED, {ru_utime={tv_sec=0, tv_usec=1968}, ru_stime={tv_sec=0, tv_usec=1963}, ...}) = 0",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "waitid",
                arguments: vec![
                    Argument::Enum("P_PIDFD"),
                    Argument::Numeric("184"),
                    Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Named("si_signo", Box::new(Argument::Enum("SIGCHLD"))),
                        Argument::Named("si_code", Box::new(Argument::Enum("CLD_EXITED"))),
                        Argument::Named("si_pid", Box::new(Argument::Numeric("85784"))),
                        Argument::Named("si_uid", Box::new(Argument::Numeric("1000"))),
                        Argument::Named("si_status", Box::new(Argument::Numeric("0"))),
                        Argument::Named("si_utime", Box::new(Argument::Numeric("0"))),
                        Argument::Named("si_stime", Box::new(Argument::Numeric("0"))),
                    ])),
                    Argument::Enum("WEXITED"),
                    Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Named(
                            "ru_utime",
                            Box::new(Argument::Structure(ArgumentStructure::new(vec![
                                Argument::Named("tv_sec", Box::new(Argument::Numeric("0"))),
                                Argument::Named("tv_usec", Box::new(Argument::Numeric("1968")))
                            ])))
                        ),
                        Argument::Named(
                            "ru_stime",
                            Box::new(Argument::Structure(ArgumentStructure::new(vec![
                                Argument::Named("tv_sec", Box::new(Argument::Numeric("0"))),
                                Argument::Named("tv_usec", Box::new(Argument::Numeric("1963")))
                            ])))
                        ),
                    ])),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(r"354914 rt_sigprocmask(SIG_BLOCK, ~[], [], 8) = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "354914",
                function: "rt_sigprocmask",
                arguments: vec![
                    Argument::Enum("SIG_BLOCK"),
                    Argument::InverseStructure(ArgumentStructure::new(vec![])),
                    Argument::Structure(ArgumentStructure::new(vec![])),
                    Argument::Numeric("8"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            "395436 writev(26, [{iov_base=\"POST /api/v0/rust/coverage-data/testtrim-tests/c1 HTTP/1.1\\r\\ncontent-type: application/json\\r\\ncontent-encoding: zstd\\r\\naccept: */*\\r\\nuser-agent: testtrim (0.12.4)\\r\\naccept-encoding: gzip, zstd\\r\\nhost: 127.0.0.1:44861\\r\\ncontent-length: 124\\r\\n\\r\\n\", iov_len=235}, {iov_base=\"(\\xb5/\\xfd\\x00X\\x9d\\x03\\x00\\xc2\\xc7\\x16\\x16\\xa05m\\xb8\\xcd\\xef\\x84\\xc0\\xcb*\\xf2\\x11J\\x99\\xe4\\x17\\x80\\t\\x16\\x06\\xd5\\xf7I\\x82\\xac-\\x9d|\\x9c\\xcax\\xc7\\xc8$\\x0f\\xd4R\\xef\\x96\\xc6)\\xbd\\xc0\\x14\\xb5\\xc6;\\xa5'|\\xc3|\\xf8\\xde\\xfa\\xfa\\x85\\xf2\\xbew\\xb8\\x10M\\x11\\x02\\x80\\xa1,2/\\x02\\xa2\\x91CI\\xbesO\\x13W\\xbf\\xa2P\\xab\\xa4_[\\x9a\\x82\\x04\\x07\\x00t\\xe0\\x15u\\xaf\\x971\\xe2Q\\xcc\\xd4\\x8a\\xa6:o\\x1c\\x1c\\x9bQ\", iov_len=124}], 2 <unfinished ...>",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "395436",
                function: "writev",
                arguments: vec![
                    Argument::Numeric("26"),
                    Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Structure(ArgumentStructure::new(vec![
                            Argument::Named(
                                "iov_base",
                                Box::new(Argument::String(EncodedString::new(
                                    "POST /api/v0/rust/coverage-data/testtrim-tests/c1 HTTP/1.1\\r\\ncontent-type: application/json\\r\\ncontent-encoding: zstd\\r\\naccept: */*\\r\\nuser-agent: testtrim (0.12.4)\\r\\naccept-encoding: gzip, zstd\\r\\nhost: 127.0.0.1:44861\\r\\ncontent-length: 124\\r\\n\\r\\n"
                                )))
                            ),
                            Argument::Named("iov_len", Box::new(Argument::Numeric("235"))),
                        ])),
                        Argument::Structure(ArgumentStructure::new(vec![
                            Argument::Named(
                                "iov_base",
                                Box::new(Argument::String(EncodedString::new(
                                    "(\\xb5/\\xfd\\x00X\\x9d\\x03\\x00\\xc2\\xc7\\x16\\x16\\xa05m\\xb8\\xcd\\xef\\x84\\xc0\\xcb*\\xf2\\x11J\\x99\\xe4\\x17\\x80\\t\\x16\\x06\\xd5\\xf7I\\x82\\xac-\\x9d|\\x9c\\xcax\\xc7\\xc8$\\x0f\\xd4R\\xef\\x96\\xc6)\\xbd\\xc0\\x14\\xb5\\xc6;\\xa5'|\\xc3|\\xf8\\xde\\xfa\\xfa\\x85\\xf2\\xbew\\xb8\\x10M\\x11\\x02\\x80\\xa1,2/\\x02\\xa2\\x91CI\\xbesO\\x13W\\xbf\\xa2P\\xab\\xa4_[\\x9a\\x82\\x04\\x07\\x00t\\xe0\\x15u\\xaf\\x971\\xe2Q\\xcc\\xd4\\x8a\\xa6:o\\x1c\\x1c\\x9bQ"
                                )))
                            ),
                            Argument::Named("iov_len", Box::new(Argument::Numeric("124"))),
                        ])),
                    ])),
                    Argument::Numeric("2"),
                ],
                outcome: CallOutcome::Unfinished
            }
        );

        let strace = String::from(
            "500779 prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "500779",
                function: "prlimit64",
                arguments: vec![
                    Argument::Numeric("0"),
                    Argument::Enum("RLIMIT_STACK"),
                    Argument::Null,
                    Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Named(
                            "rlim_cur",
                            Box::new(Argument::NumericWithConstant("8192*1024"))
                        ),
                        Argument::Named("rlim_max", Box::new(Argument::Enum("RLIM64_INFINITY"))),
                    ])),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let strace = String::from(
            "521386 sched_getaffinity(521386, 32, [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21]) = 8",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "521386",
                function: "sched_getaffinity",
                arguments: vec![
                    Argument::Numeric("521386"),
                    Argument::Numeric("32"),
                    Argument::CpuSet("[0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21]"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(8)
                }
            }
        );

        Ok(())
    }

    #[test]
    fn test_extract_encoded_string() {
        let strace = String::from("\"abc\"");
        let v = extract_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, EncodedString::new("abc"));
        let strace = String::from("\"\"");
        let v = extract_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, EncodedString::new(""));
        let strace = String::from("\"abc\\\"def\"");
        let v = extract_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, EncodedString::new("abc\\\"def"));
        let strace = String::from("\"abc\\x00def\"");
        let v = extract_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, EncodedString::new("abc\\x00def"));
    }

    #[test]
    fn test_parse_escaped_char() {
        let strace = String::from("\\t");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, b'\t');
        let strace = String::from("\\n");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, b'\n');
        let strace = String::from("\\v");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, 0x0b);
        let strace = String::from("\\f");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, 0x0c);
        let strace = String::from("\\r");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, b'\r');
        let strace = String::from("\\\"");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, b'\"');
        let strace = String::from("\\\\");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, b'\\');
        let strace = String::from("\\x00");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, 0x00);
        let strace = String::from("\\xFF");
        let v = parse_escaped_char(&mut strace.as_str()).unwrap();
        assert_eq!(v, 0xFF);
    }

    #[test]
    fn test_parse_pointer_with_comment_argument() {
        let strace = String::from("0x7ffdf2244ed8 /* 218 vars */");
        let arg = parse_pointer_with_comment_argument(&mut strace.as_str()).unwrap();
        assert_eq!(
            arg,
            Argument::PointerWithComment("0x7ffdf2244ed8", "/* 218 vars */")
        );
    }

    #[test]
    fn test_nested_brackets() {
        let strace = String::from(r#"["input"]"#);
        let v = nested_brackets(&mut strace.as_str()).expect("nested_brackets case 1");
        assert_eq!(v, vec![Argument::String(EncodedString::new("input"))]);

        let strace = String::from("[1, [2, 3], 4]");
        let v = nested_brackets(&mut strace.as_str()).expect("nested_brackets case 2");
        assert_eq!(
            v,
            vec![
                Argument::Numeric("1"),
                Argument::Structure(ArgumentStructure::new(vec![
                    Argument::Numeric("2"),
                    Argument::Numeric("3")
                ])),
                Argument::Numeric("4"),
            ]
        );

        let strace = String::from("[123]ut");
        let v = nested_brackets(&mut strace.as_str()).expect("nested_brackets case 3");
        assert_eq!(v, vec![Argument::Numeric("123"),]);

        let strace =
            String::from(r#"["abc 123 ] this is a string but it contains a few ] in it"]"#);
        let v = nested_brackets(&mut strace.as_str()).expect("nested_brackets case 4");
        assert_eq!(
            v,
            vec![Argument::String(EncodedString::new(
                "abc 123 ] this is a string but it contains a few ] in it"
            ))]
        );
    }

    #[test]
    fn test_nested_braces() {
        let strace = String::from("{input=1}");
        let v = nested_braces(&mut strace.as_str()).expect("nested_braces case 1");
        assert_eq!(
            v,
            vec![Argument::Named("input", Box::new(Argument::Numeric("1")))]
        );

        let strace = String::from("{inp=1, abc={def=2}, ghk=3}");
        let v = nested_braces(&mut strace.as_str()).expect("nested_braces case 2");
        assert_eq!(
            v,
            vec![
                Argument::Named("inp", Box::new(Argument::Numeric("1"))),
                Argument::Named(
                    "abc",
                    Box::new(Argument::Structure(ArgumentStructure::new(vec![
                        Argument::Named("def", Box::new(Argument::Numeric("2")))
                    ])))
                ),
                Argument::Named("ghk", Box::new(Argument::Numeric("3"))),
            ]
        );

        let strace = String::from("{inp=123}ut");
        let v = nested_braces(&mut strace.as_str()).expect("nested_braces case 3");
        assert_eq!(
            v,
            vec![Argument::Named("inp", Box::new(Argument::Numeric("123")))]
        );

        let strace = String::from(r#"{field="string with a } in it can be confusing"}"#);
        let v = nested_braces(&mut strace.as_str()).expect("nested_braces case 4");
        assert_eq!(
            v,
            vec![Argument::Named(
                "field",
                Box::new(Argument::String(EncodedString::new(
                    "string with a } in it can be confusing"
                )))
            )]
        );
    }

    #[test]
    fn test_parse_encoded_string() {
        let strace = String::from("abc");
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, Vec::from(b"abc"));
        let strace = String::new();
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, Vec::from(b""));
        let strace = String::from("abc\\\"def");
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, Vec::from(b"abc\"def"));
        let strace = String::from("abc\\x00def");
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, Vec::from(b"abc\x00def"));
        let strace = String::from("Hello!");
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, vec![72, 101, 108, 108, 111, 33]);
        let strace = String::from("\\x00\\x01\\xFF");
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(v, vec![0, 1, 255]);
        let strace = String::from(" dquote: \\\"  more text");
        let v = parse_encoded_string(&mut strace.as_str()).unwrap();
        assert_eq!(
            v,
            vec![
                32, 100, 113, 117, 111, 116, 101, 58, 32, 34, 32, 32, 109, 111, 114, 101, 32, 116,
                101, 120, 116
            ]
        );
    }

    #[test]
    fn test_encoded_string() {
        let s = EncodedString::new("abc\\x00def");
        assert_eq!(s.encoded, "abc\\x00def");
        assert_eq!(s.decoded(), &Vec::from(b"abc\x00def"));
        assert_ne!(s, EncodedString::new("abc\\x00def")); // no longer eq as OnceCell now has value
        let other = EncodedString::new("abc\\x00def");
        let _ = other.decoded();
        assert_eq!(s, other); // sanity check for last test that eq will be eq when OnceCell has value
    }

    #[test]
    fn test_resumed_addt_arguments() -> Result<()> {
        let strace = String::from(r#"1316971 <... read resumed>"abc"..., 1140) = 792"#);
        let tokenized = tokenize_syscall(&mut strace.as_str())?;

        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![
                    Argument::PartialString(EncodedString::new("abc")),
                    Argument::Numeric("1140")
                ],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(792)
                }
            }
        );

        let strace =
            String::from("1316971 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "clone",
                arguments: vec![Argument::Named(
                    "child_tidptr",
                    Box::new(Argument::Pointer("0x7f9f93f88a10"))
                ),],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(337_654)
                }
            }
        );

        let strace = String::from("1316971 <... clone3 resumed> => {parent_tid=[0]}, 88) = 15620");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;

        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "clone3",
                arguments: vec![
                    Argument::WrittenArgumentResumed(Box::new(Argument::Structure(
                        ArgumentStructure::new(vec![Argument::Named(
                            "parent_tid",
                            Box::new(Argument::Structure(ArgumentStructure::new(vec![
                                Argument::Numeric("0")
                            ])))
                        )])
                    ))),
                    Argument::Numeric("88")
                ],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(15_620)
                }
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_proc_exit() {
        let strace = String::from("1316971 +++ exited with 0 +++");
        let exit = parse_proc_exit(&mut strace.as_str()).unwrap();
        assert_eq!(
            exit,
            ProcessExit {
                pid: "1316971",
                exit_code: "0"
            }
        );
    }

    #[test]
    fn test_parse_proc_killed() {
        let strace = String::from("1316971 +++ killed by SIGKILL +++");
        let exit = parse_proc_killed(&mut strace.as_str()).unwrap();
        assert_eq!(
            exit,
            ProcessExit {
                pid: "1316971",
                exit_code: "-1"
            }
        );

        let strace = String::from("4182469 +++ killed by SIGABRT (core dumped) +++");
        let exit = parse_proc_killed(&mut strace.as_str()).unwrap();
        assert_eq!(
            exit,
            ProcessExit {
                pid: "4182469",
                exit_code: "-1"
            }
        );
    }

    #[test]
    fn test_parse_signal() {
        let strace = String::from(
            "337651 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=337653, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---",
        );
        let exit = parse_signal(&mut strace.as_str()).unwrap();
        assert_eq!(
            exit,
            SignalRecv {
                pid: "337651",
                signal: "SIGCHLD"
            }
        );

        let strace = String::from("337651 --- stopped by SIGURG ---");
        let exit = parse_signal(&mut strace.as_str()).unwrap();
        assert_eq!(
            exit,
            SignalRecv {
                pid: "337651",
                signal: "SIGURG"
            }
        );
    }

    #[test]
    fn test_parse_all_results() {
        let strace = String::from("337651 +++ exited with 0 +++");
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Exit(ProcessExit {
                pid: "337651",
                exit_code: "0"
            })
        );
        let strace = String::from("337651 +++ killed by SIGKILL +++");
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Exit(ProcessExit {
                pid: "337651",
                exit_code: "-1"
            })
        );

        let strace = String::from(r"337651 close(3)                        = 0");
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Syscall(SyscallSegment {
                pid: "337651",
                function: "close",
                arguments: vec![Argument::Numeric("3")],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            })
        );
        let strace = String::from("+++ exited with 0 ++");
        let res = tokenize(&mut strace.as_str());
        assert!(res.is_err());
        let strace = String::from(
            "337651 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=337653, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---",
        );
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Signal(SignalRecv {
                pid: "337651",
                signal: "SIGCHLD"
            })
        );
        let strace = String::from(
            "337651 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=9564, si_uid=0, si_status=0, si_utime=2 /* 0.02 s */, si_stime=4 /* 0.04 s */} ---",
        );
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Signal(SignalRecv {
                pid: "337651",
                signal: "SIGCHLD"
            })
        );
    }
}
