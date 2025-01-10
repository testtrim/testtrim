// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::cell::OnceCell;

use anyhow::{Result, anyhow};
use winnow::ascii::{dec_int, digit1, hex_digit1, multispace1};
use winnow::combinator::{alt, delimited, opt, preceded, repeat, separated};
use winnow::token::{literal, none_of, one_of, rest, take_until};
use winnow::token::{take_till, take_while};
use winnow::{PResult, Parser};

#[derive(Debug, PartialEq)]
pub struct EncodedString<'a> {
    pub encoded: &'a str,
    decoded: OnceCell<Vec<u8>>,
}

impl<'a> EncodedString<'a> {
    pub(crate) fn new(encoded: &'a str) -> Self {
        EncodedString {
            encoded,
            decoded: OnceCell::new(),
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

    #[must_use]
    pub fn take(&mut self) -> Vec<u8> {
        self.decoded.get_or_init(|| self.do_decode());
        self.decoded.take().unwrap()
    }
}

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
    /// Structure: {...} or [...]
    Structure(&'a str),
    /// This represents a struct that was passed into a syscall and then modified by the syscall; strace represents it
    /// as {...} => {..} where the first part is the input and the second is the changes made.
    WrittenStructure(&'a str, &'a str),
    /// In the event that a `WrittenStructure` and a `CallOutcome::Resumed` occur at the same time, only the "=> {..}"
    /// part of the argument will be present in the resumed strace line.
    ///
    /// This is an awkward case because it will represent one more argument in the resumed case than in the standard
    /// syscall case -- to compensate for this, the `Sequencer` must merge any Structure arguments followed by a
    /// `WrittenStructureResumed` argument.  At this time I don't know if multiple of these are possible at once which
    /// would be more confusing; but I've only seen a case for a signle.
    WrittenStructureResumed(&'a str),
    /// Enum: `MSG_NOSIGNAL|MSG_NOSIGNAL`
    Enum(&'a str),
    //. Just "NULL"
    Null,
    /// Named argument; eg. `child_tidptr=0x7f9f93f88a10`, arg name will be tuple 0, value 1.
    Named(&'a str, Box<Argument<'a>>),
}

#[derive(Debug, PartialEq)]
pub enum Retval<'a> {
    Success(i32),
    Failure(i32, &'a str), // retval and error code
    Restart(&'a str),      // "? ERESTARTSYS"
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
    pub function: &'a str,
    pub arguments: Vec<Argument<'a>>,
    pub outcome: CallOutcome<'a>,
}

#[derive(Debug, PartialEq)]
pub struct ProcessExit<'a> {
    pub exit_code: &'a str,
}

#[derive(Debug, PartialEq)]
pub struct SignalRecv<'a> {
    pub signal: &'a str,
}

pub fn tokenize<'i>(input: &mut &'i str) -> Result<TokenizerOutput<'i>> {
    internal_tokenize
        .parse(input)
        .map_err(|e| anyhow!("error occurred in strace tokenize: {e:?}"))
}

fn internal_tokenize<'i>(input: &mut &'i str) -> PResult<TokenizerOutput<'i>> {
    alt((
        Parser::map(parse_syscall, TokenizerOutput::Syscall),
        Parser::map(parse_proc_exit, TokenizerOutput::Exit),
        Parser::map(parse_proc_killed, TokenizerOutput::Exit),
        Parser::map(parse_signal, TokenizerOutput::Signal),
    ))
    .parse_next(input)
}

fn parse_proc_exit<'i>(input: &mut &'i str) -> PResult<ProcessExit<'i>> {
    let _ = literal("+++ exited with ").parse_next(input)?;
    let exit_code = digit1(input)?;
    let _ = literal(" +++").parse_next(input)?;
    Ok(ProcessExit { exit_code })
}

fn parse_proc_killed<'i>(input: &mut &'i str) -> PResult<ProcessExit<'i>> {
    let _ = literal("+++ killed by SIGKILL +++").parse_next(input)?;
    Ok(ProcessExit { exit_code: "-1" })
}

fn parse_signal<'i>(input: &mut &'i str) -> PResult<SignalRecv<'i>> {
    alt((parse_signal_format1, parse_signal_format2)).parse_next(input)
}

fn parse_signal_format1<'i>(input: &mut &'i str) -> PResult<SignalRecv<'i>> {
    let _ = literal("---").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let signal = take_while(1.., |c: char| c.is_ascii_uppercase()).parse_next(input)?;
    // pretty lazy here but we don't do anything with signals yet, and may never
    let _ = take_while(0.., |_| true).parse_next(input)?;
    Ok(SignalRecv { signal })
}

fn parse_signal_format2<'i>(input: &mut &'i str) -> PResult<SignalRecv<'i>> {
    let _ = literal("--- stopped by ").parse_next(input)?;
    let signal = take_while(1.., |c: char| c.is_ascii_uppercase()).parse_next(input)?;
    let _ = literal(" ---").parse_next(input)?;
    Ok(SignalRecv { signal })
}

#[cfg(test)]
fn tokenize_syscall<'i>(input: &mut &'i str) -> Result<SyscallSegment<'i>> {
    parse_syscall
        .parse(input)
        .map_err(|e| anyhow!("error occurred in strace parse_syscall: {e:?}"))
}

fn parse_syscall<'i>(input: &mut &'i str) -> PResult<SyscallSegment<'i>> {
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
            function: function_name,
            arguments,
            outcome,
        }),
        InternalLineType::ResumedUnfinished { function_name } => Ok(SyscallSegment {
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

fn parse_line_type<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    alt((
        parse_started_call,
        parse_resumed_call,
        parse_resumed_unfinished_call,
    ))
    .parse_next(input)
}

fn parse_started_call<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
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

fn parse_resumed_call<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    let _ = literal("<... ").parse_next(input)?;
    let function_name = parse_function_name(input)?;
    let _ = literal(" resumed>").parse_next(input)?;
    let _ = opt(literal(", ")).parse_next(input)?; // sometimes "resumed>, ", somtimes straight into args -- can't quite see why it would be one or the other right now
    let resumed = opt((parse_written_structure_resumed, opt(literal(", ")))).parse_next(input)?;
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

fn parse_resumed_unfinished_call<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    alt((
        parse_terminating_process_case1,
        parse_terminating_process_case2,
        parse_terminating_process_case3,
        parse_terminating_process_case4,
    ))
    .parse_next(input)
}

fn parse_terminating_process_case1<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    let _ = literal("<... ").parse_next(input)?;
    let function_name = parse_function_name(input)?;
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

fn parse_terminating_process_case2<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    let _ = literal("???( <unfinished ...>").parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished {
        function_name: "???",
    })
}

fn parse_terminating_process_case3<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    let _ = literal("???()").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("= ?").parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished {
        function_name: "???",
    })
}

fn parse_terminating_process_case4<'i>(input: &mut &'i str) -> PResult<InternalLineType<'i>> {
    let function_name = parse_function_name(input)?;
    let _ = literal("(").parse_next(input)?;
    let _: Vec<Argument> = separated(0.., parse_argument, literal(", ")).parse_next(input)?;
    let _ = literal(", )").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("= ? <unavailable>").parse_next(input)?;
    Ok(InternalLineType::ResumedUnfinished { function_name })
}

fn consume_whitespace<'i>(input: &mut &'i str) -> PResult<&'i str> {
    multispace1(input)
}

fn parse_function_name<'i>(input: &mut &'i str) -> PResult<&'i str> {
    take_while(1.., |c: char| c.is_alphanumeric() || c == '_').parse_next(input)
}

fn parse_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    alt((
        parse_named_argument,
        parse_null_argument,
        parse_enum_argument,
        parse_pointer_with_comment_argument,
        parse_pointer_argument,
        parse_numeric_argument,
        parse_partial_string_argument,
        parse_string_argument,
        parse_written_structure_argument,
        parse_structure_argument,
    ))
    .parse_next(input)
}

fn parse_named_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let name = take_while(1.., |c: char| c.is_ascii_lowercase() || c == '_').parse_next(input)?;
    let _ = literal("=").parse_next(input)?;
    let arg = parse_argument(input)?;
    Ok(Argument::Named(name, Box::new(arg)))
}

fn parse_null_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let _ = literal("NULL").parse_next(input)?;
    Ok(Argument::Null)
}

fn parse_enum_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let arg = (
        one_of(|c: char| c.is_ascii_uppercase()),
        take_while(1.., |c: char| {
            c.is_ascii_uppercase() || c == '_' || c == '|' || c.is_numeric()
        }),
    )
        .take()
        .parse_next(input)?;
    Ok(Argument::Enum(arg))
}

fn parse_numeric_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let arg = (opt(literal("-")), digit1).take().parse_next(input)?;
    Ok(Argument::Numeric(arg))
}

fn parse_string_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let contents = extract_encoded_string(input)?;
    Ok(Argument::String(contents))
}

fn parse_partial_string_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let contents = parse_string_argument(input)?;
    let _ = literal("...").parse_next(input)?;
    let Argument::String(inner_str) = contents else {
        unreachable!()
    };
    Ok(Argument::PartialString(inner_str))
}

fn parse_pointer_with_comment_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let pointer = (literal("0x"), hex_digit1).take().parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let comment = (literal("/*"), take_until(1.., "*/"), literal("*/"))
        .take()
        .parse_next(input)?;
    Ok(Argument::PointerWithComment(pointer, comment))
}

fn parse_pointer_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let something = (literal("0x"), hex_digit1).take().parse_next(input)?;
    Ok(Argument::Pointer(something))
}

fn parse_written_structure_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let orig_struct = parse_structure_argument(input)?;
    let Argument::Structure(orig_struct) = orig_struct else {
        unreachable!()
    };
    let Argument::WrittenStructureResumed(upd_struct) = parse_written_structure_resumed(input)?
    else {
        unreachable!()
    };
    Ok(Argument::WrittenStructure(orig_struct, upd_struct))
}

fn parse_written_structure_resumed<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let _ = literal(" => ").parse_next(input)?;
    let upd_struct = parse_structure_argument(input)?;
    let Argument::Structure(upd_struct) = upd_struct else {
        unreachable!()
    };
    Ok(Argument::WrittenStructureResumed(upd_struct))
}

fn parse_structure_argument<'i>(input: &mut &'i str) -> PResult<Argument<'i>> {
    let structure = alt((nested_brackets, nested_braces)).parse_next(input)?;
    Ok(Argument::Structure(structure))
}

fn nested_brackets<'i>(input: &mut &'i str) -> PResult<&'i str> {
    delimited(
        literal("["),
        repeat::<_, _, Vec<_>, _, _>(
            0..,
            alt((none_of(|c| c == '[' || c == ']').take(), nested_brackets)),
        ),
        literal("]"),
    )
    .take()
    .parse_next(input)
}

fn nested_braces<'i>(input: &mut &'i str) -> PResult<&'i str> {
    delimited(
        literal("{"),
        repeat::<_, _, Vec<_>, _, _>(
            0..,
            alt((none_of(|c| c == '{' || c == '}').take(), nested_braces)),
        ),
        literal("}"),
    )
    .take()
    .parse_next(input)
}

fn parse_started_call_outcome<'i>(input: &mut &'i str) -> PResult<CallOutcome<'i>> {
    alt((parse_complete_outcome, parse_unfinished_outcome)).parse_next(input)
}

fn parse_complete_outcome<'i>(input: &mut &'i str) -> PResult<CallOutcome<'i>> {
    let _ = literal(")").parse_next(input)?;
    let _ = consume_whitespace(input)?;
    let _ = literal("=").parse_next(input)?;

    alt((parse_end_with_retval, parse_end_with_qmark)).parse_next(input)
}

fn parse_end_with_retval<'i>(input: &mut &'i str) -> PResult<CallOutcome<'i>> {
    let _ = consume_whitespace(input)?;
    let retval = parse_retval(input)?;
    Ok(CallOutcome::Complete { retval })
}

fn parse_end_with_qmark<'i>(input: &mut &'i str) -> PResult<CallOutcome<'i>> {
    let _ = consume_whitespace(input)?;
    let _ = literal("?").parse_next(input)?;
    Ok(CallOutcome::ResumedUnfinished)
}

fn parse_retval<'i>(input: &mut &'i str) -> PResult<Retval<'i>> {
    alt((
        parse_error_retval,
        parse_success_retval,
        parse_restart_retval,
    ))
    .parse_next(input)
}

fn parse_success_retval<'i>(input: &mut &'i str) -> PResult<Retval<'i>> {
    let arg = dec_int(input)?;
    Ok(Retval::Success(arg))
}

fn parse_error_retval<'i>(input: &mut &'i str) -> PResult<Retval<'i>> {
    let value = dec_int(input)?;
    let _ = consume_whitespace(input)?;
    let err = rest(input)?;
    Ok(Retval::Failure(value, err))
}

fn parse_restart_retval<'i>(input: &mut &'i str) -> PResult<Retval<'i>> {
    let _ = literal("? ").parse_next(input)?;
    let rem = rest(input)?;
    Ok(Retval::Restart(rem))
}

fn parse_unfinished_outcome<'i>(input: &mut &'i str) -> PResult<CallOutcome<'i>> {
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

fn extract_encoded_string<'i>(input: &mut &'i str) -> PResult<EncodedString<'i>> {
    // FIXME: not supporting backslash-escaped double-quotes here yet
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
fn extract_str_escape<'i>(input: &mut &'i str) -> PResult<&'i str> {
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
fn parse_escaped_char(input: &mut &str) -> PResult<u8> {
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

fn extract_hex_byte(input: &mut &str) -> PResult<char> {
    let parse_hex = take_while(2..=2, |c: char| c.is_ascii_hexdigit());
    preceded(one_of('x'), parse_hex)
        .map(|_| ' ')
        .parse_next(input)
}

fn parse_hex_byte(input: &mut &str) -> PResult<u8> {
    let parse_hex = take_while(2..=2, |c: char| c.is_ascii_hexdigit());
    let parse_delimited_hex = preceded(one_of('x'), parse_hex);
    let mut parse_u8 = Parser::try_map(parse_delimited_hex, move |hex| u8::from_str_radix(hex, 16));
    parse_u8.parse_next(input)
}

fn extract_str_literal<'i>(input: &mut &'i str) -> PResult<&'i str> {
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

fn parse_str_fragment<'i>(input: &mut &'i str) -> PResult<StringFragment<'i>> {
    alt((
        Parser::map(extract_str_literal, StringFragment::Literal),
        Parser::map(parse_escaped_char, StringFragment::EscapedChar),
    ))
    .parse_next(input)
}

fn parse_encoded_string(input: &mut &str) -> PResult<Vec<u8>> {
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
        Argument, CallOutcome, EncodedString, ProcessExit, Retval, SignalRecv, SyscallSegment,
        TokenizerOutput, extract_encoded_string, nested_braces, parse_encoded_string,
        parse_proc_killed, parse_signal, tokenize, tokenize_syscall,
    };

    use super::{
        nested_brackets, parse_escaped_char, parse_pointer_with_comment_argument, parse_proc_exit,
    };

    #[test]
    fn start_all_retval_states() -> Result<()> {
        let strace = String::from(r"close(3)                                = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "close",
            arguments: vec![Argument::Numeric("3")],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

        let strace =
            String::from(r"close(3)                        = -1 EBADF (Bad file descriptor)");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "close",
            arguments: vec![Argument::Numeric("3")],
            outcome: CallOutcome::Complete {
                retval: Retval::Failure(-1, "EBADF (Bad file descriptor)"),
            }
        });

        let strace = String::from(r"close(17 <unfinished ...>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "close",
            arguments: vec![Argument::Numeric("17")],
            outcome: CallOutcome::Unfinished,
        });

        let strace = String::from(r"read(7,  <unfinished ...>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![Argument::Numeric("7")],
            outcome: CallOutcome::Unfinished,
        });

        let strace =
            String::from(r"close(3)                        = ? ERESTARTSYS (To be restarted)");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "close",
            arguments: vec![Argument::Numeric("3")],
            outcome: CallOutcome::Complete {
                retval: Retval::Restart("ERESTARTSYS (To be restarted)"),
            }
        });

        // The cases where I've seen this behavior -- "resumed> <unfinished...>" AND "resumed>) = ?" have both occurred
        // right before the process exited.  I'm combining both of these into one "ResumedUnfinished" state because, at
        // least for now, it doesn't seem like I need to do anything differently with them.
        let strace = String::from(r"<... read resumed> <unfinished ...>) = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![],
            outcome: CallOutcome::ResumedUnfinished
        });
        let strace = String::from(r"<... openat resumed>)           = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "openat",
            arguments: vec![],
            outcome: CallOutcome::ResumedUnfinished
        });
        let strace = String::from(r"read(3,  <unfinished ...>)              = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![Argument::Numeric("3")],
            outcome: CallOutcome::ResumedUnfinished
        });
        let strace = String::from(r"read(7, )                               = ? <unavailable>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            // ResumedUnfinished doesn't bother providing args back because the outcome of the syscall is undefined
            arguments: vec![],
            outcome: CallOutcome::ResumedUnfinished,
        });

        // Another unrecognizable mess right before a process exit.  Again since ResumedUnfinished is just suppressed at
        // the sequencer layer, I'll output it like that... but maybe "ResumedUnfinished" is just becoming "terminated
        // during process exit"?
        let strace = String::from(r"???( <unfinished ...>");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "???",
            arguments: vec![],
            outcome: CallOutcome::ResumedUnfinished
        });
        let strace = String::from(r"???()                                   = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "???",
            arguments: vec![],
            outcome: CallOutcome::ResumedUnfinished
        });
        // basically anything ending with a ? seems to happen at the end of a process... even a completed call?
        let strace = String::from(
            r#"openat(AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY|O_CLOEXEC) = ?"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "openat",
            arguments: vec![
                Argument::Enum("AT_FDCWD"),
                Argument::String(EncodedString::new("/proc/sys/vm/overcommit_memory")),
                Argument::Enum("O_RDONLY|O_CLOEXEC"),
            ],
            outcome: CallOutcome::ResumedUnfinished
        });

        let strace = String::from(r"exit_group(0)                           = ?");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "exit_group",
            arguments: vec![Argument::Numeric("0"),],
            outcome: CallOutcome::ResumedUnfinished
        });

        Ok(())
    }

    #[test]
    fn resumed_all_retval_states() -> Result<()> {
        let strace = String::from(r"<... chdir resumed>)             = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "chdir",
            arguments: vec![],
            outcome: CallOutcome::Resumed {
                retval: Retval::Success(0)
            }
        });

        let strace = String::from(
            r"<... chdir resumed>)             = -1 ENOENT (No such file or directory)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "chdir",
            arguments: vec![],
            outcome: CallOutcome::Resumed {
                retval: Retval::Failure(-1, "ENOENT (No such file or directory)")
            }
        });

        Ok(())
    }

    #[test]
    fn various_arguments() -> Result<()> {
        let strace = String::from(r#"read(3, "", 4096)               = 0"#);
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![
                Argument::Numeric("3"),
                Argument::String(EncodedString::new("")),
                Argument::Numeric("4096"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

        let strace = String::from(
            r"wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG, NULL) = 4187946",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "wait4",
            arguments: vec![
                Argument::Numeric("-1"),
                Argument::Structure("[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]"),
                Argument::Enum("WNOHANG"),
                Argument::Null,
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(4_187_946)
            }
        });

        let strace = String::from(r#"read(3, ""..., 4096)               = 0"#);
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![
                Argument::Numeric("3"),
                Argument::PartialString(EncodedString::new("")),
                Argument::Numeric("4096"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

        let strace = String::from(
            r#"sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00\\", 20, MSG_NOSIGNAL, NULL, 0) = 20"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
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
        });

        let strace = String::from(r"tgkill(4143934, 4144060, SIGUSR1)       = 0");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "tgkill",
            arguments: vec![
                Argument::Numeric("4143934"),
                Argument::Numeric("4144060"),
                Argument::Enum("SIGUSR1"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

        let strace = String::from(
            "openat(AT_FDCWD, \"/nix/store/ixq7chmml361204anwph16ll2njcf19d-curl-8.11.0/lib/glibc-hwcaps/x86-64-v4/libcurl.so.4\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "openat",
            arguments: vec![
                Argument::Enum("AT_FDCWD"),
                Argument::String(EncodedString::new(
                    "/nix/store/ixq7chmml361204anwph16ll2njcf19d-curl-8.11.0/lib/glibc-hwcaps/x86-64-v4/libcurl.so.4"
                ),),
                Argument::Enum("O_RDONLY|O_CLOEXEC"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Failure(-1, "ENOENT (No such file or directory)")
            }
        });

        let strace = String::from(
            r"read(17, 0x7fb0f00111d6, 122)   = -1 EAGAIN (Resource temporarily unavailable)",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![
                Argument::Numeric("17"),
                Argument::Pointer("0x7fb0f00111d6"),
                Argument::Numeric("122"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Failure(-1, "EAGAIN (Resource temporarily unavailable)")
            }
        });

        let strace = String::from(
            r#"connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "connect",
            arguments: vec![
                Argument::Numeric("3"),
                Argument::Structure(r#"{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}"#),
                Argument::Numeric("110"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

        let strace = String::from(
            r"clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
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
        });

        let strace = String::from(
            r"clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f4223fff990, parent_tid=0x7f4223fff990, exit_signal=0, stack=0x7f42237ff000, stack_size=0x7fff80, tls=0x7f4223fff6c0} => {parent_tid=[1343642]}, 88) = 1343642",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "clone3",
            arguments: vec![
                Argument::WrittenStructure(
                    "{flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f4223fff990, parent_tid=0x7f4223fff990, exit_signal=0, stack=0x7f42237ff000, stack_size=0x7fff80, tls=0x7f4223fff6c0}",
                    "{parent_tid=[1343642]}"
                ),
                Argument::Numeric("88"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(1_343_642)
            }
        });

        let strace = String::from(
            r#"execve("/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7", ["/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7", "--exact", "basic_ops::tests::test_add"], 0x7ffdf2244ed8 /* 218 vars */) = 0"#,
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "execve",
            arguments: vec![
                Argument::String(EncodedString::new(
                    "/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7"
                )),
                Argument::Structure(
                    r#"["/tmp/testtrim-test.ZPFzcuIZaMIL/rust-coverage-specimen/target/debug/deps/rust_coverage_specimen-5763007524fa57f7", "--exact", "basic_ops::tests::test_add"]"#
                ),
                Argument::PointerWithComment("0x7ffdf2244ed8", "/* 218 vars */"),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

        let strace = String::from(
            r"waitid(P_PIDFD, 184, {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=85784, si_uid=1000, si_status=0, si_utime=0, si_stime=0}, WEXITED, {ru_utime={tv_sec=0, tv_usec=1968}, ru_stime={tv_sec=0, tv_usec=1963}, ...}) = 0",
        );
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "waitid",
            arguments: vec![
                Argument::Enum("P_PIDFD"),
                Argument::Numeric("184"),
                Argument::Structure(
                    "{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=85784, si_uid=1000, si_status=0, si_utime=0, si_stime=0}"
                ),
                Argument::Enum("WEXITED"),
                Argument::Structure(
                    "{ru_utime={tv_sec=0, tv_usec=1968}, ru_stime={tv_sec=0, tv_usec=1963}, ...}"
                ),
            ],
            outcome: CallOutcome::Complete {
                retval: Retval::Success(0)
            }
        });

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
        let strace = String::from("[input]");
        let v = nested_brackets(&mut strace.as_str()).unwrap();
        assert_eq!(v, "[input]");
        let strace = String::from("[inp[ [abc] u]t]");
        let v = nested_brackets(&mut strace.as_str()).unwrap();
        assert_eq!(v, "[inp[ [abc] u]t]");
        let strace = String::from("[inp]ut");
        let v = nested_brackets(&mut strace.as_str()).unwrap();
        assert_eq!(v, "[inp]");
    }

    #[test]
    fn test_nested_braces() {
        let strace = String::from("{input}");
        let v = nested_braces(&mut strace.as_str()).unwrap();
        assert_eq!(v, "{input}");
        let strace = String::from("{inp{ {abc} u}t}");
        let v = nested_braces(&mut strace.as_str()).unwrap();
        assert_eq!(v, "{inp{ {abc} u}t}");
        let strace = String::from("{inp}ut");
        let v = nested_braces(&mut strace.as_str()).unwrap();
        assert_eq!(v, "{inp}");
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
        assert_eq!(v, vec![
            32, 100, 113, 117, 111, 116, 101, 58, 32, 34, 32, 32, 109, 111, 114, 101, 32, 116, 101,
            120, 116
        ]);
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
        let strace = String::from(r#"<... read resumed>"abc"..., 1140) = 792"#);
        let tokenized = tokenize_syscall(&mut strace.as_str())?;

        assert_eq!(tokenized, SyscallSegment {
            function: "read",
            arguments: vec![
                Argument::PartialString(EncodedString::new("abc")),
                Argument::Numeric("1140")
            ],
            outcome: CallOutcome::Resumed {
                retval: Retval::Success(792)
            }
        });

        let strace = String::from("<... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;
        assert_eq!(tokenized, SyscallSegment {
            function: "clone",
            arguments: vec![Argument::Named(
                "child_tidptr",
                Box::new(Argument::Pointer("0x7f9f93f88a10"))
            ),],
            outcome: CallOutcome::Resumed {
                retval: Retval::Success(337_654)
            }
        });

        let strace = String::from("<... clone3 resumed> => {parent_tid=[0]}, 88) = 15620");
        let tokenized = tokenize_syscall(&mut strace.as_str())?;

        assert_eq!(tokenized, SyscallSegment {
            function: "clone3",
            arguments: vec![
                Argument::WrittenStructureResumed("{parent_tid=[0]}"),
                Argument::Numeric("88")
            ],
            outcome: CallOutcome::Resumed {
                retval: Retval::Success(15_620)
            }
        });

        Ok(())
    }

    #[test]
    fn test_parse_proc_exit() {
        let strace = String::from("+++ exited with 0 +++");
        let exit = parse_proc_exit(&mut strace.as_str()).unwrap();
        assert_eq!(exit, ProcessExit { exit_code: "0" });
    }

    #[test]
    fn test_parse_proc_killed() {
        let strace = String::from("+++ killed by SIGKILL +++");
        let exit = parse_proc_killed(&mut strace.as_str()).unwrap();
        assert_eq!(exit, ProcessExit { exit_code: "-1" });
    }

    #[test]
    fn test_parse_signal() {
        let strace = String::from(
            "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=337653, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---",
        );
        let exit = parse_signal(&mut strace.as_str()).unwrap();
        assert_eq!(exit, SignalRecv { signal: "SIGCHLD" });

        let strace = String::from("--- stopped by SIGURG ---");
        let exit = parse_signal(&mut strace.as_str()).unwrap();
        assert_eq!(exit, SignalRecv { signal: "SIGURG" });
    }

    #[test]
    fn test_parse_all_results() {
        let strace = String::from("+++ exited with 0 +++");
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(res, TokenizerOutput::Exit(ProcessExit { exit_code: "0" }));
        let strace = String::from("+++ killed by SIGKILL +++");
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(res, TokenizerOutput::Exit(ProcessExit { exit_code: "-1" }));

        let strace = String::from(r"close(3)                        = 0");
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Syscall(SyscallSegment {
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
            "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=337653, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---",
        );
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Signal(SignalRecv { signal: "SIGCHLD" })
        );
        let strace = String::from(
            "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=9564, si_uid=0, si_status=0, si_utime=2 /* 0.02 s */, si_stime=4 /* 0.04 s */} ---",
        );
        let res = tokenize(&mut strace.as_str()).unwrap();
        assert_eq!(
            res,
            TokenizerOutput::Signal(SignalRecv { signal: "SIGCHLD" })
        );
    }
}
