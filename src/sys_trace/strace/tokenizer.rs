// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, take_while, take_while1, take_while_m_n};
use nom::character::complete::{self, alphanumeric1, digit1, hex_digit1, multispace1, none_of};
use nom::combinator::{map, map_res, opt, recognize, value, verify};
use nom::multi::{fold_many0, many0, separated_list0};
use nom::sequence::{delimited, preceded, tuple};
use nom::{IResult, Parser as _};

#[derive(Debug, PartialEq, Clone)]
pub enum Argument<'a> {
    /// Argument in the form of double-quote delimited string, eg. "contents".  The value is the interior of the string
    /// decoded into a u8 vector.  This is likely usable as a `CStr`, but could also be a data buffer that can contain
    /// null bytes.
    String(Vec<u8>),
    /// String(_) which has been truncated due to limited "--string-limit"; ref is to the interior of the partial string
    /// same as String(_).
    PartialString(Vec<u8>),
    /// Numeric value, eg. "3"
    Numeric(&'a str),
    /// Pointer: 0x...
    Pointer(&'a str),
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

pub fn tokenize(input: &str) -> Result<TokenizerOutput<'_>> {
    match internal_tokenize(input) {
        Ok((input, function_call)) => {
            if input.is_empty() {
                Ok(function_call)
            } else {
                Err(anyhow!(
                    "strace tokenize had unexpected remaining results {input:?}"
                ))
            }
        }
        Err(e) => Err(anyhow!("error occurred in strace tokenize: {e:?}")),
    }
}

fn internal_tokenize(input: &str) -> IResult<&str, TokenizerOutput<'_>> {
    alt((
        map(parse_syscall, TokenizerOutput::Syscall),
        map(parse_proc_exit, TokenizerOutput::Exit),
        map(parse_signal, TokenizerOutput::Signal),
    ))
    .parse(input)
}

fn parse_proc_exit(input: &str) -> IResult<&str, ProcessExit<'_>> {
    let (input, pid) = parse_pid(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, _) = tag("+++ exited with ")(input)?;
    let (input, exit_code) = digit1(input)?;
    let (input, _) = tag(" +++")(input)?;
    Ok((input, ProcessExit { pid, exit_code }))
}

fn parse_signal(input: &str) -> IResult<&str, SignalRecv<'_>> {
    let (input, pid) = parse_pid(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, _) = tag("---")(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, signal) = take_while1(|c: char| c.is_ascii_uppercase())(input)?;
    // pretty lazy here but we don't do anything with signals yet, and may never
    let (input, _) = take_while(|_| true)(input)?;
    Ok((input, SignalRecv { pid, signal }))
}

#[cfg(test)]
fn tokenize_syscall(input: &str) -> Result<SyscallSegment<'_>> {
    match parse_syscall(input) {
        Ok((input, function_call)) => {
            if input.is_empty() {
                Ok(function_call)
            } else {
                Err(anyhow!(
                    "strace tokenize had unexpected remaining results {input:?}"
                ))
            }
        }
        Err(e) => Err(anyhow!("error occurred in strace tokenize: {e:?}")),
    }
}

fn parse_syscall(input: &str) -> IResult<&str, SyscallSegment<'_>> {
    let (input, pid) = parse_pid(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, line_type) = parse_line_type(input)?;

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
        } => Ok((
            input,
            SyscallSegment {
                pid,
                function: function_name,
                arguments,
                outcome,
            },
        )),
        InternalLineType::ResumedUnfinished { function_name } => Ok((
            input,
            SyscallSegment {
                pid,
                function: function_name,
                arguments: Vec::new(),
                outcome: CallOutcome::ResumedUnfinished,
            },
        )),
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

fn parse_line_type(input: &str) -> IResult<&str, InternalLineType> {
    alt((
        parse_started_call,
        parse_resumed_call,
        parse_resumed_unfinished_call,
    ))(input)
}

fn parse_started_call(input: &str) -> IResult<&str, InternalLineType> {
    let (input, function_name) = parse_function_name(input)?;
    let (input, _) = tag("(")(input)?;
    let (input, arguments) = separated_list0(tag(", "), parse_argument)(input)?;
    let (input, outcome) = parse_started_call_outcome(input)?;
    Ok((
        input,
        InternalLineType::Started {
            function_name,
            arguments,
            outcome,
        },
    ))
}

fn parse_resumed_call(input: &str) -> IResult<&str, InternalLineType> {
    let (input, _) = tag("<... ")(input)?;
    let (input, function_name) = parse_function_name(input)?;
    let (input, _) = tag(" resumed>")(input)?;
    let (input, _) = opt(tag(", "))(input)?; // sometimes "resumed>, ", somtimes straight into args -- can't quite see why it would be one or the other right now
    let (input, resumed) = opt(tuple((parse_written_structure_resumed, opt(tag(", ")))))(input)?;
    let (input, mut arguments) = separated_list0(tag(", "), parse_argument)(input)?;
    if let Some((resumed_arg, _)) = resumed {
        // handles uncommon case of a structure write after a resumed; don't love inserting into the head of a vec but
        // it's probably OK given the rarity.
        // 15615 <... clone3 resumed> => {parent_tid=[0]}, 88) = 15620
        arguments.insert(0, resumed_arg);
    }
    let (input, outcome) = parse_complete_outcome(input)?;
    let outcome = match outcome {
        CallOutcome::Complete { retval } => CallOutcome::Resumed { retval },
        _ => unreachable!(),
    };
    Ok((
        input,
        InternalLineType::Resumed {
            function_name,
            arguments,
            outcome,
        },
    ))
}

fn parse_resumed_unfinished_call(input: &str) -> IResult<&str, InternalLineType> {
    alt((
        parse_terminating_process_case1,
        parse_terminating_process_case2,
    ))(input)
}

fn parse_terminating_process_case1(input: &str) -> IResult<&str, InternalLineType> {
    let (input, _) = tag("<... ")(input)?;
    let (input, function_name) = parse_function_name(input)?;
    let (input, _) = tag(" resumed>")(input)?;
    let (input, _) = alt((
        recognize(tuple((consume_whitespace, tag("<unfinished ...>) = ?")))),
        recognize(tuple((tag(")"), consume_whitespace, tag("= ?")))),
    ))(input)?;
    Ok((input, InternalLineType::ResumedUnfinished { function_name }))
}

fn parse_terminating_process_case2(input: &str) -> IResult<&str, InternalLineType> {
    let (input, _) = tag("???( <unfinished ...>")(input)?;
    Ok((
        input,
        InternalLineType::ResumedUnfinished {
            function_name: "???",
        },
    ))
}

fn consume_whitespace(input: &str) -> IResult<&str, &str> {
    multispace1(input)
}

fn parse_pid(input: &str) -> IResult<&str, &str> {
    digit1(input)
}

fn parse_function_name(input: &str) -> IResult<&str, &str> {
    alphanumeric1(input)
}

fn parse_argument(input: &str) -> IResult<&str, Argument<'_>> {
    alt((
        parse_named_argument,
        parse_null_argument,
        parse_enum_argument,
        parse_pointer_argument,
        parse_numeric_argument,
        parse_partial_string_argument,
        parse_string_argument,
        parse_written_structure_argument,
        parse_structure_argument,
    ))(input)
}

fn parse_named_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, name) = take_while1(|c: char| c.is_ascii_lowercase() || c == '_')(input)?;
    let (input, _) = tag("=")(input)?;
    let (input, arg) = parse_argument(input)?;
    Ok((input, Argument::Named(name, Box::new(arg))))
}

fn parse_null_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, _) = tag("NULL")(input)?;
    Ok((input, Argument::Null))
}

fn parse_enum_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, arg) =
        take_while1(|c: char| c.is_ascii_uppercase() || c == '_' || c == '|')(input)?;
    Ok((input, Argument::Enum(arg)))
}

fn parse_numeric_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, arg) = digit1(input)?;
    Ok((input, Argument::Numeric(arg)))
}

fn parse_string_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, contents) = parse_string(input)?;
    Ok((input, Argument::String(contents)))
}

fn parse_partial_string_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, contents) = parse_string_argument(input)?;
    let (input, _) = tag("...")(input)?;
    let Argument::String(inner_str) = contents else {
        unreachable!()
    };
    Ok((input, Argument::PartialString(inner_str)))
}

fn parse_pointer_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, something) = recognize(tuple((tag("0x"), hex_digit1)))(input)?;
    Ok((input, Argument::Pointer(something)))
}

fn parse_written_structure_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, orig_struct) = parse_structure_argument(input)?;
    let Argument::Structure(orig_struct) = orig_struct else {
        unreachable!()
    };
    let (input, Argument::WrittenStructureResumed(upd_struct)) =
        parse_written_structure_resumed(input)?
    else {
        unreachable!()
    };
    Ok((input, Argument::WrittenStructure(orig_struct, upd_struct)))
}

fn parse_written_structure_resumed(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, _) = tag(" => ")(input)?;
    let (input, upd_struct) = parse_structure_argument(input)?;
    let Argument::Structure(upd_struct) = upd_struct else {
        unreachable!()
    };
    Ok((input, Argument::WrittenStructureResumed(upd_struct)))
}

fn parse_structure_argument(input: &str) -> IResult<&str, Argument<'_>> {
    let (input, structure) = alt((nested_brackets, nested_braces))(input)?;
    Ok((input, Argument::Structure(structure)))
}

fn nested_brackets(input: &str) -> IResult<&str, &str> {
    recognize(delimited(
        tag("["),
        many0(alt((recognize(none_of("[]")), nested_brackets))),
        tag("]"),
    ))(input)
}

fn nested_braces(input: &str) -> IResult<&str, &str> {
    recognize(delimited(
        tag("{"),
        many0(alt((recognize(none_of("{}")), nested_brackets))),
        tag("}"),
    ))(input)
}

fn parse_started_call_outcome(input: &str) -> IResult<&str, CallOutcome<'_>> {
    alt((parse_complete_outcome, parse_unfinished_outcome))(input)
}

fn parse_complete_outcome(input: &str) -> IResult<&str, CallOutcome<'_>> {
    let (input, _) = tag(")")(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, _) = tag("=")(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, retval) = parse_retval(input)?;
    Ok((input, CallOutcome::Complete { retval }))
}

fn parse_retval(input: &str) -> IResult<&str, Retval<'_>> {
    alt((
        parse_error_retval,
        parse_success_retval,
        parse_restart_retval,
    ))(input)
}

fn parse_success_retval(input: &str) -> IResult<&str, Retval<'_>> {
    let (input, arg) = complete::i32(input)?;
    Ok((input, Retval::Success(arg)))
}

fn parse_error_retval(input: &str) -> IResult<&str, Retval<'_>> {
    let (input, value) = complete::i32(input)?;
    let (input, _) = consume_whitespace(input)?;
    Ok(("", Retval::Failure(value, input)))
}

fn parse_restart_retval(input: &str) -> IResult<&str, Retval<'_>> {
    let (input, _) = tag("? ")(input)?;
    Ok(("", Retval::Restart(input)))
}

fn parse_unfinished_outcome(input: &str) -> IResult<&str, CallOutcome<'_>> {
    // sometimes the last argument has a ",", then whitespace, then "<unfinished ...>".  Not sure why -- have observed
    // (and have test case covering) `read` doing this.
    let (input, _) = opt(tag(","))(input)?;
    let (input, _) = consume_whitespace(input)?;
    let (input, _) = tag("<unfinished ...>")(input)?;
    Ok((input, CallOutcome::Unfinished))
}

fn parse_hex_byte(input: &str) -> IResult<&str, u8> {
    let parse_hex = take_while_m_n(2, 2, |c: char| c.is_ascii_hexdigit());
    let parse_delimited_hex = preceded(complete::char('x'), parse_hex);
    let mut parse_u8 = map_res(parse_delimited_hex, move |hex| u8::from_str_radix(hex, 16));
    parse_u8.parse(input)
}

/// Parse an escaped character: \n, \t, \r, \u{00AC}, etc.
fn parse_escaped_char(input: &str) -> IResult<&str, u8> {
    preceded(
        complete::char('\\'),
        alt((
            // hex: \x00
            parse_hex_byte,
            // `man strace` -> \t, \n, \v, \f, \r are all possible
            value(b'\t', complete::char('t')),  // Tab
            value(b'\n', complete::char('n')),  // Newline
            value(0x0b, complete::char('v')),   // Vertical tab
            value(0x0c, complete::char('f')),   // form feed page break
            value(b'\r', complete::char('r')),  // Carriage return
            value(b'"', complete::char('"')),   // Escaped double-quote
            value(b'\\', complete::char('\\')), // Backslash escaped
        )),
    )
    .parse(input)
}

fn parse_str_literal(input: &str) -> IResult<&str, &str> {
    let not_quote_slash = is_not("\"\\");
    verify(not_quote_slash, |s: &str| !s.is_empty()).parse(input)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringFragment<'a> {
    Literal(&'a str),
    EscapedChar(u8),
}

fn parse_str_fragment(input: &str) -> IResult<&str, StringFragment<'_>> {
    alt((
        map(parse_str_literal, StringFragment::Literal),
        map(parse_escaped_char, StringFragment::EscapedChar),
    ))
    .parse(input)
}

fn parse_string(input: &str) -> IResult<&str, Vec<u8>> {
    let build_string = fold_many0(
        parse_str_fragment,
        || Vec::<u8>::with_capacity(input.len()), // capacity guess
        |mut bytes, fragment| {
            match fragment {
                StringFragment::Literal(s) => bytes.extend(s.as_bytes()),
                StringFragment::EscapedChar(c) => bytes.push(c),
            }
            bytes
        },
    );
    delimited(complete::char('"'), build_string, complete::char('"')).parse(input)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::sys_trace::strace::tokenizer::{
        parse_signal, parse_string, tokenize, tokenize_syscall, Argument, CallOutcome, ProcessExit,
        Retval, SignalRecv, SyscallSegment, TokenizerOutput,
    };

    use super::{nested_brackets, parse_escaped_char, parse_proc_exit};

    #[test]
    fn start_all_retval_states() -> Result<()> {
        let tokenized = tokenize_syscall(r"1316971 close(3)                        = 0")?;
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

        let tokenized = tokenize_syscall(
            r"1316971 close(3)                        = -1 EBADF (Bad file descriptor)",
        )?;
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

        let tokenized = tokenize_syscall(r"1435293 close(17 <unfinished ...>")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1435293",
                function: "close",
                arguments: vec![Argument::Numeric("17")],
                outcome: CallOutcome::Unfinished,
            }
        );

        let tokenized = tokenize_syscall(r"34187 read(7,  <unfinished ...>")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "34187",
                function: "read",
                arguments: vec![Argument::Numeric("7")],
                outcome: CallOutcome::Unfinished,
            }
        );

        let tokenized = tokenize_syscall(
            r"1316971 close(3)                        = ? ERESTARTSYS (To be restarted)",
        )?;
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

        // The cases where I've seen this behavior -- "resumed> <unfinished...>" AND "resumed>) = ?" have both occurred
        // right before the process exited.  I'm combining both of these into one "ResumedUnfinished" state because, at
        // least for now, it doesn't seem like I need to do anything differently with them.
        let tokenized = tokenize_syscall(r"3101180 <... read resumed> <unfinished ...>) = ?")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "3101180",
                function: "read",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        let tokenized = tokenize_syscall(r"3139449 <... openat resumed>)           = ?")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "3139449",
                function: "openat",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );
        // Another unrecognizable mess right before a process exit.  Again since ResumedUnfinished is just suppressed at
        // the sequencer layer, I'll output it like that... but maybe "ResumedUnfinished" is just becoming "terminated
        // during process exit"?
        let tokenized = tokenize_syscall(r"3165682 ???( <unfinished ...>")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "3165682",
                function: "???",
                arguments: vec![],
                outcome: CallOutcome::ResumedUnfinished
            }
        );

        Ok(())
    }

    #[test]
    fn resumed_all_retval_states() -> Result<()> {
        let tokenized = tokenize_syscall(r"189532 <... chdir resumed>)             = 0")?;
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

        let tokenized = tokenize_syscall(
            r"189531 <... chdir resumed>)             = -1 ENOENT (No such file or directory)",
        )?;
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
        let tokenized = tokenize_syscall(r#"1316971 read(3, "", 4096)               = 0"#)?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::String(vec![]),
                    Argument::Numeric("4096"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let tokenized = tokenize_syscall(r#"1316971 read(3, ""..., 4096)               = 0"#)?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1316971",
                function: "read",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::PartialString(vec![]),
                    Argument::Numeric("4096"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let tokenized = tokenize_syscall(
            r#"1343641 sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00\\", 20, MSG_NOSIGNAL, NULL, 0) = 20"#,
        )?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1343641",
                function: "sendto",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::String(Vec::from(
                        b"\x02\x00\x00\x00\x0b\x00\x00\x00\x07\x00\x00\x00passwd\x00\\"
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

        let tokenized = tokenize_syscall(
            "1343641 openat(AT_FDCWD, \"/nix/store/ixq7chmml361204anwph16ll2njcf19d-curl-8.11.0/lib/glibc-hwcaps/x86-64-v4/libcurl.so.4\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)"
        )?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1343641",
                function: "openat",
                arguments: vec![
                    Argument::Enum("AT_FDCWD"),
                    Argument::String(Vec::from(
                        b"/nix/store/ixq7chmml361204anwph16ll2njcf19d-curl-8.11.0/lib/glibc-hwcaps/x86-64-v4/libcurl.so.4"
                    )),
                    Argument::Enum("O_RDONLY|O_CLOEXEC"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Failure(-1, "ENOENT (No such file or directory)")
                }
            }
        );

        let tokenized = tokenize_syscall(
            r"1437466 read(17, 0x7fb0f00111d6, 122)   = -1 EAGAIN (Resource temporarily unavailable)",
        )?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1437466",
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

        let tokenized = tokenize_syscall(
            r#"1343641 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0"#,
        )?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1343641",
                function: "connect",
                arguments: vec![
                    Argument::Numeric("3"),
                    Argument::Structure(r#"{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}"#),
                    Argument::Numeric("110"),
                ],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            }
        );

        let tokenized = tokenize_syscall(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653",
        )?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "337651",
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

        let tokenized = tokenize_syscall(
            r"1343641 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f4223fff990, parent_tid=0x7f4223fff990, exit_signal=0, stack=0x7f42237ff000, stack_size=0x7fff80, tls=0x7f4223fff6c0} => {parent_tid=[1343642]}, 88) = 1343642",
        )?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1343641",
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
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_escaped_char() -> Result<()> {
        let (_, v) = parse_escaped_char("\\t")?;
        assert_eq!(v, b'\t');
        let (_, v) = parse_escaped_char("\\n")?;
        assert_eq!(v, b'\n');
        let (_, v) = parse_escaped_char("\\v")?;
        assert_eq!(v, 0x0b);
        let (_, v) = parse_escaped_char("\\f")?;
        assert_eq!(v, 0x0c);
        let (_, v) = parse_escaped_char("\\r")?;
        assert_eq!(v, b'\r');
        let (_, v) = parse_escaped_char("\\\"")?;
        assert_eq!(v, b'\"');
        let (_, v) = parse_escaped_char("\\\\")?;
        assert_eq!(v, b'\\');
        let (_, v) = parse_escaped_char("\\x00")?;
        assert_eq!(v, 0x00);
        let (_, v) = parse_escaped_char("\\xFF")?;
        assert_eq!(v, 0xFF);
        Ok(())
    }

    #[test]
    fn test_nested_brackets() -> Result<()> {
        let (_, v) = nested_brackets("[input]")?;
        assert_eq!(v, "[input]");
        let (_, v) = nested_brackets("[inp[ [abc] u]t]")?;
        assert_eq!(v, "[inp[ [abc] u]t]");
        let (_, v) = nested_brackets("[inp]ut")?;
        assert_eq!(v, "[inp]");
        Ok(())
    }

    #[test]
    fn test_parse_string() -> Result<()> {
        let (_, v) = parse_string("\"Hello!\"")?;
        assert_eq!(v, vec![72, 101, 108, 108, 111, 33]);
        let (_, v) = parse_string("\"\\x00\\x01\\xFF\"")?;
        assert_eq!(v, vec![0, 1, 255]);
        let (_, v) = parse_string("\" dquote: \\\"  more text\"")?;
        assert_eq!(
            v,
            vec![
                32, 100, 113, 117, 111, 116, 101, 58, 32, 34, 32, 32, 109, 111, 114, 101, 32, 116,
                101, 120, 116
            ]
        );
        Ok(())
    }

    #[test]
    fn test_resumed_addt_arguments() -> Result<()> {
        let tokenized = tokenize_syscall(r#"1435250 <... read resumed>"abc"..., 1140) = 792"#)?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "1435250",
                function: "read",
                arguments: vec![
                    Argument::PartialString(Vec::from(b"abc")),
                    Argument::Numeric("1140")
                ],
                outcome: CallOutcome::Resumed {
                    retval: Retval::Success(792)
                }
            }
        );

        let tokenized =
            tokenize_syscall("337651 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "337651",
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

        let tokenized =
            tokenize_syscall("15615 <... clone3 resumed> => {parent_tid=[0]}, 88) = 15620")?;
        assert_eq!(
            tokenized,
            SyscallSegment {
                pid: "15615",
                function: "clone3",
                arguments: vec![
                    Argument::WrittenStructureResumed("{parent_tid=[0]}"),
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
    fn test_parse_proc_exit() -> Result<()> {
        let (rem, exit) = parse_proc_exit("337655 +++ exited with 0 +++")?;
        assert_eq!(rem, "");
        assert_eq!(
            exit,
            ProcessExit {
                pid: "337655",
                exit_code: "0"
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_signal() -> Result<()> {
        let (rem, exit) = parse_signal("337651 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=337653, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---")?;
        assert_eq!(rem, "");
        assert_eq!(
            exit,
            SignalRecv {
                pid: "337651",
                signal: "SIGCHLD",
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_all_results() -> Result<()> {
        let res = tokenize("337655 +++ exited with 0 +++")?;
        assert_eq!(
            res,
            TokenizerOutput::Exit(ProcessExit {
                pid: "337655",
                exit_code: "0"
            })
        );
        let res = tokenize(r"1316971 close(3)                        = 0")?;
        assert_eq!(
            res,
            TokenizerOutput::Syscall(SyscallSegment {
                pid: "1316971",
                function: "close",
                arguments: vec![Argument::Numeric("3")],
                outcome: CallOutcome::Complete {
                    retval: Retval::Success(0)
                }
            })
        );
        let res = tokenize("337655 +++ exited with 0 ++");
        assert!(res.is_err());
        let res = tokenize("337651 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=337653, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---")?;
        assert_eq!(
            res,
            TokenizerOutput::Signal(SignalRecv {
                pid: "337651",
                signal: "SIGCHLD"
            })
        );
        let res = tokenize("9563  --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=9564, si_uid=0, si_status=0, si_utime=2 /* 0.02 s */, si_stime=4 /* 0.04 s */} ---")?;
        assert_eq!(
            res,
            TokenizerOutput::Signal(SignalRecv {
                pid: "9563",
                signal: "SIGCHLD"
            })
        );
        Ok(())
    }
}
