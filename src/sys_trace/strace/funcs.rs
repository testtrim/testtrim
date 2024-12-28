// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{os::unix::ffi::OsStrExt, path::PathBuf, str::FromStr};

use anyhow::{anyhow, ensure, Result};
use lazy_static::lazy_static;
use regex::Regex;

use crate::sys_trace::trace::UnifiedSocketAddr;

use super::tokenizer::{
    tokenize, Argument, CallOutcome, EncodedString, Retval, SyscallSegment, TokenizerOutput,
};

#[derive(Debug, PartialEq)]
pub enum OpenPath {
    RelativeToCwd(PathBuf),
    RelativeToOpenDirFD(PathBuf, i32), // i32 is the directory file descriptor
}

#[derive(Debug, PartialEq)]
pub enum StringArgument<'a> {
    Complete(EncodedString<'a>),
    Partial,
}

#[derive(Debug, PartialEq)]
pub enum FunctionTrace<'a> {
    Function(Function<'a>),
    Exit,
}

#[derive(Debug, PartialEq)]
pub enum Function<'a> {
    Openat {
        path: OpenPath,
    },
    Chdir {
        path: PathBuf,
    },
    Clone {
        child_pid: u32,
    },
    Connect {
        // connect is a trickier syscall than the others we've handled because it is typically used with non-blocking
        // sockets, and so connect() is likely to return EINPROGRESS immediately and then be followed-up with poll()
        // calls to check if the socket is available.  I think it doesn't matter if connect succeeds, fails, becomes an
        // unfinished syscall, or returns EINPROGRESS or EAGAIN -- all of them mean the same thing, this strace tried to
        // reach outside of its process through the network and therefore we'll report that it has an external
        // dependency.  This simplifies the implementation here and seems more-or-less right.
        //
        // So the sum of that is that Connect is currently the only syscall which will be emitted here even if it has an
        // error.
        socket_fd: &'a str,
        socket_addr: UnifiedSocketAddr,
    },
    Sendto {
        socket_fd: &'a str,
        data: StringArgument<'a>,
    },
    Close {
        fd: &'a str,
    },
    Read {
        fd: &'a str,
        data: StringArgument<'a>,
    },
    Recv {
        socket_fd: &'a str,
        data: StringArgument<'a>,
    },
    Execve {
        arg0: PathBuf,
    },
}

lazy_static! {
    static ref socket_struct_regex: Regex = Regex::new(
        r#"(?x)
        (
            \{
                sa_family=AF_UNIX,
                \s+
                sun_path="(?<unix_path>(?:[^"\\]|\\.)*)"
            \}
            |
            \{
                sa_family=AF_INET6,
                \s+
                sin6_port=htons\((?<sin6_port>\d+)\),
                \s+
                sin6_flowinfo=htonl\((?<sin6_flowinfo>\d+)\),
                \s+
                inet_pton\(
                    AF_INET6,
                    \s+
                    "(?<sin6_addr>[^"]+)",
                    \s+
                    &sin6_addr
                \),
                \s+
                sin6_scope_id=(?<sin6_scope_id>\d+)
            \}
            |
            \{
                sa_family=AF_INET,
                \s+
                sin_port=htons\((?<sin_port>\d+)\),
                \s+
                sin_addr=inet_addr\("(?<sin_addr>[^"]+)"\)
            \}
            |
            \{
                (?<af_unspec>sa_family=AF_UNSPEC)
                .*
            \}
        )
        $"#
    )
    .unwrap();
}

pub struct FunctionExtractor {
    // sequencer: Sequencer<'a>,
}

impl FunctionExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            // sequencer: Sequencer::new(),
        }
    }

    pub fn extract<'a>(&mut self, input: &'a str) -> Result<Option<FunctionTrace<'a>>> {
        let trace_output = tokenize(input)?;
        // let Some(trace_output) = trace_output else {
        //     return Ok(None);
        // };
        match trace_output {
            TokenizerOutput::Syscall(syscall) => {
                let CallOutcome::Complete { ref retval } = syscall.outcome else {
                    return Ok(None);
                };
                let retval = match retval {
                    Retval::Success(retval) => retval,
                    // Permit "connect" failures to be emitted.
                    Retval::Failure(retval, _msg) if syscall.function == "connect" => retval,
                    _ => {
                        // Ignore error and resumed states.
                        return Ok(None);
                    }
                };
                let function = match syscall.function {
                    "close" => Some(Self::extract_close(&syscall.arguments)?),
                    "openat" => Some(Self::extract_openat(&syscall.arguments)?),
                    "chdir" => Some(Self::extract_chdir(&syscall.arguments)?),
                    "clone" => Some(Self::extract_clone((*retval).try_into()?)),
                    "clone3" => Some(Self::extract_clone((*retval).try_into()?)),
                    "vfork" => Some(Self::extract_clone((*retval).try_into()?)),
                    "sendto" => Self::extract_sendto(syscall)?, // may have None
                    "read" => Some(Self::extract_read(syscall)?),
                    "connect" => Self::extract_connect(&syscall.arguments)?, // may have None
                    "recvfrom" => Some(Self::extract_recvfrom(syscall)?),
                    "execve" => Some(Self::extract_execve(&syscall.arguments)?),

                    // some syscalls we receive because we trace "%process" (for completeness if anything comes along to
                    // create new processes), but can be dropped because they aren't relevant to our current needs:
                    "wait4" | "kill" | "tgkill" | "waitid" | "pidfd_send_signal" => None,

                    other => {
                        return Err(anyhow!("unexpected syscall: {other:?}"));
                    }
                };

                Ok(function.map(FunctionTrace::Function))
            }
            TokenizerOutput::Exit(_) => Ok(Some(FunctionTrace::Exit)),
            TokenizerOutput::Signal(_) => Ok(None),
        }
    }

    fn extract_close<'a>(arguments: &[Argument<'a>]) -> Result<Function<'a>> {
        ensure!(
            arguments.len() == 1,
            "expected 1 argument to close, but was: {}",
            arguments.len()
        );
        let fd = Self::numeric(arguments, 0)?;
        Ok(Function::Close { fd })
    }

    fn extract_openat<'a>(arguments: &[Argument<'a>]) -> Result<Function<'a>> {
        ensure!(
            // mode_t mode optional 4th
            (3..=4).contains(&arguments.len()),
            "expected 3-4 argument to openat, but arguments were: {:?}",
            arguments,
        );
        let path = Self::path(arguments, 1)?;
        let path = match &arguments[0] {
            Argument::Enum(val) if *val == "AT_FDCWD" => OpenPath::RelativeToCwd(path),
            Argument::Numeric(num) => OpenPath::RelativeToOpenDirFD(path, num.parse::<i32>()?),
            other => {
                return Err(anyhow!(
                    "argument 0 was unexpected in syscall openat: {other:?}",
                ));
            }
        };
        Ok(Function::Openat { path })
    }

    fn extract_chdir<'a>(arguments: &[Argument<'a>]) -> Result<Function<'a>> {
        ensure!(
            arguments.len() == 1,
            "expected 1 argument to chdir, but arguments were: {:?}",
            arguments
        );
        let path = Self::path(arguments, 0)?;
        Ok(Function::Chdir { path })
    }

    fn extract_clone<'a>(retval: u32) -> Function<'a> {
        Function::Clone { child_pid: retval }
    }

    fn extract_sendto(mut syscall: SyscallSegment) -> Result<Option<Function<'_>>> {
        ensure!(
            syscall.arguments.len() == 6,
            "expected 6 argument to sendto, but arguments were: {:?}",
            syscall.arguments,
        );
        if let Argument::Structure(_) = syscall.arguments[1] {
            // unreachable!()
            return Ok(None);
        }
        let data = Self::remove_data_argument(&mut syscall.arguments, 1)?;
        let socket_fd = Self::numeric(&syscall.arguments, 0)?;
        Ok(Some(Function::Sendto { socket_fd, data }))
    }

    fn extract_read(mut syscall: SyscallSegment) -> Result<Function<'_>> {
        ensure!(
            syscall.arguments.len() == 3,
            "expected 3 argument to read, but arguments were: {:?}",
            syscall.arguments
        );
        let _ = syscall.arguments.pop();
        let data = Self::pop_data_argument(&mut syscall.arguments)?;
        let fd = Self::pop_numeric_argument(&mut syscall.arguments)?;
        Ok(Function::Read { fd, data })
    }

    fn extract_connect<'a>(arguments: &[Argument<'a>]) -> Result<Option<Function<'a>>> {
        ensure!(
            arguments.len() == 3,
            "expected 3 argument to connect, but arguments were: {:?}",
            arguments
        );
        let socket_addr = match &arguments[1] {
            Argument::Structure(v) => Self::parse_socket_structure(v)?,
            v => {
                return Err(anyhow!(
                    "argument 1 was not structure on syscall connect; it was {v:?}",
                ));
            }
        };
        let socket_fd = Self::numeric(arguments, 0)?;
        Ok(socket_addr.map(|s| Function::Connect {
            socket_addr: s,
            socket_fd,
        }))
    }

    fn parse_socket_structure(data: &str) -> Result<Option<UnifiedSocketAddr>> {
        let Some(cap) = socket_struct_regex.captures(data) else {
            return Err(anyhow!("unable to parse socket structure: {data}"));
        };

        #[allow(clippy::manual_map)] // more extensible with current pattern
        Ok(if let Some(unix_path) = cap.name("unix_path") {
            Some(UnifiedSocketAddr::Unix(PathBuf::from(unix_path.as_str())))
        } else if let Some(sin6_addr) = cap.name("sin6_addr") {
            let port = u16::from_str(&cap["sin6_port"]).unwrap();
            if port == 0 {
                // port = 0 are internal syscalls to prepare the local endpoint and test feasibility of different remote
                // endpoints.  As they don't really communicate externally, it makes sense to filter them out.
                None
            } else {
                Some(UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(
                    std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from_str(sin6_addr.as_str()).unwrap(),
                        port,
                        u32::from_str(&cap["sin6_flowinfo"]).unwrap(),
                        u32::from_str(&cap["sin6_scope_id"]).unwrap(),
                    ),
                )))
            }
        } else if let Some(sin_addr) = cap.name("sin_addr") {
            let port = u16::from_str(&cap["sin_port"]).unwrap();
            if port == 0 {
                // port = 0 are internal syscalls to prepare the local endpoint and test feasibility of different remote
                // endpoints.  As they don't really communicate externally, it makes sense to filter them out.
                None
            } else {
                Some(UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(
                    std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from_str(sin_addr.as_str()).unwrap(),
                        port,
                    ),
                )))
            }
        } else if cap.name("af_unspec").is_some() {
            None
        } else {
            unreachable!()
        })
    }

    fn extract_recvfrom(mut syscall: SyscallSegment) -> Result<Function<'_>> {
        ensure!(
            syscall.arguments.len() == 6,
            "expected 6 argument to recvfrom, but arguments were: {:?}",
            syscall.arguments
        );
        let data = Self::remove_data_argument(&mut syscall.arguments, 1)?;
        let socket_fd = Self::numeric(&syscall.arguments, 0)?;
        Ok(Function::Recv { socket_fd, data })
    }

    fn extract_execve<'a>(arguments: &[Argument<'a>]) -> Result<Function<'a>> {
        ensure!(
            arguments.len() == 3,
            "expected 3 argument to execve, but arguments were: {:?}",
            arguments
        );
        let path = Self::path(arguments, 0)?;
        Ok(Function::Execve { arg0: path })
    }

    fn numeric<'a>(args: &[Argument<'a>], index: usize) -> Result<&'a str> {
        match &args[index] {
            Argument::Numeric(v) => Ok(v),
            v => Err(anyhow!("argument {index} was not numeric; it was {v:?}",)),
        }
    }

    fn pop_numeric_argument<'a>(arguments: &mut Vec<Argument<'a>>) -> Result<&'a str> {
        match arguments.pop() {
            Some(Argument::Numeric(v)) => Ok(v),
            Some(v) => Err(anyhow!("argument was not numeric; it was {v:?}",)),
            None => Err(anyhow!("argument was not present in pop_numeric_argument")),
        }
    }

    fn path(args: &[Argument<'_>], index: usize) -> Result<PathBuf> {
        match &args[index] {
            Argument::String(v) => Ok(PathBuf::from(<std::ffi::OsStr as OsStrExt>::from_bytes(
                v.decoded(),
            ))),
            v => Err(anyhow!("argument {index} was not string; it was {v:?}",)),
        }
    }

    fn pop_data_argument<'a>(arguments: &mut Vec<Argument<'a>>) -> Result<StringArgument<'a>> {
        match arguments.pop() {
            Some(Argument::String(data)) => Ok(StringArgument::Complete(data)),
            Some(Argument::PartialString(_)) => Ok(StringArgument::Partial),
            Some(v) => Err(anyhow!("argument was not string; it was {v:?}")),
            None => Err(anyhow!("argument was not present in pop_data_argument")),
        }
    }

    fn remove_data_argument<'a>(
        arguments: &mut Vec<Argument<'a>>,
        index: usize,
    ) -> Result<StringArgument<'a>> {
        match arguments.remove(index) {
            Argument::String(data) => Ok(StringArgument::Complete(data)),
            Argument::PartialString(_) => Ok(StringArgument::Partial),
            v => Err(anyhow!("argument was not string; it was {v:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
        path::PathBuf,
    };

    use anyhow::Result;

    use crate::sys_trace::{
        strace::{
            funcs::{Function, FunctionExtractor, FunctionTrace, OpenPath, StringArgument},
            tokenizer::EncodedString,
        },
        trace::UnifiedSocketAddr,
    };

    #[test]
    fn close() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"close(3)                        = 0")?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Close { fd: "3" }))
        );

        Ok(())
    }

    #[test]
    fn error_filtered() -> Result<()> {
        let mut fe = FunctionExtractor::new();
        let t = fe.extract(
            r#"chdir("/home/mfenniak")               = -1 ENOENT (No such file or directory)"#,
        )?;
        assert_eq!(t, None);
        Ok(())
    }

    #[test]
    fn openat() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"openat(AT_FDCWD, "test_data/Fibonacci_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Openat {
                path: OpenPath::RelativeToCwd(PathBuf::from("test_data/Fibonacci_Sequence.txt")),
            }))
        );

        let t = fe.extract(
            // not using AT_FDCWD...
            r#"openat(7, "gocoverdir", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) = 4"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Openat {
                path: OpenPath::RelativeToOpenDirFD(PathBuf::from("gocoverdir"), 7),
            }))
        );

        Ok(())
    }

    #[test]
    fn chdir() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r#"chdir("test_data/\"Fibonacci\"_Sequence.txt") = 0"#)?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Chdir {
                path: PathBuf::from("test_data/\"Fibonacci\"_Sequence.txt"),
            }))
        );

        Ok(())
    }

    #[test]
    fn clone() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653")?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Clone {
                child_pid: 337_653
            }))
        );

        Ok(())
    }

    #[test]
    fn clone3() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7fcdb7d7f990, parent_tid=0x7fcdb7d7f990, exit_signal=0, stack=0x7fcdb7b7f000, stack_size=0x1fff00, tls=0x7fcdb7d7f6c0} => {parent_tid=[416676]}, 88) = 416676")?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Clone {
                child_pid: 416_676
            }))
        );

        Ok(())
    }

    #[test]
    fn vfork() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"vfork()                                 = 38724")?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Clone {
                child_pid: 38724
            }))
        );

        Ok(())
    }

    #[test]
    fn sendto() -> Result<()> {
        let mut fe = FunctionExtractor::new();
        let t = fe.extract(
            r"sendto(12, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1734979518, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12 <unfinished ...>",
        )?;
        assert_eq!(t, None);

        let t = fe.extract(
            r#"sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00\\", 20, MSG_NOSIGNAL, NULL, 0) = 20"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Sendto {
                socket_fd: "3",
                data: StringArgument::Complete(EncodedString::new(
                    "\\x02\\x00\\x00\\x00\\v\\x00\\x00\\x00\\x07\\x00\\x00\\x00passwd\\x00\\\\"
                )),
            }))
        );

        let t = fe.extract(
            r#"sendto(5, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xb5NG\xda\xd9\x9fX\x07\xd4\xb3a\x7f\xe7\\\xbe\x96\xe1\x01\xe3E;\x85\x1ei\xcc\xd6\xdfc\xf7~\xec\xb4 q\x96\x1cW\x805\x84\xce\x9b\xe8\xd4\x89j%|\x95:<\xd952zYbj\rM\xd1(\xa0D\x8e\x00>\x13\x02\x13\x03\x13\x01\xc0,\xc00\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0+\xc0/\x00\x9e\xc0$\xc0(\x00k\xc0#\xc0'\x00g\xc0\n\xc0\x14\x009\xc0\t\xc0\x13\x003\x00\x9d\x00\x9c\x00=\x00<\x005\x00/\x00\xff\x01\x00\x01u\x00\x00\x00\x0e\x00\f\x00\x00\tgoogle.ca\x00\v\x00\x04\x03\x00\x01\x02\x00\n\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x10\x00\x0e\x00\f\x02h2\x08http/1.1\x00\x16\x00\x00\x00\x17\x00\x00\x001\x00\x00\x00\r\x000\x00.\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x1a\x08\x1b\x08\x1c\x08\t\x08\n\x08\v\x08\x04"..., 517, MSG_NOSIGNAL, NULL, 0) = 517"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Sendto {
                socket_fd: "5",
                data: StringArgument::Partial,
            }))
        );

        Ok(())
    }

    #[test]
    fn read() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"read(3, "\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00", 38) = 36"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Read {
                fd: "3",
                data: StringArgument::Complete(EncodedString::new("\\x02\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\t\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\xe8\\x03\\x00\\x00d\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x0f\\x00\\x00\\x00\\x1f\\x00\\x00\\x00")),
            }))
        );

        let t = fe.extract(
            r#"read(3, "d attributes must be the same, and the optional\n# and supplied fields are just that :-)\npolicy\t\t= policy_match\n\n# For the CA policy\n[ policy_match ]\ncountryName\t\t= match\nstateOrProvinceName\t= match\norganizationName\t= match\norganizationalUnitName\t= optional"..., 4096) = 4096"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Read {
                fd: "3",
                data: StringArgument::Partial,
            }))
        );

        Ok(())
    }

    #[test]
    fn connect() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Connect {
                socket_fd: "3",
                socket_addr: UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket")),
            }))
        );

        let t = fe.extract(
            r#"connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Connect {
                socket_fd: "5",
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2607, 0xf8b0, 0x400a, 0x805, 0, 0, 0, 0x2003),
                    443,
                    0,
                    0
                ))),
            }))
        );

        let t = fe.extract(
            r#"connect(5, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        )?;
        // 0 port is filtered out:
        assert_eq!(t, None);

        let t = fe.extract(
            r#"connect(17, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, 16) = 0"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Connect {
                socket_fd: "17",
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(100, 100, 100, 100),
                    53
                ))),
            }))
        );

        let t = fe.extract(
            r#"connect(17, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("100.100.100.100")}, 16) = 0"#,
        )?;
        // 0 port is filtered out:
        assert_eq!(t, None);

        // errors are not filtered out:
        let t = fe.extract(
            r#"connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)"#,
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Connect {
                socket_fd: "5",
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2607, 0xf8b0, 0x400a, 0x805, 0, 0, 0, 0x2003),
                    443,
                    0,
                    0
                ))),
            }))
        );

        // AF_UNSPEC is ignored
        let t = fe.extract(
            r#"connect(7, {sa_family=AF_UNSPEC, sa_data="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}, 16) = 0"#,
        )?;
        assert_eq!(t, None);

        Ok(())
    }

    #[test]
    fn recvfrom() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"recvfrom(7, "\xd6\xef\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x08codeberg\x03org\x00\x00\x01\x00\x01\xc0\f\x00\x01\x00\x01\x00\x00\x01\"\x00\x04\xd9\xc5[\x91\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x00", 2048, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, [28 => 16]) = 57"#
        )?;
        assert_eq!(
            t,
            Some(FunctionTrace::Function(Function::Recv {
                socket_fd: "7",
                data: StringArgument::Complete(EncodedString::new("\\xd6\\xef\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x01\\x08codeberg\\x03org\\x00\\x00\\x01\\x00\\x01\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x01\\\"\\x00\\x04\\xd9\\xc5[\\x91\\x00\\x00)\\x04\\xd0\\x00\\x00\\x00\\x00\\x00\\x00")),
            }))
        );

        Ok(())
    }
}
