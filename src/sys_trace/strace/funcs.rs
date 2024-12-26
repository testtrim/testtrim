// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{os::unix::ffi::OsStrExt, path::PathBuf, str::FromStr};

use anyhow::{anyhow, ensure, Result};
use lazy_static::lazy_static;
use regex::Regex;

use crate::sys_trace::trace::UnifiedSocketAddr;

use super::{
    sequencer::{OwnedArgument, Sequencer, Syscall},
    tokenizer::Retval,
};

#[derive(Debug, PartialEq)]
pub enum OpenPath {
    RelativeToCwd(PathBuf),
    RelativeToOpenDirFD(PathBuf, i32), // i32 is the directory file descriptor
}

#[derive(Debug, PartialEq)]
pub enum StringArgument {
    Complete(Vec<u8>),
    Partial,
}

#[derive(Debug, PartialEq)]
pub enum Function {
    Openat {
        pid: String,
        path: OpenPath,
    },
    Chdir {
        pid: String,
        path: PathBuf,
    },
    Clone {
        parent_pid: String,
        child_pid: String,
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
        pid: String,
        socket_fd: String,
        socket_addr: UnifiedSocketAddr,
    },
    Sendto {
        pid: String,
        socket_fd: String,
        data: StringArgument,
    },
    Close {
        pid: String,
        fd: String,
    },
    Read {
        pid: String,
        fd: String,
        data: StringArgument,
    },
    Recv {
        pid: String,
        socket_fd: String,
        data: StringArgument,
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

pub struct FunctionExtractor<'a> {
    sequencer: Sequencer<'a>,
}

impl FunctionExtractor<'_> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sequencer: Sequencer::new(),
        }
    }

    pub fn extract(&mut self, input: &str) -> Result<Option<Function>> {
        let syscall = self.sequencer.tokenize(input)?;
        let Some(syscall) = syscall else {
            return Ok(None);
        };
        let retval = match syscall.retval {
            Retval::Success(retval) => retval,
            // Permit "connect" failures to be emitted.
            Retval::Failure(retval, _msg) if syscall.function == "connect" => retval,
            _ => {
                // Ignore error and resumed states.
                return Ok(None);
            }
        };
        Ok(Some(match &*syscall.function {
            "close" => Self::extract_close(syscall)?,
            "openat" => Self::extract_openat(syscall)?,
            "chdir" => Self::extract_chdir(syscall)?,
            "clone" => Self::extract_clone(syscall, retval)?,
            "clone3" => Self::extract_clone(syscall, retval)?,
            "sendto" => return Self::extract_sendto(syscall), // may have None
            "read" => Self::extract_read(syscall)?,
            "connect" => return Self::extract_connect(syscall), // may have None
            "recvfrom" => Self::extract_recvfrom(syscall)?,
            other => {
                return Err(anyhow!("unexpected syscall: {other:?}"));
            }
        }))
    }

    fn extract_close(mut syscall: Syscall<'_>) -> Result<Function> {
        ensure!(
            syscall.arguments.len() == 1,
            "expected 1 argument to close, but was: {}",
            syscall.arguments.len()
        );
        let fd = syscall.remove_numeric_arg(0)?;
        Ok(Function::Close {
            pid: syscall.pid.into_owned(),
            fd,
        })
    }

    fn extract_openat(mut syscall: Syscall<'_>) -> Result<Function> {
        ensure!(
            // mode_t mode optional 4th
            (3..=4).contains(&syscall.arguments.len()),
            "expected 3-4 argument to openat, but arguments were: {:?}",
            syscall.arguments,
        );
        let path = syscall.remove_path_arg(1)?;

        let path = match &syscall.arguments[0] {
            OwnedArgument::Enum(val) if val == "AT_FDCWD" => OpenPath::RelativeToCwd(path),
            OwnedArgument::Numeric(num) => OpenPath::RelativeToOpenDirFD(path, num.parse::<i32>()?),
            other => {
                return Err(anyhow!(
                    "argument 0 was unexpected in syscall openat: {other:?}",
                ));
            }
        };
        Ok(Function::Openat {
            pid: syscall.pid.into_owned(),
            path,
        })
    }

    fn extract_chdir(mut syscall: Syscall<'_>) -> Result<Function> {
        ensure!(
            syscall.arguments.len() == 1,
            "expected 1 argument to chdir, but was: {}",
            syscall.arguments.len()
        );
        let path = syscall.remove_path_arg(0)?;
        Ok(Function::Chdir {
            pid: syscall.pid.into_owned(),
            path,
        })
    }

    fn extract_clone(syscall: Syscall<'_>, retval: i32) -> Result<Function> {
        if syscall.function == "clone" {
            ensure!(
                syscall.arguments.len() == 3,
                "expected 3 argument to clone, but was: {}",
                syscall.arguments.len()
            );
        } else {
            ensure!(
                syscall.arguments.len() == 2,
                "expected 2 argument to {}, but was: {}",
                syscall.function,
                syscall.arguments.len()
            );
        }

        Ok(Function::Clone {
            parent_pid: syscall.pid.into_owned(),
            child_pid: retval.to_string(),
        })
    }

    fn extract_sendto(mut syscall: Syscall<'_>) -> Result<Option<Function>> {
        ensure!(
            syscall.arguments.len() == 6,
            "expected 6 argument to {}, but was: {}",
            syscall.function,
            syscall.arguments.len()
        );
        if let OwnedArgument::Structure(_) = syscall.arguments[1] {
            return Ok(None);
        }
        let data = syscall.remove_data_arg(1)?;
        let socket_fd = syscall.remove_numeric_arg(0)?;
        Ok(Some(Function::Sendto {
            pid: syscall.pid.into_owned(),
            socket_fd,
            data,
        }))
    }

    fn extract_read(mut syscall: Syscall<'_>) -> Result<Function> {
        ensure!(
            syscall.arguments.len() == 3,
            "expected 3 argument to {}, but was: {}",
            syscall.function,
            syscall.arguments.len()
        );
        let data = syscall.remove_data_arg(1)?;
        let fd = syscall.remove_numeric_arg(0)?;
        Ok(Function::Read {
            pid: syscall.pid.into_owned(),
            fd,
            data,
        })
    }

    fn extract_connect(mut syscall: Syscall<'_>) -> Result<Option<Function>> {
        ensure!(
            syscall.arguments.len() == 3,
            "expected 3 argument to {}, but was: {}",
            syscall.function,
            syscall.arguments.len()
        );
        let socket_addr = match syscall.arguments.remove(1) {
            OwnedArgument::Structure(v) => Self::parse_socket_structure(&v)?,
            v => {
                return Err(anyhow!(
                    "argument 1 was not structure on syscall connect; it was {v:?}",
                ));
            }
        };
        let socket_fd = syscall.remove_numeric_arg(0)?;
        Ok(socket_addr.map(|s| Function::Connect {
            pid: syscall.pid.into_owned(),
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
                // port = 0 are internal syscalls to prepare the local endpoint and test feasibility of different
                // remote endpoints.  As they don't really communicate externally, it makes sense to filter them
                // out.
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
                // port = 0 are internal syscalls to prepare the local endpoint and test feasibility of different
                // remote endpoints.  As they don't really communicate externally, it makes sense to filter them
                // out.
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

    fn extract_recvfrom(mut syscall: Syscall<'_>) -> Result<Function> {
        ensure!(
            syscall.arguments.len() == 6,
            "expected 6 argument to {}, but was: {}",
            syscall.function,
            syscall.arguments.len()
        );
        let data = syscall.remove_data_arg(1)?;
        let socket_fd = syscall.remove_numeric_arg(0)?;
        Ok(Function::Recv {
            pid: syscall.pid.into_owned(),
            socket_fd,
            data,
        })
    }
}

impl Syscall<'_> {
    fn remove_numeric_arg(&mut self, index: usize) -> Result<String> {
        match self.arguments.remove(index) {
            OwnedArgument::Numeric(v) => Ok(v),
            v => Err(anyhow!(
                "argument {index} was not numeric on syscall {}; it was {v:?}",
                self.function
            )),
        }
    }

    fn remove_path_arg(&mut self, index: usize) -> Result<PathBuf> {
        match self.arguments.remove(index) {
            OwnedArgument::String(v) => {
                Ok(PathBuf::from(<std::ffi::OsStr as OsStrExt>::from_bytes(&v)))
            }
            v => Err(anyhow!(
                "argument {index} was not string on syscall {}; it was {v:?}",
                self.function
            )),
        }
    }

    fn remove_data_arg(&mut self, index: usize) -> Result<StringArgument> {
        match self.arguments.remove(index) {
            OwnedArgument::String(v) => Ok(StringArgument::Complete(v)),
            OwnedArgument::PartialString(_) => Ok(StringArgument::Partial),
            v => Err(anyhow!(
                "argument {index} was not string on syscall {}; it was {v:?}",
                self.function
            )),
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
        strace::funcs::{Function, FunctionExtractor, OpenPath, StringArgument},
        trace::UnifiedSocketAddr,
    };

    #[test]
    fn close() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"1316971 close(3)                        = 0")?;
        assert_eq!(
            t,
            Some(Function::Close {
                pid: "1316971".to_string(),
                fd: "3".to_string(),
            })
        );

        Ok(())
    }

    #[test]
    fn error_filtered() -> Result<()> {
        let mut fe = FunctionExtractor::new();
        let t = fe.extract(r#"152738 chdir("/home/mfenniak")               = -1 ENOENT (No such file or directory)"#,)?;
        assert_eq!(t, None);
        Ok(())
    }

    #[test]
    fn openat() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r#"2892755 openat(AT_FDCWD, "test_data/Fibonacci_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#)?;
        assert_eq!(
            t,
            Some(Function::Openat {
                pid: String::from("2892755"),
                path: OpenPath::RelativeToCwd(PathBuf::from("test_data/Fibonacci_Sequence.txt")),
            })
        );

        let t = fe.extract(
            // not using AT_FDCWD...
            r#"1094494 openat(7, "gocoverdir", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) = 4"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Openat {
                pid: String::from("1094494"),
                path: OpenPath::RelativeToOpenDirFD(PathBuf::from("gocoverdir"), 7),
            })
        );

        Ok(())
    }

    #[test]
    fn chdir() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r#"152738 chdir("test_data/\"Fibonacci\"_Sequence.txt") = 0"#)?;
        assert_eq!(
            t,
            Some(Function::Chdir {
                pid: String::from("152738"),
                path: PathBuf::from("test_data/\"Fibonacci\"_Sequence.txt"),
            })
        );

        Ok(())
    }

    #[test]
    fn clone() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653")?;
        assert_eq!(
            t,
            Some(Function::Clone {
                parent_pid: String::from("337651"),
                child_pid: String::from("337653")
            })
        );

        Ok(())
    }

    #[test]
    fn clone3() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(r"416671 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7fcdb7d7f990, parent_tid=0x7fcdb7d7f990, exit_signal=0, stack=0x7fcdb7b7f000, stack_size=0x1fff00, tls=0x7fcdb7d7f6c0} => {parent_tid=[416676]}, 88) = 416676")?;
        assert_eq!(
            t,
            Some(Function::Clone {
                parent_pid: String::from("416671"),
                child_pid: String::from("416676")
            })
        );

        Ok(())
    }

    #[test]
    fn sendto() -> Result<()> {
        let mut fe = FunctionExtractor::new();
        let t = fe.extract(
            r"1951665 sendto(12, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1734979518, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12 <unfinished ...>",
        )?;
        assert_eq!(t, None);

        let t = fe.extract(
            r#"1343641 sendto(3, "\x02\x00\x00\x00\v\x00\x00\x00\x07\x00\x00\x00passwd\x00\\", 20, MSG_NOSIGNAL, NULL, 0) = 20"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Sendto {
                pid: String::from("1343641"),
                socket_fd: String::from("3"),
                data: StringArgument::Complete(Vec::from(
                    b"\x02\x00\x00\x00\x0b\x00\x00\x00\x07\x00\x00\x00passwd\x00\\"
                )),
            })
        );

        let t = fe.extract(
            r#"1343641 sendto(5, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xb5NG\xda\xd9\x9fX\x07\xd4\xb3a\x7f\xe7\\\xbe\x96\xe1\x01\xe3E;\x85\x1ei\xcc\xd6\xdfc\xf7~\xec\xb4 q\x96\x1cW\x805\x84\xce\x9b\xe8\xd4\x89j%|\x95:<\xd952zYbj\rM\xd1(\xa0D\x8e\x00>\x13\x02\x13\x03\x13\x01\xc0,\xc00\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0+\xc0/\x00\x9e\xc0$\xc0(\x00k\xc0#\xc0'\x00g\xc0\n\xc0\x14\x009\xc0\t\xc0\x13\x003\x00\x9d\x00\x9c\x00=\x00<\x005\x00/\x00\xff\x01\x00\x01u\x00\x00\x00\x0e\x00\f\x00\x00\tgoogle.ca\x00\v\x00\x04\x03\x00\x01\x02\x00\n\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x10\x00\x0e\x00\f\x02h2\x08http/1.1\x00\x16\x00\x00\x00\x17\x00\x00\x001\x00\x00\x00\r\x000\x00.\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x1a\x08\x1b\x08\x1c\x08\t\x08\n\x08\v\x08\x04"..., 517, MSG_NOSIGNAL, NULL, 0) = 517"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Sendto {
                pid: String::from("1343641"),
                socket_fd: String::from("5"),
                data: StringArgument::Partial,
            })
        );

        Ok(())
    }

    #[test]
    fn read() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"1343641 read(3, "\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00", 38) = 36"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Read {
                pid: String::from("1343641"),
                fd: String::from("3"),
                data: StringArgument::Complete(Vec::from(b"\x02\x00\x00\x00\x01\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\xe8\x03\x00\x00d\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x1f\x00\x00\x00")),
            })
        );

        let t = fe.extract(
            r#"1343641 read(3, "d attributes must be the same, and the optional\n# and supplied fields are just that :-)\npolicy\t\t= policy_match\n\n# For the CA policy\n[ policy_match ]\ncountryName\t\t= match\nstateOrProvinceName\t= match\norganizationName\t= match\norganizationalUnitName\t= optional"..., 4096) = 4096"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Read {
                pid: String::from("1343641"),
                fd: String::from("3"),
                data: StringArgument::Partial,
            })
        );

        Ok(())
    }

    #[test]
    fn connect() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"337651 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = 0"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Connect {
                pid: String::from("337651"),
                socket_fd: String::from("3"),
                socket_addr: UnifiedSocketAddr::Unix(PathBuf::from("/var/run/nscd/socket")),
            })
        );

        let t = fe.extract(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Connect {
                pid: String::from("337651"),
                socket_fd: String::from("5"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2607, 0xf8b0, 0x400a, 0x805, 0, 0, 0, 0x2003),
                    443,
                    0,
                    0
                ))),
            })
        );

        let t = fe.extract(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
        )?;
        // 0 port is filtered out:
        assert_eq!(t, None);

        let t = fe.extract(
            r#"337651 connect(17, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, 16) = 0"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Connect {
                pid: String::from("337651"),
                socket_fd: String::from("17"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(100, 100, 100, 100),
                    53
                ))),
            })
        );

        let t = fe.extract(
            r#"337651 connect(17, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("100.100.100.100")}, 16) = 0"#,
        )?;
        // 0 port is filtered out:
        assert_eq!(t, None);

        // errors are not filtered out:
        let t = fe.extract(
            r#"337651 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2607:f8b0:400a:805::2003", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)"#,
        )?;
        assert_eq!(
            t,
            Some(Function::Connect {
                pid: String::from("337651"),
                socket_fd: String::from("5"),
                socket_addr: UnifiedSocketAddr::Inet(std::net::SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0x2607, 0xf8b0, 0x400a, 0x805, 0, 0, 0, 0x2003),
                    443,
                    0,
                    0
                ))),
            })
        );

        // AF_UNSPEC is ignored
        let t = fe.extract(
            r#"1343642 connect(7, {sa_family=AF_UNSPEC, sa_data="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}, 16) = 0"#,
        )?;
        assert_eq!(t, None);

        Ok(())
    }

    #[test]
    fn recvfrom() -> Result<()> {
        let mut fe = FunctionExtractor::new();

        let t = fe.extract(
            r#"103155 recvfrom(7, "\xd6\xef\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x08codeberg\x03org\x00\x00\x01\x00\x01\xc0\f\x00\x01\x00\x01\x00\x00\x01\"\x00\x04\xd9\xc5[\x91\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x00", 2048, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("100.100.100.100")}, [28 => 16]) = 57"#
        )?;
        assert_eq!(
            t,
            Some(Function::Recv {
                pid: String::from("103155"),
                socket_fd: String::from("7"),
                data: StringArgument::Complete(Vec::from(b"\xd6\xef\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x08codeberg\x03org\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\"\x00\x04\xd9\xc5[\x91\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x00")),
            })
        );

        Ok(())
    }
}
