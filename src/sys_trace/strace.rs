// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::trace;
use regex::Regex;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use super::{trace::Trace, SysTraceCommand};

/// Implementation of `SysTraceCommand` that uses the `strace` command to trace all the relevant system calls.
pub struct STraceSysTraceCommand;

lazy_static! {

    // When tracing multiple processes, it's likely to get situations like this:
    //
    // ```
    // 189532 chdir("/home/mfenniak/Dev" <unfinished ...>
    // 189531 openat(AT_FDCWD, "README.md", O_RDONLY|O_CLOEXEC <unfinished ...>
    // 189532 <... chdir resumed>)             = 0
    // 189531 <... openat resumed>)            = 4
    // ```
    //
    // This indicates that before 189532's chdir call was completed, 189531 started an openat call; then they both
    // finished.  The return-value is listed on a separate line in the strace.  In these cases, to filter out failed
    // calls, we'll need to put these together and track them across multiple lines.

    static ref openat: Regex = Regex::new(
        // note that this will exclude any openat that had an error (eg. ENOENT) because it matches on a number then the
        // string terminator; an error would have a -1 response followed by an error code that wouldn't match.
        r#"^(?<pid>[0-9]+)\s+openat\(AT_FDCWD,\s+"(?<path>(?:[^"\\]|\\.)*)",\s+[^)]+(?<end>\)\s+=\s+\d+|\s*<unfinished \.\.\.>)$"#
    )
    .unwrap();

    // Here we don't filter out failures; we need to still match so that we can unwind any state stored from the
    // "unfinished" syscall.
    static ref openat_resumed: Regex = Regex::new(
        r"^(?<pid>[0-9]+)\s+<... openat resumed>\)\s+=\s+(?<retval>-?\d+)"
    )
    .unwrap();

    static ref chdir: Regex = Regex::new(
        // note that this will exclude any syscall that had an error, unless unfinished
        r#"^(?<pid>[0-9]+)\s+chdir\("(?<path>(?:[^"\\]|\\.)*)"(?<end>\)\s+=\s+0|\s*<unfinished \.\.\.>)$"#
    )
    .unwrap();

    // Here we don't filter out failures; we need to still match so that we can unwind any state stored from the
    // "unfinished" syscall.
    static ref chdir_resumed: Regex = Regex::new(
        r"^(?<pid>[0-9]+)\s+<... chdir resumed>\)\s+=\s+(?<retval>-?\d+)"
    )
    .unwrap();

    // 337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653
    static ref clone: Regex = Regex::new(
        r"(?x)
        ^(?<pid>[0-9]+)
        \s+
        clone3?\(.+                      # call & arguments
        (?<end>
            \)\s+=\s+(?<child_pid>-?\d+)
            .*                         # possible errno output; child_pid = -1
            |
            <unfinished\s\.\.\.>
        )
        $"
    )
    .unwrap();

    // Here we don't filter out failures; we need to still match so that we can unwind any state stored from the
    // "unfinished" syscall.
    static ref clone_resumed: Regex = Regex::new(
        r"(?x)
        ^(?<pid>[0-9]+)
        \s+
        <...\sclone3?\sresumed>,?.*\)   # child_tidptr retval comes back here
        \s+=\s+
        (?<retval>-?\d+)
        .*                           # possible errno output; child_pid = -1
        $"
    )
    .unwrap();
}

#[derive(Debug, PartialEq)]
enum SyscallState {
    Complete,
    Unfinished(String), // pid for completion // FIXME: don't really need this
}

#[derive(Debug, PartialEq)]
enum SyscallResult {
    Success,
    Failure,
}

#[derive(Debug, PartialEq)]
enum CloneParse {
    FinishedError,
    FinishedSuccess {
        parent_pid: String,
        child_pid: String,
    },
    Unfinished {
        parent_pid: String,
    },
}

impl STraceSysTraceCommand {
    pub fn is_available() -> bool {
        let output = Command::new("strace").arg("--help").output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn new() -> Self {
        STraceSysTraceCommand {}
    }

    fn parse_openat(trace: &str) -> Option<(String, String, SyscallState)> {
        // Note: only openat w/ AT_FDCWD is supported, which opens a path from the current working directory (unless
        // absolute).  Opening a directory, then opening a file in it, isn't supported by this.  FIXME: It *should*
        // probably be detected and either a warning or error generated though, so that it's not silently ignored.
        openat.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let path = String::from(&cap["path"])
                // Un-escape any escaped double-quotes
                .replace("\\\"", "\"");
            if cap["end"].starts_with(')') {
                (pid, path, SyscallState::Complete)
            } else {
                (pid.clone(), path, SyscallState::Unfinished(pid))
            }
        })
    }

    fn parse_openat_resumed(trace: &str) -> Option<(String, SyscallResult)> {
        openat_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                (pid, SyscallResult::Failure)
            } else {
                (pid, SyscallResult::Success)
            }
        })
    }

    fn parse_chdir(trace: &str) -> Option<(String, String, SyscallState)> {
        chdir.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let path = String::from(&cap["path"])
                // Un-escape any escaped double-quotes
                .replace("\\\"", "\"");
            if cap["end"].starts_with(')') {
                (pid, path, SyscallState::Complete)
            } else {
                (pid.clone(), path, SyscallState::Unfinished(pid))
            }
        })
    }

    fn parse_chdir_resumed(trace: &str) -> Option<(String, SyscallResult)> {
        chdir_resumed.captures(trace).map(|cap| {
            let pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                (pid, SyscallResult::Failure)
            } else {
                (pid, SyscallResult::Success)
            }
        })
    }

    fn parse_clone(trace: &str) -> Option<CloneParse> {
        clone.captures(trace).map(|cap| {
            let parent_pid = String::from(&cap["pid"]);
            if cap["end"].starts_with(')') {
                let child_pid = String::from(&cap["child_pid"]);
                if child_pid == "-1" {
                    CloneParse::FinishedError
                } else {
                    CloneParse::FinishedSuccess {
                        parent_pid,
                        child_pid,
                    }
                }
            } else {
                CloneParse::Unfinished { parent_pid }
            }
        })
    }

    fn parse_clone_resumed(trace: &str) -> Option<CloneParse> {
        clone_resumed.captures(trace).map(|cap| {
            let parent_pid = String::from(&cap["pid"]);
            let retval = String::from(&cap["retval"]);
            if retval.starts_with('-') {
                // negative retval
                CloneParse::FinishedError
            } else {
                CloneParse::FinishedSuccess {
                    parent_pid,
                    child_pid: retval,
                }
            }
        })
    }

    fn read_trace_file(trace: &mut Trace, trace_file: &Path) -> Result<()> {
        let file = File::open(trace_file)?;
        Self::read_trace(trace, BufReader::new(file))
    }

    fn read_trace<T: Read>(trace: &mut Trace, read: T) -> Result<()> {
        // FIXME: this assumes that the contents of the trace are UTF-8; this probably isn't right
        let lines = BufReader::new(read).lines();

        let mut pid_openat_in_progress: HashMap<String, PathBuf> = HashMap::new();
        let mut pid_cwd: HashMap<String, PathBuf> = HashMap::new();
        let mut pid_cwd_in_progress: HashMap<String, PathBuf> = HashMap::new();

        for line in lines {
            let line = line?;
            match Self::parse_openat(&line) {
                Some((pid, filepath, SyscallState::Complete)) => {
                    // FIXME: if we weren't reading this content as UTF-8, we likely wouldn't need to go 'backwards' from a
                    // String to a PathBuf here

                    // FIXME: duplicate between interrupted and complete codepaths
                    let mut filepath = PathBuf::from(&filepath);
                    if let Some(cwd) = pid_cwd.get(&pid) {
                        trace!("trace openat accessed {filepath:?} relative to {cwd:?}");
                        filepath = cwd.join(filepath);
                    } else {
                        trace!(
                            "trace openat accessed {filepath:?} from pid {pid:?} with no known cwd"
                        );
                    }

                    trace.add_open(filepath);
                    continue;
                }
                Some((pid, filepath, SyscallState::Unfinished(_pid))) => {
                    // this openat might fail, and if so we don't want to trace it
                    let mut filepath = PathBuf::from(&filepath);
                    if let Some(cwd) = pid_cwd.get(&pid) {
                        trace!(
                            "trace openat accessed {filepath:?} relative to {cwd:?}; unfinished"
                        );
                        filepath = cwd.join(filepath);
                    } else {
                        trace!(
                            "trace openat accessed {filepath:?} from pid {pid:?} with no known cwd"
                        );
                    }
                    pid_openat_in_progress.insert(pid, PathBuf::from(&filepath));
                    continue;
                }
                None => {}
            }

            match Self::parse_openat_resumed(&line) {
                Some((pid, SyscallResult::Success)) => {
                    let path = pid_openat_in_progress.remove(&pid);
                    if let Some(path) = path {
                        trace.add_open(path);
                    } else {
                        return Err(anyhow!(
                            "pid openat was resumed but no unfinished syscall was found"
                        ));
                    }
                    continue;
                }
                Some((pid, SyscallResult::Failure)) => {
                    pid_openat_in_progress.remove(&pid);
                    continue;
                }
                None => {}
            }

            match Self::parse_chdir(&line) {
                Some((pid, filepath, SyscallState::Complete)) => {
                    let previous_path = pid_cwd.remove(&pid).unwrap_or(PathBuf::from(""));
                    let new_path = previous_path.join(filepath);
                    pid_cwd.insert(pid, new_path);
                }
                Some((pid, filepath, SyscallState::Unfinished(_pid))) => {
                    // this chdir might fail, and if so we don't want to trace it
                    pid_cwd_in_progress.insert(pid, PathBuf::from(&filepath));
                    continue;
                }
                None => {}
            }

            match Self::parse_chdir_resumed(&line) {
                Some((pid, SyscallResult::Success)) => {
                    let path = pid_cwd_in_progress.remove(&pid);
                    if let Some(filepath) = path {
                        // FIXME: code duplication between interrupted and direct path
                        let previous_path = pid_cwd.remove(&pid).unwrap_or(PathBuf::from(""));
                        let new_path = previous_path.join(filepath);
                        pid_cwd.insert(pid, new_path);
                    } else {
                        return Err(anyhow!(
                            "pid openat was resumed but no unfinished syscall was found"
                        ));
                    }
                    continue;
                }
                Some((pid, SyscallResult::Failure)) => {
                    pid_openat_in_progress.remove(&pid);
                    continue;
                }
                None => {}
            }

            if let Some(CloneParse::FinishedSuccess {
                parent_pid,
                child_pid,
            }) = Self::parse_clone(&line).or_else(|| Self::parse_clone_resumed(&line))
            {
                // Inherit working directory
                if let Some(cwd) = pid_cwd.get(&parent_pid) {
                    pid_cwd.insert(child_pid, cwd.clone());
                }
            }
        }

        Ok(())
    }
}

impl SysTraceCommand for STraceSysTraceCommand {
    fn trace_command(&self, orig_cmd: Command, tmp: &Path) -> Result<(Output, Trace)> {
        let mut new_cmd = Command::new("strace");
        new_cmd
            .arg("--follow-forks")
            .arg("--trace=chdir,openat,clone,clone3")
            .arg("--output")
            .arg(tmp);

        new_cmd.arg(orig_cmd.get_program());
        for arg in orig_cmd.get_args() {
            new_cmd.arg(arg);
        }
        for (ref key, ref value) in orig_cmd.get_envs() {
            match value {
                Some(value) => new_cmd.env(key, value),
                None => new_cmd.env_remove(key),
            };
        }
        if let Some(cwd) = orig_cmd.get_current_dir() {
            new_cmd.current_dir(cwd);
        }

        let output = new_cmd.output()?;
        let mut trace = Trace::new();

        if output.status.success() {
            Self::read_trace_file(&mut trace, tmp)?;
        }

        // Occasionally useful for debugging to keep a copy of all the strace output...
        // std::fs::copy(
        //     &tmp,
        //     PathBuf::from("/home/mfenniak/Dev/testtrim-test-projects/logs/strace/")
        //         .join(tmp.file_name().unwrap()),
        // )?;

        Ok((new_cmd.output()?, trace))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openat() {
        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/Fibonacci_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("2892755"),
                String::from("test_data/Fibonacci_Sequence.txt"),
                SyscallState::Complete
            ))
        );

        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/\"Fibonacci\"_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("2892755"),
                String::from("test_data/\"Fibonacci\"_Sequence.txt"),
                SyscallState::Complete
            ))
        );

        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/\"Fibonacci\"_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("2892755"),
                String::from("test_data/\"Fibonacci\"_Sequence.txt"),
                SyscallState::Complete
            ))
        );

        let res = STraceSysTraceCommand::parse_openat(
            // whitespace variations here; strace makes some weak alignment attempts
            r#"6503  openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 4"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("6503"),
                String::from("/proc/self/maps"),
                SyscallState::Complete
            ))
        );

        let res = STraceSysTraceCommand::parse_openat(
            // started without finish
            r#"189531 openat(AT_FDCWD, "README.md", O_RDONLY|O_CLOEXEC <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("189531"),
                String::from("README.md"),
                SyscallState::Unfinished(String::from("189531"))
            ))
        );
    }

    #[test]
    fn parse_openat_resumed() {
        let res = STraceSysTraceCommand::parse_openat_resumed(
            r"189531 <... openat resumed>)            = 4",
        );
        assert_eq!(res, Some((String::from("189531"), SyscallResult::Success)));
        let res = STraceSysTraceCommand::parse_openat_resumed(
            r"189531 <... openat resumed>)            = -1 ENOENT (No such file or directory)",
        );
        assert_eq!(res, Some((String::from("189531"), SyscallResult::Failure)));
    }

    #[test]
    fn parse_chdir() {
        let res =
            STraceSysTraceCommand::parse_chdir(r#"152738 chdir("/home/mfenniak")          = 0"#);
        assert_eq!(
            res,
            Some((
                String::from("152738"),
                String::from("/home/mfenniak"),
                SyscallState::Complete
            ))
        );

        let res = STraceSysTraceCommand::parse_chdir(
            r#"152738 chdir("test_data/\"Fibonacci\"_Sequence.txt") = 0"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("152738"),
                String::from("test_data/\"Fibonacci\"_Sequence.txt"),
                SyscallState::Complete
            ))
        );

        let res = STraceSysTraceCommand::parse_chdir(
            r#"189532 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(
            res,
            Some((
                String::from("189532"),
                String::from("/home/mfenniak/Dev"),
                SyscallState::Unfinished(String::from("189532"))
            ))
        );

        let res = STraceSysTraceCommand::parse_chdir(
            r#"152738 chdir("/home/mfenniak")               = -1 ENOENT (No such file or directory)"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn parse_chdir_resumed() {
        let res = STraceSysTraceCommand::parse_chdir_resumed(
            r"189532 <... chdir resumed>)             = 0",
        );
        assert_eq!(res, Some((String::from("189532"), SyscallResult::Success)));
        let res = STraceSysTraceCommand::parse_chdir_resumed(
            r"189531 <... chdir resumed>)             = -1 ENOENT (No such file or directory)",
        );
        assert_eq!(res, Some((String::from("189531"), SyscallResult::Failure)));
    }

    #[test]
    fn parse_clone() {
        let res = STraceSysTraceCommand::parse_clone(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = 337653",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("337651"),
                child_pid: String::from("337653"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r"416671 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7fcdb7d7f990, parent_tid=0x7fcdb7d7f990, exit_signal=0, stack=0x7fcdb7b7f000, stack_size=0x1fff00, tls=0x7fcdb7d7f6c0} => {parent_tid=[416676]}, 88) = 416676",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("416671"),
                child_pid: String::from("416676"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9f93f88a10) = -1",
        );
        assert_eq!(res, Some(CloneParse::FinishedError));

        let res = STraceSysTraceCommand::parse_clone(
            r"337651 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>",
        );
        assert_eq!(
            res,
            Some(CloneParse::Unfinished {
                parent_pid: String::from("337651")
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r"416676 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0x7fcdb7b73000, stack_size=0x9000}, 88 <unfinished ...>",
        );
        assert_eq!(
            res,
            Some(CloneParse::Unfinished {
                parent_pid: String::from("416676")
            })
        );

        let res = STraceSysTraceCommand::parse_clone(
            r#"337653 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn parse_clone_resumed() {
        let res = STraceSysTraceCommand::parse_clone_resumed(
            r"337651 <... clone resumed>, child_tidptr=0x7f9f93f88a10) = 337654",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("337651"),
                child_pid: String::from("337654"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone_resumed(
            r"416676 <... clone3 resumed>)            = 416677",
        );
        assert_eq!(
            res,
            Some(CloneParse::FinishedSuccess {
                parent_pid: String::from("416676"),
                child_pid: String::from("416677"),
            })
        );

        let res = STraceSysTraceCommand::parse_clone_resumed(
            r"337651 <... clone resumed>, child_tidptr=0x0) = -1 EAGAIN (Some text here)",
        );
        assert_eq!(res, Some(CloneParse::FinishedError));

        let res = STraceSysTraceCommand::parse_clone_resumed(
            r#"337653 chdir("/home/mfenniak/Dev" <unfinished ...>"#,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn multiprocess_cwd() {
        // trace_raw contains an strace that was generated by running scripts/generate-strace-multiproc-chdir.py under
        // strace.  This script accesses these files, but all in separate processes with `chdir` commands to the parent
        // directories; this creates a test case for per-process cwd tracking:
        //
        // - "flake.nix" (from start process's cwd)
        // - "/home/mfenniak/Dev/testtrim/README.md"
        // - "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
        // - "/home/mfenniak/.zsh_history"
        // - "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
        // - "/home/mfenniak/Dev/test.txt"
        //
        // These files aren't required to make this test work; read_trace doesn't canonicalize the paths.
        let trace_raw = include_bytes!("../../tests/test_data/strace-multiproc-chdir.txt");

        let mut trace = Trace::new();

        let res = STraceSysTraceCommand::read_trace(&mut trace, &trace_raw[..]);
        assert!(res.is_ok());

        let paths = trace.get_open_paths();
        assert!(paths.contains(&PathBuf::from("flake.nix")));
        assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/testtrim/README.md")));
        assert!(paths.contains(&PathBuf::from(
            "/home/mfenniak/Dev/wifi-fix-standalone-0.3.1.tar.gz"
        )));
        assert!(paths.contains(&PathBuf::from("/home/mfenniak/.zsh_history")));
        assert!(paths.contains(&PathBuf::from(
            "/nix/store/0019vid273mjmsm95vwjk6zjp50g66xa-openssl-3.0.11/etc/ssl/openssl.cnf"
        )));

        // test.txt is accessed in an unusual way compared to above cases; one process chdir's into /home/mfenniak/Dev,
        // and then starts a subprocess which inherits that directory, and then accesses "test.txt".  So if this test
        // case is failing, it's the inheritence of the cwd from parent processes that is to blame (probably).
        assert!(paths.contains(&PathBuf::from("/home/mfenniak/Dev/test.txt")));
    }
}
