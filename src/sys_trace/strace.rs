// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use super::{trace::Trace, SysTraceCommand};

/// Implementation of `SysTraceCommand` that uses the `strace` command to trace all the relevant system calls.
pub struct STraceSysTraceCommand;

lazy_static! {
    static ref openat: Regex = Regex::new(
        // note that this will exclude any openat that had an error (eg. ENOENT) because it checks for a returned
        // file-descriptor; that probably makes sense?
        r#"^(?<pid>[0-9]+)\s+openat\(AT_FDCWD,\s+"(?<path>(?:[^"\\]|\\.)*)",\s+[^)]+\)\s+=\s+\d+$"#
    )
    .unwrap();
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

    fn parse_openat(trace: &str) -> Option<String> {
        // Note: only openat w/ AT_FDCWD is supported, which opens a path from the current working directory (unless
        // absolute).  Opening a directory, then opening a file in it, isn't supported by this.  FIXME: It *should*
        // probably be detected and either a warning or error generated though, so that it's not silently ignored.
        openat.captures(trace).map(|cap| {
            String::from(&cap["path"])
                // Un-escape any escaped double-quotes
                .replace("\\\"", "\"")
        })
    }

    fn read_trace(&self, trace: &mut Trace, trace_file: &Path) -> Result<()> {
        let file = File::open(trace_file)?;

        // FIXME: this assumes that the contents of the trace are UTF-8; this probably isn't right
        let lines = BufReader::new(file).lines();

        for line in lines {
            let line = line?;
            if let Some(filepath) = Self::parse_openat(&line) {
                // FIXME: if we weren't reading this content as UTF-8, we likely wouldn't need to go 'backwards' from a
                // String to a PathBuf here
                trace.add_open(PathBuf::from(&filepath));
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
            .arg("--trace=openat")
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
            self.read_trace(&mut trace, tmp)?;
        }

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
        assert_eq!(res, Some(String::from("test_data/Fibonacci_Sequence.txt")));

        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/\"Fibonacci\"_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some(String::from("test_data/\"Fibonacci\"_Sequence.txt"))
        );

        let res = STraceSysTraceCommand::parse_openat(
            r#"2892755 openat(AT_FDCWD, "test_data/\"Fibonacci\"_Sequence.txt", O_RDONLY|O_CLOEXEC) = 3"#,
        );
        assert_eq!(
            res,
            Some(String::from("test_data/\"Fibonacci\"_Sequence.txt"))
        );

        let res = STraceSysTraceCommand::parse_openat(
            // whitespace variations here; strace makes some weak alignment attempts
            r#"6503  openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 4"#,
        );
        assert_eq!(res, Some(String::from("/proc/self/maps")));
    }
}
