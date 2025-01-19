<!--
SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# strace syscall tracing

In the "straight-forward" approach where testtrim is executing a test under strace:

```mermaid
sequenceDiagram
    testtrim->>strace: "--trace ..."
    strace->>test: Execute
    loop Every Syscall
        test->>strace: ptrace(SYSCALL)
        strace->>testtrim: data (over pipe)
        testtrim->>testtrim: Parse & Build Trace
        strace->>test: Resume
    end
    test->>strace: Exit
    strace->>testtrim: Exit
    testtrim->>testtrim: Read Pipe to EOF, Build Trace
```

However, when testtrim runs it's own tests, it can't run a nested strace under strace.  We work around that by having the child process (test) coordinate with the parent process (testtrim) to receive syscall data:


```mermaid
sequenceDiagram
    testtrim->>strace: "--trace ..."
    strace->>test: Execute
    loop Every Syscall
        test->>strace: ptrace(SYSCALL)
        strace->>testtrim: data (over pipe)
        testtrim->>testtrim: Parse & Build Trace
        strace->>test: Resume
    end
    test->>Nested-strace: fork subprocess (PID)
    Nested-strace->>Nested-strace: Wait
    test->>testtrim: Subscribe (PID)
    testtrim->>test: Subscription w/ shmem
    test->>Nested-strace: Start Event
    Nested-strace->>Nested-strace: execve subprocess
    testtrim->>testtrim: Write shmem
    test->>test: Read shmem, Parse, Build Trace
    Nested-strace->>test: Exit
    test->>test: Wait
    testtrim->>testtrim: Notice Process Tree Empty
    testtrim->>test: EOF marker in shmem
    test->>test: Finalize Trace
    test->>strace: Exit
    strace->>testtrim: Exit
    testtrim->>testtrim: Read Pipe to EOF, Build Trace
```
