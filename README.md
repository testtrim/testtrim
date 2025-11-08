<!--
SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Introduction

testtrim targets software automated tests for execution based upon previous code-coverage data and git changes.  It's in early development, but it's looking quite promising with evaluations showing that on-average 90% of tests can be safely skipped with this strategy.

I've also published an introductory video:

[Short Introduction Video, 10 minutes](https://youtu.be/wNPeTxf3xFw)

[Deep-dive Introduction Video, 37 minutes](https://youtu.be/YQKc58dTR1M)


# testtrim's Equation

## Core

1. Just like you would use to report test coverage (eg. "75% of our code is tested!"), run tests with a coverage tool.  But rather than running the entire test suite and reporting generalized coverage, run each individual test to get the coverage for each test.

2. Invert the data; change "test case touches code" into "code was touched by test case", and then store it into a database.

3. Look at a source control diff since the last time you did #2 to find out what changes occurred to the code, then look them up in the database to see what test cases need to be run.

This is the core concept behind [testtrim](https://codeberg.org/testtrim/testtrim).

## Supplementary Data

### Local Files

Some tests might access data files while they're running, in order to have a file that contains the expected input or output from a test.  In order to accommodate this, testtrim runs all the tests with syscall tracing (only supported on Linux presently) in order to detect which local files are needed by which tests.  In the future if those local files change, then the tests that read then will be targeted for re-execution.

Some tests might embed local files during their compile; in Rust, using the `include_str!`, `include_bytes!`, or `include!` compiler macros.  testtrim inspects the code to find those include macros, and in the future if those local files are modified, the appropriate tests are targeted for re-execution.

### Network Access

The long-term goal of testtrim is to work with tests that require network services via distributed tracing using OpenTelemetry, in a complicated dance of figuring out whether external dependencies have changed by understanding them in depth.  Presently this capability is on the drawing board only.

testtrim does detect access to external processes through the network.  It's default behavior is that any test that touches the network will always be rerun on a future commit, but [this can be configured](#network-configuration) to meet a variety of needs.

### Tags & Platforms

When running tests on different operating systems, it would be common for different code and tests to be executed.  In order to support situations like this, testtrim supports "tagging" the test results with arbitrary key-value entries which will distinguish its coverage data from other test runs.  The platform that the tests are running on is an automatic default tag.


# How well does it work?

It's early days for testtrim.  It looks **promising**, but not **promised**.

## alacritty evaluation

To evaluate how well it worked, I took an Open Source project ([alacritty](https://github.com/alacritty/alacritty)), and I ran the last 100 commits through testtrim.  testtrim has a command `simulate-history` that does this automatically and generates a CSV file with the output data, which can be easily analyzed:

| # Commits:                           |       100 |
|--------------------------------------|----------:|
| # Commits Successful Build & Test:   |        83 |
| # Commits Analyzed w/ Ancestor Data: |        82 |
| Average Tests to Run per Commit:     | **14.5%** |
| Median Tests to Run per Commit:      |  **1.6%** |
| P90 Tests to Run per Commit:         | **54.6%** |

For each commit, testtrim identified that an average of only 14.5% of tests needed to be executed to fully test the code change that was being made.

I could list a dozen reasons why this analysis isn't generalizable... and so I will:

- alacritty is a pretty mature project that isn't undergoing rapid development.
- alacritty has some tests that work through reading static files; changes to those files wouldn't be considered as requiring reruns of the related tests because they don't appear in code coverage and testtrim doesn't do anything else to compensate for that.
- There's no evidence that a test on a single project will generalize to lots of other projects.
- The only guarantee of correctness in this analysis is my own eyeballing of the changes and proposed tests.

## ripgrep evaluation

The same evaluation was performed on [ripgrep](https://github.com/BurntSushi/ripgrep), which has a slightly larger test base (>1000 unit tests) than alacritty, using the `simulate-history` command on the past 100 commits:

| # Commits:                           |       100 |
|--------------------------------------|----------:|
| # Commits Successful Build & Test:   |       100 |
| # Commits Analyzed w/ Ancestor Data: |        99 |
| Average Tests to Run per Commit:     |  **6.0%** |
| Median Tests to Run per Commit:      |  **0.0%** |
| P90 Tests to Run per Commit:         | **12.7%** |

These results are also great, but suffer from some of the same reasons listed above for why it may not be generalizable to every project

# Feature Matrix

testtrim supports a small number of test project types in different programming languages and runtimes, but not all of them have the same features and capabilities.

| Feature | Rust | Go | .NET (C#, etc.) | JavaScript |
|---|:---:|:---:|:---:|:---:|
| File-based coverage tracking<br>(ie. changes that will affect tests are tracked on a file-by-file basis;<br>the least granular but simplest approach) | ✅ | ✅ | ✅ | ✅ |
| Function-based coverage tracking<br>(Only theorized, not implemented at all yet) | ❌ | ❌ | ❌ | ❌ |
| External dependency change tracking | ✅ | ✅ | ❌ | ❌ |
| syscall tracking for file & network tracking | ✅ | ✅ | ❌ | ❌ |
| Embedded file tracking (ie. if a file embeds another file, changes to<br>either will trigger related tests) | ✅ | ✅ | ❌ | ❌ |
| Performance | 👍 | OK | Mega-👎 | OK |

# Coverage Database

testtrim's coverage database has three implementations accessible through the `TESTTRIM_DATABASE_URL` environment variable:
- SQLite database: `file://...` with a file path, or `:memory:` for a temporary in-memory database.
- PostgreSQL database: `postgres://` with optional credentials, hostname, and a database; eg. `postgres://user:password@host/database`.
- Remote API:
    - The server is an instance of `testtrim` running with the `run-server` subcommand, which needs to have it's own `TESTTRIM_DATABASE_URL` configured to either a SQLite or PostgreSQL database URL.
    - The client accesses the remote server via a `TESTTRIM_DATABASE_URL` set to `http://...` or `https://...` with the host and port of the testtrim database.

# Known Issues

## Limited Scope

I'd love for testtrim to have a larger scope of applicability.

Scope today:
- Platforms: limited; see Feature Matrix
- Most testing is completed with
- Coverage database can be shared through a shared PostgreSQL database or remote web API

Scope planned for the future:
- Integrate with third-party test runners, rather than owning the entire test execution process
- More platforms (eg. JavaScript, Java, Python, C#, etc.)
- Track changes to external dependencies that are [accessed over a network](https://codeberg.org/testtrim/testtrim/issues/27), and allow running only relevant tests when they change
- Perform more granular [function-level tracing](https://codeberg.org/testtrim/testtrim/issues/16) to reduce targeted test suite

## Known Known Issues

Significant problems that are known to exist within the scope described above, and should be known to any users:

- **Rust**:
    - testtrim can be fooled [when a `pub const` value, or a `lazy_static` value, is modified](https://codeberg.org/testtrim/testtrim/issues/52), and target fewer tests than required.  However, this would require that the const be modified in a file by itself, without any tests requiring modification, which seems to have a very low likelihood.
- **Go**:
    - Go does not instrument test files (`*_test.go`) when tests are executed, preventing testtrim from identifying what codepaths are executed in those files for each test.  As a substitute, testtrim makes the assumption that changing such a file requires rerunning all the tests defined in this file.  This is a reasonable approximation, but tests may reference each other or common utility functions defined in other `*_test.go` files and such dependencies cannot be identified at this time.
    - testrim can be fooled when [`const` and package-level `var` values are changed](https://codeberg.org/testtrim/testtrim/issues/136).  The codepaths to initialize these values are always invoked regardless of whether they're accessed or not, and so testtrim can't tell the difference between initialization and access.
    - The current Go implementation requires building test binaries into temp storage space and then executing them, which will likely be incompatible with `noexec` tmp spaces.
- **JavaScript**:
    - The project under test must use a specific supported combination of tools:
        - the `npm` package manager must be used (not `pnpm` or `yarn`); other tooling is possible in the future but not currently implemented
        - `npm test` must run `nyc`
        - the tests must be implemented with the `mocha` test platform; it may be possible to add support for more tooling, but a hard requirement of the test runner is that it supports a "dry run" mode to discover the available tests in a test suite which precludes the use of some more popular testing tools like `jest` at the moment
    - JavaScript support for external dependency tracking and syscall tracing is planned, but not currently implemented.
- testtrim isn't published as a released tool and must be checked out and built from source.
    - exception: testtrim has an OCI/Docker container published intended as a Remote API server, the container is `codeberg.org/testtrim/server:latest`
- Using the [Network Configuration](#network-configuration) feature is often necessary to reduce superfluous test re-execution; however it's capabilities in matching hostnames for connections is limited by current DNS interpretation limitations such as [inaccurate multithreading support](https://codeberg.org/testtrim/testtrim/issues/217).

## Known Unknown Issues

Unknowns within the scope described above, which should be considered with skepticism for the moment:

- **Rust**:
    - testtrim hasn't been [tested with macros](https://codeberg.org/testtrim/testtrim/issues/40) to ensure that changes that touch them are appropriately tested.  It's probably fine though.
- **JavaScript**:
    - Modifications to exports from a file that are not functions, such as constants, will likely fool testtrim into believing that no test-relevant changes have been made.

# How to use?

Oh, well, I'm not quite sure I'd recommend that right now.  But it could be fun to experiment with.

- Clone the git repo:
    ```
    git clone https://codeberg.org/testtrim/testtrim.git
    ```

- (Optional, for PostgreSQL backend): Run DB migrations to create a testtrim database; see notes under [Development](#development) below for more information:
    ```bash
    sqlx migrate run --source ./db/postgres/migrations
    ```

- Build the project with `cargo`; might as well use the release mode for optimizations:
    ```
    cargo build --release
    ```

- Change directory into a Rust project that you'd like to test.

- Using the built testtrim binary from wherever you put the repo, run the `run-tests` command.

    **Clean working directory**: run at least once with a clean working directory and verify that the output says `save_coverage_data: true` in order to get a baseline for future runs.

    Use `-vv` for verbose output.

    Example:

    ```
    $ ~/Dev/testtrim/target/release/testtrim run-tests -vv
    19:11:19 [INFO] source_mode: Automatic, save_coverage_data: true, ancestor_search_mode: SkipHeadCommit
    19:11:19 [WARN] no base commit identified with coverage data to work from
    19:11:19 [INFO] successfully ran tests
    ```

- Make some changes to your project, and rerun testtrim.

    ```
    $ ~/Dev/testtrim/target/release/testtrim run-tests -vv
    19:12:05 [INFO] source_mode: Automatic, save_coverage_data: false, ancestor_search_mode: AllCommits
    19:12:06 [INFO] relevant test cases will be computed base upon commit "c15667fe0655a2fcb43b4c88cd900ede3921f23c"
    relevant test cases are 2 of 8, 25%
    19:12:06 [INFO] successfully ran tests
    ```

    Hopefully you'll see the output "relevant test cases" which indicates how many tests were relevant for the change you made.

- Note that testtrim will by-default store coverage data in `$XDG_CACHE_HOME/testtrim/testtrim.db`, or `$HOME/.cache` if `$XDG_CACHE_HOME` is undefined; or uses a PostgreSQL database defined at the environment variable `TESTTRIM_DATABASE_URL`.  This data allows testtrim to make determinations on what tests need to be executed for future changes.

## Network Configuration

By default, every time a test accesses the network it will be assumed that on future commits the test will need to be rerun in order to continue to verify its assertions hold true.  This is a conservative choice aimed at never missing a regression; if the test accessed the network then testtrim assumes it might test something that could have changed since last run.

However, there are a few common cases where this assumption isn't the case and you might want to change the behavior.  testtrim supports reading a `.config/testtrim.toml` file from the source repo and tweaking its network behavior based upon that.

It is important to remember that network detection builds on top of code-coverage testing; it doesn't replace it.  When code is changed that affects a test it will always rerun related tests regardless of the network configured rules.

The starting point for evaluating what network configuration rules are required in your project is:

1. Run `testtrim run-tests --source-mode=clean-commit` on your repo.

    `--source-mode=clean-commit` indicates to testtrim that you expect this test run to be on a clean repo, generating a coverage record for this run.  If the repo isn't clean, the command will fail.

    If no coverage record is available, we won't be able to identify what tests access the network.  But if you've already run testtrim and saved a coverage record, this isn't needed.

2. Run `testtrim get-test-identifiers`:

    Example output:
    ```
    RustTestIdentifier { test_src_path: "src/lib.rs", test_name: "network::tests::test_tcp_connection_to_google" }
        CoverageIdentifier(NetworkDependency(Inet([2607:f8b0:400a:800::200e]:80)))
        CoverageIdentifier(NetworkDependency(Unix("/var/run/nscd/socket" (pathname))))
    ```

    This will output every test that testtrim believes needs to be run, and indented after the test **why** testtrim believes the test needs to be run.  In this example, it is indicating that the test made two network connections -- one to `2607:f8b0:400a:800::200e` on port `80`, and one to the Unix socket `/var/run/nscd/socket`.

3. Evaluate each test and determine the desired behavior.

    This typically falls into these categories:
    - The network connection is related to the subject under test, but it needs to be rerun only when another file changes.  Create a `network-policy` that matches it and set `apply.run-if-files-changed`.
    - The network connection is related to the subject under test, and it is desirable that the test always be run to ensure the test assertions are correct.  Don't do anything; that's the default behavior.
    - The network connection is internal, unexpected, or unrelated to the subject under test.  Create a `network-policy` that matches it and set `apply = "ignore"` on the policy so that the test is not always run.

Here are some real-world examples of network configuration:

### Internal Networking

If a test does internal networking -- for example, starting up a network server itself, and then connecting to it as part of test assertions -- it would make perfect sense to ignore this network access completely.

testtrim itself has a couple examples of this.
1. Within its remote API tests, it needs to make HTTP requests to a test server which it starts itself.
2. When running .NET builds, the `dotnet` subprocess uses sockets for interprocess communication.

To prevent tests that do this from rerunning all the time, you can selectively disable network access from triggering tests by identifying the network access that is safe and creating an "ignore" policy for it.  The below policy stored into `.config/testtrim.toml` would ignore access to a localhost port range where a test server might run, for example.  (See [config file reference](#config-file-reference) for more detail on options)

```toml
[[network-policy]]
name = "local test server"
apply = "ignore"
[[network-policy.match]]
address-port-range = ["127.0.0.1/32", "8000-8100"]
```

### Network Related Changes

Another case where network access will commonly occur during tests is when you integrate with a database server.  In this case, you might want to selectively run tests only if related code files have changed.

testtrim itself has an example of this; its PostgreSQL coverage database module runs against a live PostgreSQL database server.  Even though these tests touch the network in order to reach PostgreSQL, they do not need to be rerun every time testtrim is tested.  Instead, we can configure a policy to rerun these tests when there are other indications that their behavior might be affected:
1. If the PostgreSQL schema has been changed,
2. Or if the test environment has been changed,
3. (Or if the code for the module or tests has been changed -- but this is automatic with the code coverage checks).

The below policy stored into `.config/testtrim.toml` would ignore access to PostgreSQL during the tests unless the schema or test environment is changed:  (See [config file reference](#config-file-reference) for more detail on options)

```toml
[[network-policy]]
name = "PostgreSQL access"
apply.run-if-files-changed = [
    ".forgejo/workflows/rust-check.yaml",
    "db/postgres/*.sql",
]
[[network-policy.match]]
port = 5432
```

### Change Defaults

If you wanted to change the default behavior of running any test that touched the network, you could also ignore all network access.

```toml
[[network-policy]]
name = "all network access"
apply = 'ignore'
[[network-policy.match]]
unix-socket = "**"
[[network-policy.match]]
address = "0.0.0.0/0"
[[network-policy.match]]
address = "::/0"
```

# Config File Reference

The config file must be found within the repository under test at the location `config/testtrim.toml`.

## network-policy

One or more network-policy tables can exist in the file, which must contain:

- `name` -- the name of the policy.  This will appear in the output of the `get-test-identifiers` subcommand and various debug logs to help identify the impact of the policy.
- `apply` -- the outcome of the policy.  If a test performed network access that matched the policy, then the `apply` value is evaluated and...
    - `ignore` -- will cause that network access to be ignored.
    - `run-always` -- will cause this network access to run this test.  This overrides any other ignores that might be present, allowing you to define broad ignore rules and then enable specific network access to be rerun.
    - `run-if-files-changed` -- will cause this network access to run this test *if* one-or-more files has been changed.  The value of `run-if-files-changed` must be an array of paths, which can contain `**` (wildcard) and `*` (wildcard within directory) wildcards.
- `match` -- one or more match policies which are evaluated against the network access to see if the policy should be applied.  `match` can contain one of:
    - `unix_socket` -- path to a unix socket, which can contain `**` (wildcard) and `*` (wildcard within directory) wildcards.
    - `port` -- a single network port; all addresses will match.
    - `address` -- an IPv4 or IPv6 subnet CIDR (eg. `10.0.0.0/8`, `192.168.1.0/24`, `127.0.0.1/32`, `::1/128`); all ports will match.
    - `port-range` -- an inclusive range of network ports, eg. `"8000-8100"`; all addresses will match.  Note that this range must be quoted otherwise the TOML parser will believe it is a number and fail.
    - `address-port` -- an array of an address and a port, eg. `["127.0.0.1/32", 8080]`
    - `address-port-range` -- an address of an address and port range, eg. `["127.0.0.1/32", "8085-8086"]`
    - `host` -- a hostname, eg. `"localhost"`, on any network port.
        - **Note**: hostname matching internally functions by monitoring hostname resolution while the process is running.  This functions by monitoring traffic to `/var/run/nscd/socket` and DNS servers (on port `:53`) and decoding it.  This capability is therefore only available when syscall tracing is supported, which is currently limited to Linux systems with `strace` available.
        - **Note**: hostname matching can have unexpected outcomes; if a two hostnames resolve to the same IP address, then any network traffic to that IP address will match network policies from either hostname as testtrim cannot identify which hostname was used for that network traffic.
    - `host-port` -- an array of a hostname and a port, eg. `["127.0.0.1/32", 8080]`; notes for `host` still apply
    - `host-port-range` -- an address of a hostname and port range, eg. `["127.0.0.1/32", "8085-8086"]`; notes for `host` still apply

Here is a complete config file showing all available options (although having little logical meaning; see [Network Configuration](#network-configuration) for an explanation of plausible real-world configurations:

```toml
[[network-policy]]
name = "DNS access" # used to report test reasons in get-test-identifiers
apply = 'run-always'
[[network-policy.match]]
unix-socket = "/var/run/nscd/socket"
[[network-policy.match]]
port = 53

[[network-policy]]
name = "internal test servers"
apply = 'ignore'
[[network-policy.match]]
port-range = "16384-32768"
[[network-policy.match]]
address = "10.0.0.0/8"
[[network-policy.match]]
address = "::1/128"
[[network-policy.match]]
address-port = ["127.0.0.1/32", 8080]
[[network-policy.match]]
address-port-range = ["127.0.0.1/32", "8085-8086"]

[[network-policy]]
name = "PostgreSQL server"
apply.run-if-files-changed = [
    "db/postgres/*.sql",
]
[[network-policy.match]]
port = 5432
```

# Development

testtrim uses [direnv](https://direnv.net/) so that you can just drop into the testtrim directory and have all the necessary development dependencies provided within your shell automatically.

The development dependencies are provided by a [Nix shell](https://nix.dev/), which requires the Nix package manager to be installed.  The Nix shell then provides the correct version of all development tools, eg. rustc, cargo, etc.

## PostgreSQL Backend

testtrim's PostgreSQL tests require a functional PostgreSQL database to be available.  This database must be available at the URL defined by the `TESTTRIM_UNITTEST_PGSQL_URL` env variable (w/ fallback to `TESTTRIM_DATABASE_URL`).  You can define this manually, or you can define it in a `.localenvrc` file which would not be checked in, and would be local to your workspace.  For example:

```bash
$ cat .localenvrc
export TESTTRIM_DATABASE_URL="postgres://user:password@localhost/database"
```

Two operations also require a `DATABASE_URL` PostgreSQL parameter; running sqlx migrations to prepare a PostgreSQL database, and freezing any sqlx queries defined in `postgres_sqlx.rs`.

```bash
# Prepare database for future execution or query modifications:
DATABASE_URL=$TESTTRIM_DATABASE_URL sqlx migrate run --source ./db/postgres/migrations

# Freeze queries:
DATABASE_URL=$TESTTRIM_DATABASE_URL cargo sqlx prepare
```
