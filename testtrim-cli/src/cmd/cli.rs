// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use log::set_max_level;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::{
    fmt::Debug,
    fs::{self},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    coverage::Tag,
    platform::{
        dotnet::DotnetTestPlatform, golang::GolangTestPlatform,
        javascript::JavascriptMochaTestPlatform, rust::RustTestPlatform,
    },
    server::{self},
};

use super::{get_test_identifiers, run_tests, simulate_history};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonOptions,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Debug)]
pub struct CommonOptions {
    #[command(flatten)]
    verbose: Verbosity<WarnLevel>,

    /// Disable progress bars and spinners, even if the terminal supports them.
    #[arg(short, long, global = true)]
    pub no_progress: bool,

    /// Project directory to operate within.  Defaults to the current working directory.
    #[arg(short, long, global = true, default_value = ".")]
    pub project_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Temporary no-operation command
    Noop,

    /// List test identifiers in the target project
    GetTestIdentifiers(GetTestIdentifiersOptions),

    /// Execute tests in the target project, recording per-test coverage data
    RunTests(RunTestsOptions),

    /// Run through a series of historical commits and simulate using testtrim
    SimulateHistory(SimulateHistoryOptions),

    /// Run a testtrim web server for remote access to a coverage database
    RunServer {
        /// Socket to bind for server
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind_socket: SocketAddr,
    },
}

#[derive(Args, Debug)]
struct GetTestIdentifiersOptions {
    #[command(flatten)]
    target_parameters: TestTargetingParameters,
}

#[derive(Args, Debug)]
pub struct RunTestsOptions {
    #[command(flatten)]
    pub target_parameters: TestTargetingParameters,

    #[command(flatten)]
    pub execution_parameters: TestExecutionParameters,

    /// Strategy for treating the working directory and coverage map storage
    #[arg(value_enum, long, default_value_t = SourceMode::Automatic)]
    pub source_mode: SourceMode,
}

#[derive(Args, Debug)]
pub struct SimulateHistoryOptions {
    /// Software platform for running tests
    #[arg(value_enum, long, default_value_t=TestProjectType::AutoDetect)]
    pub test_project_type: TestProjectType,

    #[command(flatten)]
    pub execution_parameters: TestExecutionParameters,

    /// Number of historical commits to simulate
    #[arg(short, long, default_value_t = 100)]
    pub num_commits: u16,

    /// Override the in-repo testtrim.toml with a static config file
    #[arg(short, long)]
    pub override_config: Option<String>,
}

#[derive(Args, Debug)]
pub struct TestTargetingParameters {
    /// Software platform for running tests
    #[arg(value_enum, long, default_value_t=TestProjectType::AutoDetect)]
    pub test_project_type: TestProjectType,

    /// Strategy for test selection
    #[arg(value_enum, long, default_value_t = GetTestIdentifierMode::Relevant)]
    pub test_selection_mode: GetTestIdentifierMode,

    /// Tags in a key=value format
    ///
    /// Tags differentiate coverage storage, allowing the same project to be tested in different configurations.  For
    /// example, you could run tests with a tag `database=postgresql`, and later tests with a tag `database=mysql`, and
    /// the two tags would have coverage maps tracked separately.  This would allow a change that only affects one
    /// codepath to trigger only tests that are related to that codepath.
    #[arg(long)]
    pub tags: Vec<Tag>,

    /// Whether or not to add the `platform` tag automatically to test results
    #[arg(value_enum, long, default_value_t=PlatformTaggingMode::Automatic)]
    pub platform_tagging_mode: PlatformTaggingMode,

    /// Override the in-repo testtrim.toml with a static config file
    #[arg(short, long)]
    pub override_config: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum TestProjectType {
    /// Will attempt to identify the test project via simple heuristics
    AutoDetect,

    /// Operate on Rust tests; eg. using `cargo test`
    Rust,

    /// Operate on .NET tests; eg. using `dotnet test`
    Dotnet,

    /// Operate on Go language tests; eg. using `go test`
    Golang,

    /// Operate on JavaScript tests using the mocha test framework for discovery and execution
    JavascriptMocha,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum GetTestIdentifierMode {
    /// All tests will be executed.
    All,

    /// Coverage maps and diffs will be used to identify a subset of tests to run
    Relevant,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum PlatformTaggingMode {
    /// Automatically add the `platform` tag based upon the target triplet (eg. `x86_64-unknown-linux-gnu`)
    Automatic,

    /// Do not automatically add the `platform` tag
    None,
}

#[derive(Args, Debug)]
pub struct TestExecutionParameters {
    /// Number of parallel jobs for test execution; defaults to # of CPUs
    #[arg(short, long, default_value_t = 0)]
    pub jobs: u16,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum SourceMode {
    /// Automatically selects `CleanCommit` if the working tree is clean, and `WorkingTree` otherwise.
    Automatic,

    /// Tests run on the working tree, and a coverage map is saved under the HEAD commit; working tree must be clean.
    ///
    /// `CleanCommit` will fail if the current working tree is not clean, as that could indicate uncommited changes that
    /// would then be saved into the coverage map for that commit, possibly corrupting the coverage data.  It is
    /// recommended to use `CleanCommit` for continuous integration systems which are providing the coverage map, either
    /// for other developers, or for future continuous integration runs -- the advantage it has over `Automatic` is that
    /// it will never silently skip producing a coverage map.
    CleanCommit,

    /// Tests run on the working tree, and a coverage map is saved under the HEAD commit.
    ///
    /// This is similar to `CleanCommit` but overriding the check for a clean repository.  This is provided for
    /// situations where a continuous integration system might expect to have a dirty working tree, but it's still the
    /// correct functional implementation of the tests.
    OverrideCleanCommit,

    /// Tests will be run with the contents of the current working tree, and no coverage map will be saved.
    ///
    /// If available, a recent commit may still be used as a basis for identifying useful tests to run.  This mode is
    /// recommended for developers working on braches or local trees before they are finalized.
    WorkingTree,
}

#[allow(clippy::print_stderr)]
pub fn process_common(common: &mut CommonOptions) -> Option<ExitCode> {
    let project_dir = &common.project_dir;
    match fs::canonicalize(project_dir) {
        Ok(project_dir) => {
            common.project_dir = project_dir;
            None
        }
        Err(e) => {
            eprintln!("Unable to canonicalize project dir: {e}");
            Some(ExitCode::FAILURE)
        }
    }
}

pub async fn run_cli() -> ExitCode {
    let mut cli = Cli::parse();
    let logger = TermLogger::new(
        cli.common.verbose.log_level_filter(),
        Config::default(),
        TerminalMode::Stdout, // progress bars go on stderr, so by logging to stdout we can redirect this output to get a clean log
        ColorChoice::Auto,
    );
    set_max_level(cli.common.verbose.log_level_filter());

    match &cli.command {
        Commands::Noop => ExitCode::SUCCESS,
        Commands::GetTestIdentifiers(options) => {
            if let Some(exit_code) = process_common(&mut cli.common) {
                exit_code
            } else {
                get_test_identifiers::cli(logger, &cli.common, &options.target_parameters).await
            }
        }
        Commands::RunTests(options) => {
            if let Some(exit_code) = process_common(&mut cli.common) {
                exit_code
            } else {
                run_tests::cli(logger, &cli.common, options).await
            }
        }
        Commands::SimulateHistory(options) => {
            if let Some(exit_code) = process_common(&mut cli.common) {
                exit_code
            } else {
                simulate_history::cli(logger, &cli.common, options).await
            }
        }
        Commands::RunServer { bind_socket } => {
            server::cli(logger, bind_socket).await;
            ExitCode::SUCCESS
        }
    }
}

#[must_use]
pub fn autodetect_test_project_type(project_dir: &Path) -> TestProjectType {
    if RustTestPlatform::autodetect(project_dir) {
        TestProjectType::Rust
    } else if GolangTestPlatform::autodetect(project_dir) {
        TestProjectType::Golang
    } else if DotnetTestPlatform::autodetect(project_dir) {
        TestProjectType::Dotnet
    } else if JavascriptMochaTestPlatform::autodetect(project_dir) {
        TestProjectType::JavascriptMocha
    } else {
        panic!("Autodetect test project type failed.");
    }
}
