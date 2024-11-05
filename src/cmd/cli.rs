// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Args, Parser, Subcommand, ValueEnum};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::fmt::Debug;

use crate::coverage::Tag;

use super::{get_test_identifiers, run_tests, simulate_history};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Temporary no-operation command
    Noop,

    /// List test identifiers in the target project
    GetTestIdentifiers {
        #[command(flatten)]
        target_parameters: TestTargetingParameters,
    },

    /// Execute tests in the target project, recording per-test coverage data
    RunTests {
        #[command(flatten)]
        target_parameters: TestTargetingParameters,

        #[command(flatten)]
        execution_parameters: TestExecutionParameters,

        /// Strategy for treating the working directory and coverage map storage
        #[arg(value_enum, long, default_value_t = SourceMode::Automatic)]
        source_mode: SourceMode,
    },

    /// Run through a series of historical commits and simulate using testtrim
    SimulateHistory {
        #[command(flatten)]
        execution_parameters: TestExecutionParameters,

        /// Number of historical commits to simulate
        #[arg(short, long, default_value_t = 100)]
        num_commits: u16,
    },
}

#[derive(Args, Debug)]
struct TestTargetingParameters {
    /// Strategy for test selection
    #[arg(value_enum, long, default_value_t = GetTestIdentifierMode::Relevant)]
    test_selection_mode: GetTestIdentifierMode,

    /// Tags in a key=value format
    ///
    /// Tags differentiate coverage storage, allowing the same project to be tested in different configurations.  For
    /// example, you could run tests with a tag `database=postgresql`, and later tests with a tag `database=mysql`, and
    /// the two tags would have coverage maps tracked separately.  This would allow a change that only affects one
    /// codepath to trigger only tests that are related to that codepath.
    #[arg(long)]
    tags: Vec<Tag>,

    /// Whether or not to add the `platform` tag automatically to test results
    #[arg(value_enum, long, default_value_t=PlatformTaggingMode::Automatic)]
    platform_tagging_mode: PlatformTaggingMode,
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
struct TestExecutionParameters {
    /// Number of parallel jobs for test execution; defaults to # of CPUs.
    #[arg(short, long, default_value_t = 0)]
    jobs: u16,
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

pub fn run_cli() {
    let cli = Cli::parse();

    TermLogger::init(
        cli.verbose.log_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .expect("termlogger init failed");

    match &cli.command {
        Commands::Noop => {}
        Commands::GetTestIdentifiers { target_parameters } => {
            get_test_identifiers::cli(
                &target_parameters.test_selection_mode,
                &get_test_identifiers::tags(
                    &target_parameters.tags,
                    target_parameters.platform_tagging_mode,
                ),
            );
        }
        Commands::RunTests {
            target_parameters,
            source_mode,
            execution_parameters,
        } => {
            run_tests::cli(
                &target_parameters.test_selection_mode,
                source_mode,
                execution_parameters.jobs,
                &get_test_identifiers::tags(
                    &target_parameters.tags,
                    target_parameters.platform_tagging_mode,
                ),
            );
        }
        Commands::SimulateHistory {
            num_commits,
            execution_parameters,
        } => {
            simulate_history::cli(*num_commits, execution_parameters.jobs);
        }
    }
}
