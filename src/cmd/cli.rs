// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand, ValueEnum};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::fmt::Debug;

use super::{get_test_identifiers, run_tests, simulate_history};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)] // FIXME: are there things that should be customized here?
pub struct Cli {
    #[command(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Temporary no-operation command
    Noop,

    /// List test identifiers in the target project
    GetTestIdentifiers {
        /// Strategy for test selection
        #[arg(value_enum, long, default_value_t = GetTestIdentifierMode::Relevant)]
        test_selection_mode: GetTestIdentifierMode,
    },

    /// Execute tests in the target project, recording per-test coverage data
    RunTests {
        // FIXME: there's probably some kind of sub-structure that could be used to make a common set of arguments
        // between GetTestIdentifiers & RunTests -- which will likely include test targeting, database access, target
        // project, etc.
        /// Strategy for test selection
        #[arg(value_enum, long, default_value_t = GetTestIdentifierMode::Relevant)]
        test_selection_mode: GetTestIdentifierMode,

        /// Strategy for treating the working directory and coverage map storage
        #[arg(value_enum, long, default_value_t = SourceMode::Automatic)]
        source_mode: SourceMode,
    },

    /// Run through a series of historical commits and simulate using testtrim
    SimulateHistory {
        /// Number of historical commits to simulate
        #[arg(short, long, default_value_t = 100)]
        num_commits: u16,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum GetTestIdentifierMode {
    /// All tests will be executed.
    All,
    /// Coverage maps and diffs will be used to identify a subset of tests to run
    Relevant,
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
        Commands::GetTestIdentifiers {
            test_selection_mode,
        } => get_test_identifiers::cli(test_selection_mode),
        Commands::RunTests {
            test_selection_mode,
            source_mode,
        } => run_tests::cli(test_selection_mode, source_mode),
        Commands::SimulateHistory { num_commits } => simulate_history::cli(num_commits),
    }
}
