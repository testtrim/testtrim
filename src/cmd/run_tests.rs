// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, marker::PhantomData, path::PathBuf};

use anyhow::Result;
use log::{error, info};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{
    cmd::get_test_identifiers::{get_target_test_cases, AncestorSearchMode},
    commit_coverage_data::CoverageIdentifier,
    db::{CoverageDatabase, DieselCoverageDatabase},
    errors::RunTestsErrors,
    platform::{
        rust::RustTestPlatform, ConcreteTestIdentifier, TestDiscovery, TestIdentifier, TestPlatform,
    },
    scm::{git::GitScm, Scm, ScmCommit},
};

use super::cli::{GetTestIdentifierMode, SourceMode};

// Design note: the `cli` function of each command performs the interactive output, while delegating as much actual
// functionality as possible to library methods that don't do interactive output but instead return data structures.
pub fn cli(test_selection_mode: &GetTestIdentifierMode, source_mode: &SourceMode) {
    match run_tests::<_, _, _, _, _, _, RustTestPlatform>(
        test_selection_mode,
        &GitScm {},
        source_mode,
    ) {
        Ok(out) => {
            println!("successfully executed tests");
            println!(
                "target test cases were {} of {}, {}%",
                out.target_test_cases.len(),
                out.all_test_cases.len(),
                100 * out.target_test_cases.len() / out.all_test_cases.len(),
            );
        }
        Err(err) => {
            error!("error occurred in run_tests: {:?}", err)
        }
    }
}

pub struct RunTestsOutput<Commit: ScmCommit, TI: TestIdentifier, CTI: ConcreteTestIdentifier<TI>> {
    // Test discovery and analysis results
    pub all_test_cases: HashSet<CTI>,
    pub target_test_cases: HashSet<CTI>,
    pub ancestor_commit: Option<Commit>,

    // Change discovery results
    pub files_changed: Option<HashSet<PathBuf>>,
    pub external_dependencies_changed: Option<usize>,

    // FIXME: add profiling return data:
    //   - time taken to discover tests / build, time taken to run tests, time "added by testtrim" for reading coverage
    //     data, analyzing coverage data, and writing coverage data
    test_identifier_type: PhantomData<TI>,
}

pub fn run_tests<Commit, MyScm, TI, CI, TD, CTI, TP>(
    mode: &GetTestIdentifierMode,
    scm: &MyScm,
    source_mode: &SourceMode,
) -> Result<RunTestsOutput<Commit, TI, CTI>>
where
    Commit: ScmCommit,
    MyScm: Scm<Commit>,
    TI: TestIdentifier + Serialize + DeserializeOwned,
    CI: CoverageIdentifier + Serialize + DeserializeOwned,
    TD: TestDiscovery<CTI, TI>,
    CTI: ConcreteTestIdentifier<TI>,
    TP: TestPlatform<TI, CI, TD, CTI>,
{
    let save_coverage_data = match source_mode {
        SourceMode::Automatic => scm.is_working_dir_clean()?,
        SourceMode::CleanCommit => {
            if !scm.is_working_dir_clean()? {
                return Err(RunTestsErrors::CleanCommitWorkingDirectoryDirty.into());
            } else {
                true
            }
        }
        SourceMode::OverrideCleanCommit => true,
        SourceMode::WorkingTree => false,
    };

    let ancestor_search_mode = match source_mode {
        SourceMode::Automatic => {
            if scm.is_working_dir_clean()? {
                AncestorSearchMode::SkipHeadCommit
            } else {
                AncestorSearchMode::AllCommits
            }
        }
        SourceMode::CleanCommit | SourceMode::OverrideCleanCommit => {
            AncestorSearchMode::SkipHeadCommit
        }
        SourceMode::WorkingTree => AncestorSearchMode::AllCommits,
    };
    info!(
        "source_mode: {:?}, save_coverage_data: {}, ancestor_search_mode: {:?}",
        source_mode, save_coverage_data, ancestor_search_mode
    );

    let test_cases =
        get_target_test_cases::<Commit, MyScm, _, _, _, _, TP>(mode, scm, ancestor_search_mode)?;

    let mut coverage_data = TP::run_tests(&test_cases.target_test_cases)?;
    for tc in &test_cases.all_test_cases {
        coverage_data.add_existing_test(tc.test_identifier().clone());
    }

    info!("successfully ran tests");

    if save_coverage_data {
        let commit_sha = scm.get_commit_identifier(&scm.get_head_commit()?);

        let ancestor_commit_sha = test_cases
            .ancestor_commit
            .as_ref()
            .map(|c| scm.get_commit_identifier(c));

        DieselCoverageDatabase::new_sqlite_from_default_path().save_coverage_data(
            &coverage_data,
            &commit_sha,
            ancestor_commit_sha.as_deref(),
        )?;
    }

    Ok(RunTestsOutput {
        all_test_cases: test_cases.all_test_cases,
        target_test_cases: test_cases.target_test_cases,
        ancestor_commit: test_cases.ancestor_commit,

        files_changed: test_cases.files_changed,
        external_dependencies_changed: test_cases.external_dependencies_changed,

        test_identifier_type: PhantomData,
    })
}
