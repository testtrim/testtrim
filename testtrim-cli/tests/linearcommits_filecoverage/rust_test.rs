// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::sync::Arc;
use testtrim::platform::rust::RustTestPlatform;
use testtrim::timing_tracer::{PerformanceStorage, PerformanceStoringLayer};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::assert_performance_tracing;
use crate::linearcommits_filecoverage::{CommitTestData, execute_test, setup_test};

#[tokio::test]
async fn add_new_test() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "base",
            all_test_cases: vec!["basic_ops::tests::test_add", "basic_ops::tests::test_sub"],
            relevant_test_cases: vec!["basic_ops::tests::test_add", "basic_ops::tests::test_sub"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "sequences::tests::test_fibonacci",
            ],
            relevant_test_cases: vec!["sequences::tests::test_fibonacci"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn modify_single_file() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-2",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-3",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-4",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-5",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn remove_test() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
                "sequences::tests::test_fibonacci_memo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-7",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn change_external_dependency() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-8",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-9",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec!["basic_ops::tests::test_add_decimal"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn change_read_file() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-10",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-11",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
            ],
            relevant_test_cases: vec!["sequences::tests::test_fibonacci_sequence"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn change_embed_file() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-12",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-13",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            relevant_test_cases: vec![
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn change_constants() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-14",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-15",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            relevant_test_cases: vec![
                // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                // "constant_using_tests::tests::test_using_lazy_static", // FIXME: broken -- should be considered relevant but isn't
            ],
            expected_failing_test_cases: vec![
                // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                // "constant_using_tests::tests::test_using_lazy_static", // FIXME: broken -- should be considered relevant but isn't
            ],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn network_test_rerun() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<RustTestPlatform>("rust-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-16",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            relevant_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-17",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
                "network::tests::test_tcp_connection_to_google",
            ],
            relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-18",
            all_test_cases: vec![
                "basic_ops::tests::test_add",
                "basic_ops::tests::test_sub",
                "basic_ops::tests::test_mul",
                "basic_ops::tests::test_div",
                "basic_ops::tests::test_power",
                "basic_ops::tests::test_add_decimal",
                "sequences::tests::test_fibonacci",
                "sequences::tests::test_fibonacci_sequence",
                "sequences::tests::test_factorial",
                "sequences::tests::test_factorial_include",
                "constant_using_tests::tests::test_using_const",
                "constant_using_tests::tests::test_using_const_fn",
                "constant_using_tests::tests::test_using_inline",
                "constant_using_tests::tests::test_using_lazy_static",
                "network::tests::test_tcp_connection_to_google",
            ],
            relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<RustTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}
