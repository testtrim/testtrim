// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::sync::Arc;
use testtrim::platform::dotnet::DotnetTestPlatform;
use testtrim::timing_tracer::{PerformanceStorage, PerformanceStoringLayer};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::assert_performance_tracing;
use crate::linearcommits_filecoverage::{CommitTestData, execute_test, setup_test};

#[tokio::test]
async fn add_new_test() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<DotnetTestPlatform>("dotnet-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "base",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
            ],
            relevant_test_cases: vec!["MathFunctions.Tests.SequenceTests.TestFibonacci"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<DotnetTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<DotnetTestPlatform>("dotnet-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-2",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-3",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<DotnetTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

#[tokio::test]
async fn modify_test_file() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<DotnetTestPlatform>("dotnet-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-5",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<DotnetTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<DotnetTestPlatform>("dotnet-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
                "MathFunctions.Tests.SequenceTests.TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-7",
            all_test_cases: vec![
                "MathFunctions.Tests.BasicOpsTests.TestAdd",
                "MathFunctions.Tests.BasicOpsTests.TestSub",
                "MathFunctions.Tests.BasicOpsTests.TestMul",
                "MathFunctions.Tests.BasicOpsTests.TestDiv",
                "MathFunctions.Tests.BasicOpsTests.TestPower",
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            relevant_test_cases: vec![
                "MathFunctions.Tests.SequenceTests.TestFibonacci",
                "MathFunctions.Tests.SequenceTests.TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<DotnetTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}

// CommitTestData {
//     test_commit: "check-8",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//     ],
//     relevant_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//     ],
//     expected_failing_test_cases: vec![],
// },
// TODO: external dependency tracking
// FIXME: still need preemptive read of packages.lock.json changes at the beginning of a test, and lookup of
// external dependencies, I think... maybe also the coverage DB storage?  not sure where I'm left at.
// CommitTestData {
//     test_commit: "check-9",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//     ],
//     relevant_test_cases: vec!["MathFunctions.Tests.BasicOpsTests.TestDecimalSqrt"],
//     expected_failing_test_cases: vec![],
// },

// CommitTestData {
//     test_commit: "check-10",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//     ],
//     relevant_test_cases: vec![
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//     ],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-11",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//     ],
//     relevant_test_cases: vec!["MathFunctions.Tests.SequenceTests.TestFibonacci_sequence"],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-12",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//     ],
//     relevant_test_cases: vec![
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//     ],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-13",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//     ],
//     relevant_test_cases: vec![
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//     ],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-14",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//         "constant_using_tests::tests::test_using_const",
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//     ],
//     relevant_test_cases: vec![
//         "constant_using_tests::tests::test_using_const",
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//     ],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-15",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//         "constant_using_tests::tests::test_using_const",
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//     ],
//     relevant_test_cases: vec![
//         // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//     ],
//     expected_failing_test_cases: vec![
//         // "constant_using_tests::tests::test_using_const", // FIXME: broken -- should be considered relevant but isn't
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//     ],
// },
// CommitTestData {
//     test_commit: "check-16",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//         "constant_using_tests::tests::test_using_const",
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//     ],
//     relevant_test_cases: vec![],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-17",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "MathFunctions.Tests.BasicOpsTests.TestAddDecimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "MathFunctions.Tests.SequenceTests.TestFactorial_include",
//         "constant_using_tests::tests::test_using_const",
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//         "network::tests::test_tcp_connection_to_google",
//     ],
//     relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
//     expected_failing_test_cases: vec![],
// },
// CommitTestData {
//     test_commit: "check-18",
//     all_test_cases: vec![
//         "MathFunctions.Tests.BasicOpsTests.TestAdd",
//         "MathFunctions.Tests.BasicOpsTests.TestSub",
//         "MathFunctions.Tests.BasicOpsTests.TestMul",
//         "MathFunctions.Tests.BasicOpsTests.TestDiv",
//         "MathFunctions.Tests.BasicOpsTests.TestPower",
//         "basic_ops::tests::test_add_decimal",
//         "MathFunctions.Tests.SequenceTests.TestFibonacci",
//         "sequences::tests::test_fibonacci_sequence",
//         "MathFunctions.Tests.SequenceTests.TestFactorial",
//         "sequences::tests::test_factorial_include",
//         "constant_using_tests::tests::test_using_const",
//         "constant_using_tests::tests::test_using_const_fn",
//         "constant_using_tests::tests::test_using_inline",
//         "constant_using_tests::tests::test_using_lazy_static",
//         "network::tests::test_tcp_connection_to_google",
//     ],
//     relevant_test_cases: vec!["network::tests::test_tcp_connection_to_google"],
//     expected_failing_test_cases: vec![],
// },
