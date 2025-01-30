// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::sync::Arc;
use testtrim::platform::golang::GolangTestPlatform;
use testtrim::timing_tracer::{PerformanceStorage, PerformanceStoringLayer};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::assert_performance_tracing;
use crate::linearcommits_filecoverage::{CommitTestData, execute_test, setup_test};

#[tokio::test]
async fn add_new_test() -> Result<()> {
    let (_tmp_dir, _tmp_dir_cwd, _mutex, coverage_db) =
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "base",
            all_test_cases: vec!["TestAdd", "TestSub"],
            relevant_test_cases: vec!["TestAdd", "TestSub"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-1",
            all_test_cases: vec!["TestAdd", "TestSub", "TestFibonacci"],
            relevant_test_cases: vec!["TestFibonacci"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-2",
            all_test_cases: vec!["TestAdd", "TestSub", "TestMul", "TestDiv", "TestFibonacci"],
            relevant_test_cases: vec!["TestAdd", "TestSub", "TestMul", "TestDiv", "TestFibonacci"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-3",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-4",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial", "TestFibonacciMemo"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-5",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial", "TestFibonacciMemo"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-6",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
                "TestFibonacciMemo",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-7",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacci", "TestFactorial"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-8",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-9",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestAddDecimal"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-10",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-11",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
            ],
            relevant_test_cases: vec!["TestFibonacciSequence"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-12",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-13",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            relevant_test_cases: vec![
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
            ],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-14",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-15",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            relevant_test_cases: vec![
                // FIXME: none of the const modifications are detected properly; this makes some sense as consts would
                // be initialized on every test causing their coverage to be present always, and we eliminate that with
                // the test baselining to avoid false positives.  This will be documented as a known limitation for now.
                //
                // "TestUsingConst", "TestUsingFunctionInit", "TestUsingModuleInit",
            ],
            expected_failing_test_cases: vec![
                // FIXME: see above
                //
                // "TestUsingConst", "TestUsingFunctionInit", "TestUsingModuleInit",
            ],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
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
        setup_test::<GolangTestPlatform>("go-coverage-specimen").await?;

    let test_commits = vec![
        CommitTestData {
            test_commit: "check-16",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            relevant_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
            ],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-17",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
                "TestTCPConnectionToGoogle",
            ],
            relevant_test_cases: vec!["TestTCPConnectionToGoogle"],
            expected_failing_test_cases: vec![],
        },
        CommitTestData {
            test_commit: "check-18",
            all_test_cases: vec![
                "TestAdd",
                "TestSub",
                "TestMul",
                "TestDiv",
                "TestPower",
                "TestAddDecimal",
                "TestFibonacci",
                "TestFibonacciSequence",
                "TestFactorial",
                "TestFactorialInclude",
                "TestUsingConst",
                "TestUsingFunctionInit",
                "TestUsingModuleInit",
                "TestTCPConnectionToGoogle",
            ],
            relevant_test_cases: vec!["TestTCPConnectionToGoogle"],
            expected_failing_test_cases: vec![],
        },
    ];

    let perf_storage = Arc::new(PerformanceStorage::new());
    for commit_test_data in test_commits {
        execute_test::<GolangTestPlatform>(&commit_test_data, &coverage_db)
            .with_subscriber(
                Registry::default().with(PerformanceStoringLayer::new(perf_storage.clone())),
            )
            .await?;
    }
    assert_performance_tracing(perf_storage.interpret_run_test_timing());

    Ok(())
}
