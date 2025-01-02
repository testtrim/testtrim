// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use crate::{
    coverage::{
        commit_coverage_data::{
            CommitCoverageData, FileCoverage, FileReference, FunctionCoverage, HeuristicCoverage,
        },
        Tag,
    },
    platform::rust::{
        RustCoverageIdentifier, RustPackageDependency, RustTestIdentifier, RustTestPlatform,
    },
};
use lazy_static::lazy_static;

use super::CoverageDatabase;

lazy_static! {
    static ref test1: RustTestIdentifier = {
        RustTestIdentifier {
            test_src_path: PathBuf::from("src/lib.rs"),
            test_name: "test1".to_string(),
        }
    };
    static ref test2: RustTestIdentifier = {
        RustTestIdentifier {
            test_src_path: PathBuf::from("src/lib.rs"),
            test_name: "test2".to_string(),
        }
    };
    static ref test3: RustTestIdentifier = {
        RustTestIdentifier {
            test_src_path: PathBuf::from("sub_module/src/lib.rs"),
            test_name: "test1".to_string(),
        }
    };
    static ref thiserror: RustCoverageIdentifier =
        RustCoverageIdentifier::PackageDependency(RustPackageDependency {
            package_name: String::from("thiserror"),
            version: String::from("0.1"),
        });
    static ref regex: RustCoverageIdentifier =
        RustCoverageIdentifier::PackageDependency(RustPackageDependency {
            package_name: String::from("regex"),
            version: String::from("0.1"),
        });
}

pub async fn has_any_coverage_data_false(db: impl CoverageDatabase) {
    let result = db
        .has_any_coverage_data::<RustTestPlatform>("testtrim-tests")
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let has_coverage_data = result.unwrap();
    assert!(!has_coverage_data);
}

pub async fn save_empty(db: impl CoverageDatabase) {
    let data1 = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &data1, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
}

pub async fn has_any_coverage_data_true(db: impl CoverageDatabase) {
    let data1 = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &data1, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = db
        .has_any_coverage_data::<RustTestPlatform>("testtrim-tests")
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let has_coverage_data = result.unwrap();
    assert!(has_coverage_data);
}

pub async fn load_empty(db: impl CoverageDatabase) {
    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c1", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_none());
}

pub async fn save_and_load_no_ancestor(db: impl CoverageDatabase) {
    let mut saved_data = CommitCoverageData::new();
    // note -- no ancestor, so the only case that makes sense is for all existing tests to be executed tests
    saved_data.add_executed_test(test1.clone());
    saved_data.add_executed_test(test2.clone());
    saved_data.add_executed_test(test3.clone());
    saved_data.add_existing_test(test1.clone());
    saved_data.add_existing_test(test2.clone());
    saved_data.add_existing_test(test3.clone());
    saved_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test1.clone(),
    });
    saved_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test2.clone(),
    });
    saved_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file2.rs"),
        test_identifier: test1.clone(),
    });
    saved_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test1.clone(),
    });
    saved_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test2.clone(),
    });
    saved_data.add_function_to_test(FunctionCoverage {
        function_name: "func2".to_string(),
        test_identifier: test1.clone(),
    });
    saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
        test_identifier: test1.clone(),
        coverage_identifier: regex.clone(),
    });
    saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
        test_identifier: test2.clone(),
        coverage_identifier: regex.clone(),
    });
    saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
        test_identifier: test1.clone(),
        coverage_identifier: thiserror.clone(),
    });
    saved_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file1.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });
    saved_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file1.rs"),
        target_file: PathBuf::from("extra_data/things.txt"),
    });
    saved_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file2.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &saved_data, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c1", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_some());
    let loaded_data = result.unwrap();
    assert_eq!(loaded_data.all_tests().len(), 3);
    assert!(loaded_data.all_tests().contains(&test1));
    assert!(loaded_data.all_tests().contains(&test2));
    assert!(loaded_data.all_tests().contains(&test3));
    assert_eq!(loaded_data.file_to_test_map().len(), 2);
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file2.rs"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file1.rs"))
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file2.rs"))
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file1.rs"))
        .unwrap()
        .contains(&test2));
    assert_eq!(loaded_data.function_to_test_map().len(), 2);
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("func2")
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .function_to_test_map()
        .get("func1")
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .function_to_test_map()
        .get("func2")
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .function_to_test_map()
        .get("func1")
        .unwrap()
        .contains(&test2));
    assert_eq!(loaded_data.coverage_identifier_to_test_map().len(), 2);
    assert_eq!(
        loaded_data
            .coverage_identifier_to_test_map()
            .get(&regex)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        loaded_data
            .coverage_identifier_to_test_map()
            .get(&thiserror)
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .coverage_identifier_to_test_map()
        .get(&thiserror)
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .coverage_identifier_to_test_map()
        .get(&regex)
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .coverage_identifier_to_test_map()
        .get(&regex)
        .unwrap()
        .contains(&test2));
    assert_eq!(loaded_data.file_referenced_by_files_map().len(), 2);
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/stuff.txt"))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/things.txt"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file1.rs")));
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file2.rs")));
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/things.txt"))
        .unwrap()
        .contains(&PathBuf::from("file1.rs")));
}

/// Test an additive-only child coverage data set -- no overwrite/replacement of the ancestor
pub async fn save_and_load_new_case_in_child(db: impl CoverageDatabase) {
    let mut ancestor_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    ancestor_data.add_executed_test(test1.clone());
    ancestor_data.add_existing_test(test1.clone());
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file2.rs"),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func2".to_string(),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file1.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &ancestor_data, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let mut child_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    child_data.add_executed_test(test2.clone());
    child_data.add_existing_test(test1.clone());
    child_data.add_existing_test(test2.clone());
    child_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test2.clone(),
    });
    child_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test2.clone(),
    });
    child_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file2.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            &child_data,
            "c2",
            Some("c1"),
            &[],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c2", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_some());
    let loaded_data = result.unwrap();
    assert_eq!(loaded_data.all_tests().len(), 2);
    assert!(loaded_data.all_tests().contains(&test1));
    assert!(loaded_data.all_tests().contains(&test2));
    assert_eq!(loaded_data.file_to_test_map().len(), 2);
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file2.rs"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file1.rs"))
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file2.rs"))
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file1.rs"))
        .unwrap()
        .contains(&test2));
    assert_eq!(loaded_data.function_to_test_map().len(), 2);
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("func2")
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .function_to_test_map()
        .get("func1")
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .function_to_test_map()
        .get("func2")
        .unwrap()
        .contains(&test1));
    assert!(loaded_data
        .function_to_test_map()
        .get("func1")
        .unwrap()
        .contains(&test2));
    assert_eq!(loaded_data.file_referenced_by_files_map().len(), 1);
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/stuff.txt"))
            .unwrap()
            .len(),
        2
    );
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file1.rs")));
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file2.rs")));
}

/// Test a replacement-only child coverage data set -- the same test was run with new coverage data in the child
pub async fn save_and_load_replacement_case_in_child(db: impl CoverageDatabase) {
    let mut ancestor_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    ancestor_data.add_executed_test(test1.clone());
    ancestor_data.add_existing_test(test1.clone());
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file2.rs"),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func2".to_string(),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file1.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file1.rs"),
        target_file: PathBuf::from("extra_data/things.txt"),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file2.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &ancestor_data, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let mut child_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    child_data.add_executed_test(test1.clone());
    child_data.add_existing_test(test1.clone());
    child_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file3.rs"),
        test_identifier: test1.clone(),
    });
    child_data.add_function_to_test(FunctionCoverage {
        function_name: "func3".to_string(),
        test_identifier: test1.clone(),
    });
    child_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file2.rs"),
        target_file: PathBuf::from("extra_data/more-stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            &child_data,
            "c2",
            Some("c1"),
            &[],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c2", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_some());
    let loaded_data = result.unwrap();
    assert_eq!(loaded_data.all_tests().len(), 1);
    assert!(loaded_data.all_tests().contains(&test1));
    assert_eq!(loaded_data.file_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file3.rs"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file3.rs"))
        .unwrap()
        .contains(&test1));
    assert_eq!(loaded_data.function_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("func3")
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .function_to_test_map()
        .get("func3")
        .unwrap()
        .contains(&test1));
    assert_eq!(loaded_data.file_referenced_by_files_map().len(), 3);
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/stuff.txt"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/things.txt"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/more-stuff.txt"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file1.rs")));
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/things.txt"))
        .unwrap()
        .contains(&PathBuf::from("file1.rs")));
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/more-stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file2.rs")));
}

/// Test a child coverage set which indicates a test was removed and no longer present
pub async fn save_and_load_removed_case_in_child(db: impl CoverageDatabase) {
    let mut ancestor_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    ancestor_data.add_executed_test(test1.clone());
    ancestor_data.add_executed_test(test2.clone());
    ancestor_data.add_existing_test(test1.clone());
    ancestor_data.add_existing_test(test2.clone());
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file1.rs"),
        test_identifier: test2.clone(),
    });
    ancestor_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("file2.rs"),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func1".to_string(),
        test_identifier: test2.clone(),
    });
    ancestor_data.add_function_to_test(FunctionCoverage {
        function_name: "func2".to_string(),
        test_identifier: test1.clone(),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file2.rs"),
        target_file: PathBuf::from("extra_data/more-stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &ancestor_data, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    // Also an odd case -- we'll give child_data no executed tests just to make sure that no "inner joins" turn
    // into no data.  We should get all the test2 data from the ancestor because we're indicating that it still
    // exists though...
    let mut child_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    child_data.add_existing_test(test2.clone());

    let result = db
        .save_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            &child_data,
            "c2",
            Some("c1"),
            &[],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c2", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_some());
    let loaded_data = result.unwrap();
    assert_eq!(loaded_data.all_tests().len(), 1);
    assert!(loaded_data.all_tests().contains(&test2));
    assert_eq!(loaded_data.file_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("file1.rs"))
        .unwrap()
        .contains(&test2));
    assert_eq!(loaded_data.function_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .function_to_test_map()
        .get("func1")
        .unwrap()
        .contains(&test2));
}

/// Test that we can remove file references from an ancestor
pub async fn remove_file_references_in_child(db: impl CoverageDatabase) {
    let mut ancestor_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    ancestor_data.add_executed_test(test1.clone());
    ancestor_data.add_existing_test(test1.clone());
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("src/two.rs"),
        target_file: PathBuf::from("extra-data/abc-123.txt"),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("src/two.rs"),
        target_file: PathBuf::from("extra-data/abc-321.txt"),
    });
    ancestor_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("src/one.rs"),
        target_file: PathBuf::from("extra-data/abc-123.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>("testtrim-tests", &ancestor_data, "c1", None, &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    // Slightly weird here; the point of this test is to verify that the positive absence of data
    // (mark_file_makes_no_reference) correctly overwrites ancestor data with no records for that file.
    let mut child_data = CommitCoverageData::<RustTestIdentifier, RustCoverageIdentifier>::new();
    child_data.add_executed_test(test1.clone());
    child_data.add_existing_test(test1.clone());
    child_data.mark_file_makes_no_references(PathBuf::from("src/two.rs"));

    let result = db
        .save_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            &child_data,
            "c2",
            Some("c1"),
            &[],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c2", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_some());
    let loaded_data = result.unwrap();
    assert_eq!(
        loaded_data.file_referenced_by_files_map().len(),
        1,
        "expected files referenced to have length 1, but content was: {:?}",
        loaded_data.file_referenced_by_files_map()
    );
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra-data/abc-123.txt"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra-data/abc-123.txt"))
        .unwrap()
        .contains(&PathBuf::from("src/one.rs")));
}

/// Test that save and load use independent data based upon tags
pub async fn independent_tags(db: impl CoverageDatabase) {
    let mut saved_data = CommitCoverageData::new();
    let windows = RustCoverageIdentifier::PackageDependency(RustPackageDependency {
        package_name: String::from("windows-sys"),
        version: String::from("0.1"),
    });
    saved_data.add_executed_test(test1.clone());
    saved_data.add_existing_test(test1.clone());
    saved_data.add_file_to_test(FileCoverage {
        file_name: PathBuf::from("windows.rs"),
        test_identifier: test1.clone(),
    });
    saved_data.add_function_to_test(FunctionCoverage {
        function_name: "windows".to_string(),
        test_identifier: test1.clone(),
    });
    saved_data.add_heuristic_coverage_to_test(HeuristicCoverage {
        test_identifier: test1.clone(),
        coverage_identifier: windows.clone(),
    });
    saved_data.add_file_reference(FileReference {
        referencing_file: PathBuf::from("file1.rs"),
        target_file: PathBuf::from("extra_data/stuff.txt"),
    });

    let result = db
        .save_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            &saved_data,
            "c1",
            None,
            &[
                Tag {
                    key: String::from("platform"),
                    value: String::from("windows"),
                },
                Tag {
                    key: String::from("database"),
                    value: String::from("postgresql"),
                },
            ],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");

    let result = db
        .read_coverage_data::<RustTestPlatform>("testtrim-tests", "c1", &[])
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_none()); // should not load as we provided mismatching tags

    let result = db
        .read_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            "c1",
            &[
                Tag {
                    key: String::from("platform"),
                    value: String::from("linux"),
                },
                Tag {
                    key: String::from("database"),
                    value: String::from("postgresql"),
                },
            ],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_none()); // should not load as we provided mismatching tags

    // the order of the tags is reversed, but expected to be loaded successfully -- the tag order is irrelevant (should
    // probably be a HashSet for clarity?)
    let result = db
        .read_coverage_data::<RustTestPlatform>(
            "testtrim-tests",
            "c1",
            &[
                Tag {
                    key: String::from("database"),
                    value: String::from("postgresql"),
                },
                Tag {
                    key: String::from("platform"),
                    value: String::from("windows"),
                },
            ],
        )
        .await;
    assert!(result.is_ok(), "result = {result:?}");
    let result = result.unwrap();
    assert!(result.is_some());

    let loaded_data = result.unwrap();
    assert_eq!(loaded_data.all_tests().len(), 1);
    assert!(loaded_data.all_tests().contains(&test1));
    assert_eq!(loaded_data.file_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .file_to_test_map()
            .get(&PathBuf::from("windows.rs"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_to_test_map()
        .get(&PathBuf::from("windows.rs"))
        .unwrap()
        .contains(&test1));
    assert_eq!(loaded_data.function_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .function_to_test_map()
            .get("windows")
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .function_to_test_map()
        .get("windows")
        .unwrap()
        .contains(&test1));
    assert_eq!(loaded_data.coverage_identifier_to_test_map().len(), 1);
    assert_eq!(
        loaded_data
            .coverage_identifier_to_test_map()
            .get(&windows)
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .coverage_identifier_to_test_map()
        .get(&windows)
        .unwrap()
        .contains(&test1));
    assert_eq!(loaded_data.file_referenced_by_files_map().len(), 1);
    assert_eq!(
        loaded_data
            .file_referenced_by_files_map()
            .get(&PathBuf::from("extra_data/stuff.txt"))
            .unwrap()
            .len(),
        1
    );
    assert!(loaded_data
        .file_referenced_by_files_map()
        .get(&PathBuf::from("extra_data/stuff.txt"))
        .unwrap()
        .contains(&PathBuf::from("file1.rs")));
}
