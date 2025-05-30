// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use serde_map_to_array::HashMapToArray;

use crate::{
    coverage::commit_coverage_data::{
        CoverageIdentifier, FileCoverage, FileReference, FunctionCoverage,
    },
    platform::TestIdentifier,
};

/// `FullCoverageData` represents coverage data that encompasses the entire project's test suite.  It will typically be
/// coalesced and merged from multiple test runs over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
// Note: Serialize & Deserialize are present because of the mishmash between internal data structures and web API
pub struct FullCoverageData<TI: TestIdentifier, CI: CoverageIdentifier> {
    all_tests: HashSet<TI>,
    file_to_test_map: HashMap<PathBuf, HashSet<TI>>,
    // no platforms support this yet, so let's just omit it from API usage
    function_to_test_map: HashMap<String, HashSet<TI>>,
    // since CI will likely serialize as a struct, serialize this field as an array instead of a map
    #[serde(with = "HashMapToArray::<CI, HashSet<TI>>")]
    coverage_identifier_to_test_map: HashMap<CI, HashSet<TI>>,
    file_referenced_by_files_map: HashMap<PathBuf, HashSet<PathBuf>>,
}

impl<TI: TestIdentifier, CI: CoverageIdentifier> Default for FullCoverageData<TI, CI> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TI: TestIdentifier, CI: CoverageIdentifier> FullCoverageData<TI, CI> {
    #[must_use]
    pub fn new() -> Self {
        FullCoverageData {
            all_tests: HashSet::new(),
            file_to_test_map: HashMap::new(),
            function_to_test_map: HashMap::new(),
            coverage_identifier_to_test_map: HashMap::new(),
            file_referenced_by_files_map: HashMap::new(),
        }
    }

    #[must_use]
    pub fn all_tests(&self) -> &HashSet<TI> {
        &self.all_tests
    }

    #[must_use]
    pub fn file_to_test_map(&self) -> &HashMap<PathBuf, HashSet<TI>> {
        &self.file_to_test_map
    }

    #[must_use]
    pub fn function_to_test_map(&self) -> &HashMap<String, HashSet<TI>> {
        &self.function_to_test_map
    }

    #[must_use]
    pub fn coverage_identifier_to_test_map(&self) -> &HashMap<CI, HashSet<TI>> {
        &self.coverage_identifier_to_test_map
    }

    #[must_use]
    pub fn file_referenced_by_files_map(&self) -> &HashMap<PathBuf, HashSet<PathBuf>> {
        &self.file_referenced_by_files_map
    }

    pub fn add_existing_test(&mut self, test_identifier: TI) {
        self.all_tests.insert(test_identifier);
    }

    pub fn add_file_to_test(&mut self, coverage: FileCoverage<TI>) {
        // "FileCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents the
        // two strings from being passed in the wrong order by making them named.
        self.file_to_test_map
            .entry(coverage.file_name)
            .or_default()
            .insert(coverage.test_identifier);
    }

    pub fn add_function_to_test(&mut self, coverage: FunctionCoverage<TI>) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.function_to_test_map
            .entry(coverage.function_name)
            .or_default()
            .insert(coverage.test_identifier);
    }

    pub fn add_heuristic_coverage_to_test(&mut self, test_identifier: TI, coverage: CI) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.coverage_identifier_to_test_map
            .entry(coverage)
            .or_default()
            .insert(test_identifier);
    }

    pub fn add_file_reference(&mut self, file_reference: FileReference) {
        self.file_referenced_by_files_map
            .entry(file_reference.target_file)
            .or_default()
            .insert(file_reference.referencing_file);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use crate::platform::rust::{
        RustCoverageIdentifier, RustPackageDependency, RustTestIdentifier,
    };

    use super::*;
    use anyhow::Result;

    static TEST1: LazyLock<RustTestIdentifier> = LazyLock::new(|| RustTestIdentifier {
        test_src_path: PathBuf::from("src/lib.rs"),
        test_name: "test1".to_string(),
    });
    static TEST2: LazyLock<RustTestIdentifier> = LazyLock::new(|| RustTestIdentifier {
        test_src_path: PathBuf::from("src/lib.rs"),
        test_name: "test2".to_string(),
    });
    static THISERROR: LazyLock<RustCoverageIdentifier> = LazyLock::new(|| {
        RustCoverageIdentifier::PackageDependency(RustPackageDependency {
            package_name: String::from("THISERROR"),
            version: String::from("0.1"),
        })
    });
    static REGEX: LazyLock<RustCoverageIdentifier> = LazyLock::new(|| {
        RustCoverageIdentifier::PackageDependency(RustPackageDependency {
            package_name: String::from("REGEX"),
            version: String::from("0.1"),
        })
    });

    #[test]
    fn test_new_coverage_data() {
        let coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            FullCoverageData::new();
        assert!(coverage_data.all_tests().is_empty());
        assert!(coverage_data.file_to_test_map().is_empty());
        assert!(coverage_data.function_to_test_map().is_empty());
    }

    #[test]
    fn test_add_executed_test() {
        let mut coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            FullCoverageData::new();
        coverage_data.add_existing_test(TEST1.clone());
        coverage_data.add_existing_test(TEST2.clone());
        assert_eq!(coverage_data.all_tests().len(), 2);
        assert!(coverage_data.all_tests().contains(&TEST1));
        assert!(coverage_data.all_tests().contains(&TEST2));
    }

    #[test]
    fn test_add_file_to_test() {
        let mut coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            FullCoverageData::new();
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: TEST1.clone(),
        });
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: TEST2.clone(),
        });
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file2.rs"),
            test_identifier: TEST1.clone(),
        });

        assert_eq!(coverage_data.file_to_test_map().len(), 2);
        assert_eq!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file2.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .contains(&TEST1)
        );
        assert!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .contains(&TEST2)
        );
        assert!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file2.rs"))
                .unwrap()
                .contains(&TEST1)
        );
    }

    #[test]
    fn test_add_function_to_test() {
        let mut coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            FullCoverageData::new();
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: TEST1.clone(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: TEST2.clone(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_identifier: TEST1.clone(),
        });

        assert_eq!(coverage_data.function_to_test_map().len(), 2);
        assert_eq!(
            coverage_data
                .function_to_test_map()
                .get("func1")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .function_to_test_map()
                .get("func2")
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .function_to_test_map()
                .get("func1")
                .unwrap()
                .contains(&TEST1)
        );
        assert!(
            coverage_data
                .function_to_test_map()
                .get("func1")
                .unwrap()
                .contains(&TEST2)
        );
        assert!(
            coverage_data
                .function_to_test_map()
                .get("func2")
                .unwrap()
                .contains(&TEST1)
        );
    }

    #[test]
    fn add_heuristic_coverage_to_test() {
        let mut coverage_data = FullCoverageData::new();
        coverage_data.add_heuristic_coverage_to_test(TEST1.clone(), REGEX.clone());
        coverage_data.add_heuristic_coverage_to_test(TEST2.clone(), REGEX.clone());
        coverage_data.add_heuristic_coverage_to_test(TEST1.clone(), THISERROR.clone());

        assert_eq!(coverage_data.coverage_identifier_to_test_map().len(), 2);
        assert_eq!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&REGEX)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&THISERROR)
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&REGEX)
                .unwrap()
                .contains(&TEST1)
        );
        assert!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&REGEX)
                .unwrap()
                .contains(&TEST2)
        );
        assert!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&THISERROR)
                .unwrap()
                .contains(&TEST1)
        );
    }

    #[test]
    fn add_file_reference() {
        let mut coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            FullCoverageData::new();
        coverage_data.add_file_reference(FileReference {
            referencing_file: PathBuf::from("src/two.rs"),
            target_file: PathBuf::from("extra-data/abc-123.txt"),
        });
        coverage_data.add_file_reference(FileReference {
            referencing_file: PathBuf::from("src/two.rs"),
            target_file: PathBuf::from("extra-data/abc-321.txt"),
        });
        coverage_data.add_file_reference(FileReference {
            referencing_file: PathBuf::from("src/one.rs"),
            target_file: PathBuf::from("extra-data/abc-123.txt"),
        });

        assert_eq!(coverage_data.file_referenced_by_files_map().len(), 2);
        assert_eq!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-123.txt"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-321.txt"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-123.txt"))
                .unwrap()
                .contains(&PathBuf::from("src/two.rs"))
        );
        assert!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-123.txt"))
                .unwrap()
                .contains(&PathBuf::from("src/one.rs"))
        );
        assert!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-321.txt"))
                .unwrap()
                .contains(&PathBuf::from("src/two.rs"))
        );
    }

    #[test]
    fn serialize() -> Result<()> {
        let mut coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            FullCoverageData::new();

        coverage_data.add_existing_test(TEST1.clone());
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: TEST1.clone(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: TEST1.clone(),
        });
        coverage_data.add_heuristic_coverage_to_test(TEST1.clone(), REGEX.clone());
        coverage_data.add_file_reference(FileReference {
            referencing_file: PathBuf::from("src/one.rs"),
            target_file: PathBuf::from("extra-data/abc-123.txt"),
        });

        let serialized_data = serde_json::to_value(coverage_data)?;
        let coverage_data: FullCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            serde_json::from_value(serialized_data)?;

        assert_eq!(coverage_data.all_tests().len(), 1);
        assert!(coverage_data.all_tests().contains(&TEST1));
        assert_eq!(coverage_data.file_to_test_map().len(), 1);
        assert_eq!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .file_to_test_map()
                .get(&PathBuf::from("file1.rs"))
                .unwrap()
                .contains(&TEST1)
        );
        assert_eq!(coverage_data.coverage_identifier_to_test_map().len(), 1);
        assert_eq!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&REGEX)
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&REGEX)
                .unwrap()
                .contains(&TEST1)
        );
        assert_eq!(coverage_data.file_referenced_by_files_map().len(), 1);
        assert_eq!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-123.txt"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .file_referenced_by_files_map()
                .get(&PathBuf::from("extra-data/abc-123.txt"))
                .unwrap()
                .contains(&PathBuf::from("src/one.rs"))
        );

        Ok(())
    }
}
