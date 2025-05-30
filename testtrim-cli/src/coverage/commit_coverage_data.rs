// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    path::PathBuf,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_map_to_array::HashMapToArray;

use crate::{network::NetworkDependency, platform::TestIdentifier};

/// `CommitCoverageData` represents the coverage data that could be collected from test execution on a single commit.
///
/// Importantly this may represent data from only a partial execution of tests that were appropriate to that commit,
/// rather than a complete test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
// Note: Serialize & Deserialize are present because of the mishmash between internal data structures and web API. Since
// TI will likely serialize as a struct, everything HashMap<TI> will need to be serialized as an array rather than a map
// for JSON compatbility.
pub struct CommitCoverageData<TI: TestIdentifier, CI: CoverageIdentifier> {
    all_existing_test_set: HashSet<TI>,
    executed_test_set: HashSet<TI>,
    #[serde(with = "HashMapToArray::<TI, HashSet<PathBuf>>")]
    executed_test_to_files_map: HashMap<TI, HashSet<PathBuf>>,
    #[serde(with = "HashMapToArray::<TI, HashSet<String>>")]
    executed_test_to_functions_map: HashMap<TI, HashSet<String>>,
    #[serde(with = "HashMapToArray::<TI, HashSet<CI>>")]
    executed_test_to_coverage_identifier_map: HashMap<TI, HashSet<CI>>,
    file_references_files_map: HashMap<PathBuf, HashSet<PathBuf>>,
}

pub struct FileCoverage<TI: TestIdentifier> {
    pub file_name: PathBuf,
    pub test_identifier: TI,
}

pub struct FunctionCoverage<TI: TestIdentifier> {
    pub function_name: String,
    pub test_identifier: TI,
}

pub struct HeuristicCoverage<TI: TestIdentifier, CI: CoverageIdentifier> {
    pub test_identifier: TI,
    pub coverage_identifier: CI,
}

pub struct FileReference {
    pub referencing_file: PathBuf,
    pub target_file: PathBuf,
}

pub trait CoverageIdentifier:
    Eq + Hash + Clone + Debug + Serialize + DeserializeOwned + TryInto<NetworkDependency>
{
}

impl<TI: TestIdentifier, CI: CoverageIdentifier> Default for CommitCoverageData<TI, CI> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TI: TestIdentifier, CI: CoverageIdentifier> CommitCoverageData<TI, CI> {
    #[must_use]
    pub fn new() -> Self {
        CommitCoverageData {
            all_existing_test_set: HashSet::new(),
            executed_test_set: HashSet::new(),
            executed_test_to_files_map: HashMap::new(),
            executed_test_to_functions_map: HashMap::new(),
            executed_test_to_coverage_identifier_map: HashMap::new(),
            file_references_files_map: HashMap::new(),
        }
    }

    #[must_use]
    pub fn existing_test_set(&self) -> &HashSet<TI> {
        &self.all_existing_test_set
    }

    #[must_use]
    pub fn executed_test_set(&self) -> &HashSet<TI> {
        &self.executed_test_set
    }

    #[must_use]
    pub fn executed_test_to_files_map(&self) -> &HashMap<TI, HashSet<PathBuf>> {
        &self.executed_test_to_files_map
    }

    #[must_use]
    pub fn executed_test_to_functions_map(&self) -> &HashMap<TI, HashSet<String>> {
        &self.executed_test_to_functions_map
    }

    #[must_use]
    pub fn executed_test_to_coverage_identifier_map(&self) -> &HashMap<TI, HashSet<CI>> {
        &self.executed_test_to_coverage_identifier_map
    }

    #[must_use]
    pub fn file_references_files_map(&self) -> &HashMap<PathBuf, HashSet<PathBuf>> {
        &self.file_references_files_map
    }

    pub fn add_existing_test(&mut self, test_identifier: TI) {
        self.all_existing_test_set.insert(test_identifier);
    }

    pub fn add_executed_test(&mut self, test_identifier: TI) {
        self.executed_test_set.insert(test_identifier);
    }

    pub fn add_file_to_test(&mut self, coverage: FileCoverage<TI>) {
        // "FileCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents the
        // two strings from being passed in the wrong order by making them named.
        self.executed_test_to_files_map
            .entry(coverage.test_identifier)
            .or_default()
            .insert(coverage.file_name);
    }

    pub fn add_function_to_test(&mut self, coverage: FunctionCoverage<TI>) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.executed_test_to_functions_map
            .entry(coverage.test_identifier)
            .or_default()
            .insert(coverage.function_name);
    }

    pub fn add_heuristic_coverage_to_test(&mut self, coverage: HeuristicCoverage<TI, CI>) {
        self.executed_test_to_coverage_identifier_map
            .entry(coverage.test_identifier)
            .or_default()
            .insert(coverage.coverage_identifier);
    }

    pub fn add_file_reference(&mut self, file_reference: FileReference) {
        self.file_references_files_map
            .entry(file_reference.referencing_file)
            .or_default()
            .insert(file_reference.target_file);
    }

    pub fn mark_file_makes_no_references(&mut self, referencing_file: PathBuf) {
        self.file_references_files_map
            .insert(referencing_file, HashSet::new());
    }

    pub fn merge_in(&mut self, mut other: CommitCoverageData<TI, CI>) {
        for tc in other.all_existing_test_set.drain() {
            self.all_existing_test_set.insert(tc);
        }
        for tc in other.executed_test_set.drain() {
            self.executed_test_set.insert(tc);
        }
        // The contents of reach of these keys are overwritten, not merged -- that's fine for the use-case we're
        // expecting which is a single test run being merged into a library of test runs.  But just in-case we ever
        // change how this works and stumble into this being a data corruption problem, we'll assert that we're never
        // losing data.
        for (k, v) in other.executed_test_to_files_map.drain() {
            let retval = self.executed_test_to_files_map.insert(k, v);
            assert_eq!(retval, None);
        }
        for (k, v) in other.executed_test_to_functions_map.drain() {
            let retval = self.executed_test_to_functions_map.insert(k, v);
            assert_eq!(retval, None);
        }
        for (k, v) in other.executed_test_to_coverage_identifier_map.drain() {
            let retval = self.executed_test_to_coverage_identifier_map.insert(k, v);
            assert_eq!(retval, None);
        }
        for (k, v) in other.file_references_files_map.drain() {
            let retval = self.file_references_files_map.insert(k, v);
            assert_eq!(retval, None);
        }
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
            package_name: String::from("thiserror"),
            version: String::from("0.1"),
        })
    });
    static REGEX: LazyLock<RustCoverageIdentifier> = LazyLock::new(|| {
        RustCoverageIdentifier::PackageDependency(RustPackageDependency {
            package_name: String::from("regex"),
            version: String::from("0.1"),
        })
    });

    #[test]
    fn test_new_coverage_data() {
        let coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();
        assert!(coverage_data.executed_test_set().is_empty());
        assert!(coverage_data.executed_test_to_files_map().is_empty());
        assert!(coverage_data.executed_test_to_functions_map().is_empty());
    }

    #[test]
    fn test_add_executed_test() {
        let mut coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();
        coverage_data.add_executed_test(TEST1.clone());
        coverage_data.add_executed_test(TEST2.clone());
        assert_eq!(coverage_data.executed_test_set().len(), 2);
        assert!(coverage_data.executed_test_set().contains(&TEST1));
        assert!(coverage_data.executed_test_set().contains(&TEST2));
    }

    #[test]
    fn test_add_existing_test() {
        let mut coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();
        coverage_data.add_existing_test(TEST1.clone());
        coverage_data.add_existing_test(TEST2.clone());
        assert_eq!(coverage_data.existing_test_set().len(), 2);
        assert!(coverage_data.existing_test_set().contains(&TEST1));
        assert!(coverage_data.existing_test_set().contains(&TEST2));
    }

    #[test]
    fn test_add_file_to_test() {
        let mut coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();
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

        assert_eq!(coverage_data.executed_test_to_files_map().len(), 2);
        assert_eq!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST2)
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST1)
                .unwrap()
                .contains(&PathBuf::from("file1.rs"))
        );
        assert!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST1)
                .unwrap()
                .contains(&PathBuf::from("file2.rs"))
        );
        assert!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST2)
                .unwrap()
                .contains(&PathBuf::from("file1.rs"))
        );
    }

    #[test]
    fn test_add_function_to_test() {
        let mut coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();
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

        assert_eq!(coverage_data.executed_test_to_functions_map().len(), 2);
        assert_eq!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&TEST1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&TEST2)
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&TEST1)
                .unwrap()
                .contains("func1")
        );
        assert!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&TEST1)
                .unwrap()
                .contains("func2")
        );
        assert!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&TEST2)
                .unwrap()
                .contains("func1")
        );
    }

    #[test]
    fn add_coverage_identifier_to_test() {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: TEST1.clone(),
            coverage_identifier: REGEX.clone(),
        });
        coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: TEST2.clone(),
            coverage_identifier: REGEX.clone(),
        });
        coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: TEST1.clone(),
            coverage_identifier: THISERROR.clone(),
        });

        assert_eq!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST2)
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST1)
                .unwrap()
                .contains(&THISERROR)
        );
        assert!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST1)
                .unwrap()
                .contains(&REGEX)
        );
        assert!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST2)
                .unwrap()
                .contains(&REGEX)
        );
    }

    #[test]
    fn add_file_reference() {
        let mut coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();
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
        coverage_data.mark_file_makes_no_references(PathBuf::from("src/zero.rs"));

        assert_eq!(coverage_data.file_references_files_map().len(), 3);
        assert_eq!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/two.rs"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/one.rs"))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/zero.rs"))
                .unwrap()
                .len(),
            0
        );
        assert!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/two.rs"))
                .unwrap()
                .contains(&PathBuf::from("extra-data/abc-123.txt"))
        );
        assert!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/two.rs"))
                .unwrap()
                .contains(&PathBuf::from("extra-data/abc-321.txt"))
        );
        assert!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/one.rs"))
                .unwrap()
                .contains(&PathBuf::from("extra-data/abc-123.txt"))
        );
    }

    #[test]
    fn serialize() -> Result<()> {
        let mut coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            CommitCoverageData::new();

        coverage_data.add_existing_test(TEST1.clone());
        coverage_data.add_executed_test(TEST1.clone());
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: TEST1.clone(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: TEST1.clone(),
        });
        coverage_data.add_heuristic_coverage_to_test(HeuristicCoverage {
            test_identifier: TEST1.clone(),
            coverage_identifier: REGEX.clone(),
        });
        coverage_data.add_file_reference(FileReference {
            referencing_file: PathBuf::from("src/one.rs"),
            target_file: PathBuf::from("extra-data/abc-123.txt"),
        });

        let serialized_data = serde_json::to_value(coverage_data)?;
        let coverage_data: CommitCoverageData<RustTestIdentifier, RustCoverageIdentifier> =
            serde_json::from_value(serialized_data)?;

        assert_eq!(coverage_data.existing_test_set().len(), 1);
        assert!(coverage_data.existing_test_set().contains(&TEST1));
        assert_eq!(coverage_data.existing_test_set().len(), 1);
        assert!(coverage_data.existing_test_set().contains(&TEST1));
        assert_eq!(coverage_data.executed_test_to_files_map().len(), 1);
        assert_eq!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST1) // PathBuf::from("file1.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .executed_test_to_files_map()
                .get(&TEST1)
                .unwrap()
                .contains(&PathBuf::from("file1.rs"))
        );
        assert_eq!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .len(),
            1
        );
        assert_eq!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST1)
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .executed_test_to_coverage_identifier_map()
                .get(&TEST1)
                .unwrap()
                .contains(&REGEX)
        );
        assert_eq!(coverage_data.file_references_files_map().len(), 1);
        assert_eq!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/one.rs"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            coverage_data
                .file_references_files_map()
                .get(&PathBuf::from("src/one.rs"))
                .unwrap()
                .contains(&PathBuf::from("extra-data/abc-123.txt"))
        );

        Ok(())
    }
}
