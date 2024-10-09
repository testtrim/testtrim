use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

// FIXME: move RustTestIdentifier to a rust-platform-specific module
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustTestIdentifier {
    /// Project-relative source path that defines the binary which contains the test.  For example,
    /// some_module/src/lib.rs.
    pub test_src_path: PathBuf,
    /// Name of the test.  For example, basic_ops::tests::test_add.
    pub test_name: String,
}

/// CommitCoverageData represents the coverage data that could be collected from test execution on a single commit;
/// importantly this may represent data from only a partial execution of tests that were appropriate to that commit,
/// rather than a complete test run.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitCoverageData {
    // FIXME: RustTestIdentifier is specific to Rust -- in the future this structure probably becomes generic over
    // different types of test identifier storage.
    all_existing_test_set: HashSet<RustTestIdentifier>,
    executed_test_set: HashSet<RustTestIdentifier>,
    executed_test_to_files_map: HashMap<RustTestIdentifier, HashSet<PathBuf>>,
    executed_test_to_functions_map: HashMap<RustTestIdentifier, HashSet<String>>,
}

pub struct FileCoverage {
    pub file_name: PathBuf,
    pub test_identifier: RustTestIdentifier,
}

pub struct FunctionCoverage {
    pub function_name: String,
    pub test_identifier: RustTestIdentifier,
}

impl Default for CommitCoverageData {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitCoverageData {
    pub fn new() -> Self {
        CommitCoverageData {
            all_existing_test_set: HashSet::new(),
            executed_test_set: HashSet::new(),
            executed_test_to_files_map: HashMap::new(),
            executed_test_to_functions_map: HashMap::new(),
        }
    }

    pub fn existing_test_set(&self) -> &HashSet<RustTestIdentifier> {
        &self.all_existing_test_set
    }

    pub fn executed_test_set(&self) -> &HashSet<RustTestIdentifier> {
        &self.executed_test_set
    }

    pub fn executed_test_to_files_map(&self) -> &HashMap<RustTestIdentifier, HashSet<PathBuf>> {
        &self.executed_test_to_files_map
    }

    pub fn executed_test_to_functions_map(&self) -> &HashMap<RustTestIdentifier, HashSet<String>> {
        &self.executed_test_to_functions_map
    }

    pub fn add_existing_test(&mut self, test_identifier: RustTestIdentifier) {
        self.all_existing_test_set.insert(test_identifier);
    }

    pub fn add_executed_test(&mut self, test_identifier: RustTestIdentifier) {
        self.executed_test_set.insert(test_identifier);
    }

    pub fn add_file_to_test(&mut self, coverage: FileCoverage) {
        // "FileCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents the
        // two strings from being passed in the wrong order by making them named.
        self.executed_test_to_files_map
            .entry(coverage.test_identifier)
            .or_default()
            .insert(coverage.file_name);
    }

    pub fn add_function_to_test(&mut self, coverage: FunctionCoverage) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.executed_test_to_functions_map
            .entry(coverage.test_identifier)
            .or_default()
            .insert(coverage.function_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

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
    }

    #[test]
    fn test_new_coverage_data() {
        let coverage_data = CommitCoverageData::new();
        assert!(coverage_data.executed_test_set().is_empty());
        assert!(coverage_data.executed_test_to_files_map().is_empty());
        assert!(coverage_data.executed_test_to_functions_map().is_empty());
    }

    #[test]
    fn test_add_executed_test() {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_executed_test(test1.clone());
        coverage_data.add_executed_test(test2.clone());
        assert_eq!(coverage_data.executed_test_set().len(), 2);
        assert!(coverage_data.executed_test_set().contains(&test1));
        assert!(coverage_data.executed_test_set().contains(&test2));
    }

    #[test]
    fn test_add_existing_test() {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_existing_test(test1.clone());
        coverage_data.add_existing_test(test2.clone());
        assert_eq!(coverage_data.existing_test_set().len(), 2);
        assert!(coverage_data.existing_test_set().contains(&test1));
        assert!(coverage_data.existing_test_set().contains(&test2));
    }

    #[test]
    fn test_add_file_to_test() {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test1.clone(),
        });
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file1.rs"),
            test_identifier: test2.clone(),
        });
        coverage_data.add_file_to_test(FileCoverage {
            file_name: PathBuf::from("file2.rs"),
            test_identifier: test1.clone(),
        });

        assert_eq!(coverage_data.executed_test_to_files_map().len(), 2);
        assert_eq!(
            coverage_data
                .executed_test_to_files_map()
                .get(&test1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .executed_test_to_files_map()
                .get(&test2)
                .unwrap()
                .len(),
            1
        );
        assert!(coverage_data
            .executed_test_to_files_map()
            .get(&test1)
            .unwrap()
            .contains(&PathBuf::from("file1.rs")));
        assert!(coverage_data
            .executed_test_to_files_map()
            .get(&test1)
            .unwrap()
            .contains(&PathBuf::from("file2.rs")));
        assert!(coverage_data
            .executed_test_to_files_map()
            .get(&test2)
            .unwrap()
            .contains(&PathBuf::from("file1.rs")));
    }

    #[test]
    fn test_add_function_to_test() {
        let mut coverage_data = CommitCoverageData::new();
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test1.clone(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_identifier: test2.clone(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_identifier: test1.clone(),
        });

        assert_eq!(coverage_data.executed_test_to_functions_map().len(), 2);
        assert_eq!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&test1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .executed_test_to_functions_map()
                .get(&test2)
                .unwrap()
                .len(),
            1
        );
        assert!(coverage_data
            .executed_test_to_functions_map()
            .get(&test1)
            .unwrap()
            .contains("func1"));
        assert!(coverage_data
            .executed_test_to_functions_map()
            .get(&test1)
            .unwrap()
            .contains("func2"));
        assert!(coverage_data
            .executed_test_to_functions_map()
            .get(&test2)
            .unwrap()
            .contains("func1"));
    }
}
