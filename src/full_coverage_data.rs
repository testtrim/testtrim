use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use crate::commit_coverage_data::{
    FileCoverage, FunctionCoverage, RustCoverageIdentifier, RustTestIdentifier,
};

/// FullCoverageData represents coverage data that encompasses the entire project's test suite.  It will typically be
/// coalesced and merged from multiple test runs over time.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullCoverageData {
    // FIXME: RustTestIdentifier is specific to Rust -- in the future this structure probably becomes generic over
    // different types of test identifier storage.
    all_tests: HashSet<RustTestIdentifier>,
    file_to_test_map: HashMap<PathBuf, HashSet<RustTestIdentifier>>,
    function_to_test_map: HashMap<String, HashSet<RustTestIdentifier>>,
    coverage_identifier_to_test_map: HashMap<RustCoverageIdentifier, HashSet<RustTestIdentifier>>,
}

impl Default for FullCoverageData {
    fn default() -> Self {
        Self::new()
    }
}

impl FullCoverageData {
    pub fn new() -> Self {
        FullCoverageData {
            all_tests: HashSet::new(),
            file_to_test_map: HashMap::new(),
            function_to_test_map: HashMap::new(),
            coverage_identifier_to_test_map: HashMap::new(),
        }
    }

    pub fn all_tests(&self) -> &HashSet<RustTestIdentifier> {
        &self.all_tests
    }

    pub fn file_to_test_map(&self) -> &HashMap<PathBuf, HashSet<RustTestIdentifier>> {
        &self.file_to_test_map
    }

    pub fn function_to_test_map(&self) -> &HashMap<String, HashSet<RustTestIdentifier>> {
        &self.function_to_test_map
    }

    pub fn coverage_identifier_to_test_map(
        &self,
    ) -> &HashMap<RustCoverageIdentifier, HashSet<RustTestIdentifier>> {
        &self.coverage_identifier_to_test_map
    }

    pub fn add_existing_test(&mut self, test_identifier: RustTestIdentifier) {
        self.all_tests.insert(test_identifier);
    }

    pub fn add_file_to_test(&mut self, coverage: FileCoverage) {
        // "FileCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents the
        // two strings from being passed in the wrong order by making them named.
        self.file_to_test_map
            .entry(coverage.file_name)
            .or_default()
            .insert(coverage.test_identifier);
    }

    pub fn add_function_to_test(&mut self, coverage: FunctionCoverage) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.function_to_test_map
            .entry(coverage.function_name)
            .or_default()
            .insert(coverage.test_identifier);
    }

    pub fn add_heuristic_coverage_to_test(
        &mut self,
        test_identifier: RustTestIdentifier,
        coverage: RustCoverageIdentifier,
    ) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.coverage_identifier_to_test_map
            .entry(coverage)
            .or_default()
            .insert(test_identifier);
    }
}

#[cfg(test)]
mod tests {
    use crate::commit_coverage_data::RustExternalDependency;

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
        let coverage_data = FullCoverageData::new();
        assert!(coverage_data.all_tests().is_empty());
        assert!(coverage_data.file_to_test_map().is_empty());
        assert!(coverage_data.function_to_test_map().is_empty());
    }

    #[test]
    fn test_add_executed_test() {
        let mut coverage_data = FullCoverageData::new();
        coverage_data.add_existing_test(test1.clone());
        coverage_data.add_existing_test(test2.clone());
        assert_eq!(coverage_data.all_tests().len(), 2);
        assert!(coverage_data.all_tests().contains(&test1));
        assert!(coverage_data.all_tests().contains(&test2));
    }

    #[test]
    fn test_add_file_to_test() {
        let mut coverage_data = FullCoverageData::new();
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
        assert!(coverage_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test1));
        assert!(coverage_data
            .file_to_test_map()
            .get(&PathBuf::from("file1.rs"))
            .unwrap()
            .contains(&test2));
        assert!(coverage_data
            .file_to_test_map()
            .get(&PathBuf::from("file2.rs"))
            .unwrap()
            .contains(&test1));
    }

    #[test]
    fn test_add_function_to_test() {
        let mut coverage_data = FullCoverageData::new();
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
        assert!(coverage_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test1));
        assert!(coverage_data
            .function_to_test_map()
            .get("func1")
            .unwrap()
            .contains(&test2));
        assert!(coverage_data
            .function_to_test_map()
            .get("func2")
            .unwrap()
            .contains(&test1));
    }

    #[test]
    fn add_heuristic_coverage_to_test() {
        let mut coverage_data = FullCoverageData::new();
        let thiserror = RustCoverageIdentifier::ExternalDependency(RustExternalDependency {
            package_name: String::from("thiserror"),
            version: String::from("0.1"),
        });
        let regex = RustCoverageIdentifier::ExternalDependency(RustExternalDependency {
            package_name: String::from("regex"),
            version: String::from("0.1"),
        });
        coverage_data.add_heuristic_coverage_to_test(test1.clone(), regex.clone());
        coverage_data.add_heuristic_coverage_to_test(test2.clone(), regex.clone());
        coverage_data.add_heuristic_coverage_to_test(test1.clone(), thiserror.clone());

        assert_eq!(coverage_data.coverage_identifier_to_test_map().len(), 2);
        assert_eq!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&regex)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            coverage_data
                .coverage_identifier_to_test_map()
                .get(&thiserror)
                .unwrap()
                .len(),
            1
        );
        assert!(coverage_data
            .coverage_identifier_to_test_map()
            .get(&regex)
            .unwrap()
            .contains(&test1));
        assert!(coverage_data
            .coverage_identifier_to_test_map()
            .get(&regex)
            .unwrap()
            .contains(&test2));
        assert!(coverage_data
            .coverage_identifier_to_test_map()
            .get(&thiserror)
            .unwrap()
            .contains(&test1));
    }
}
