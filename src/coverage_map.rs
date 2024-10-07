use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RustTestIdentifier {
    /// Project-relative source path that defines the binary which contains the test.  For example,
    /// some_module/src/lib.rs.
    pub test_src_path: PathBuf,
    /// Name of the test.  For example, basic_ops::tests::test_add.
    pub test_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoverageData {
    // FIXME: RustTestIdentifier is specific to Rust -- in the future this structure probably becomes generic over
    // different types of test identifier storage.
    all_existing_test_set: HashSet<RustTestIdentifier>,
    executed_test_set: HashSet<RustTestIdentifier>,
    file_to_test_map: HashMap<PathBuf, HashSet<RustTestIdentifier>>,
    function_to_test_map: HashMap<String, HashSet<RustTestIdentifier>>,
}

pub struct FileCoverage {
    pub file_name: PathBuf,
    pub test_identifier: RustTestIdentifier,
}

pub struct FunctionCoverage {
    pub function_name: String,
    pub test_identifier: RustTestIdentifier,
}

impl Default for CoverageData {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageData {
    pub fn new() -> Self {
        CoverageData {
            all_existing_test_set: HashSet::new(),
            executed_test_set: HashSet::new(),
            file_to_test_map: HashMap::new(),
            function_to_test_map: HashMap::new(),
        }
    }

    pub fn existing_test_set(&self) -> &HashSet<RustTestIdentifier> {
        &self.all_existing_test_set
    }

    pub fn executed_test_set(&self) -> &HashSet<RustTestIdentifier> {
        &self.executed_test_set
    }

    pub fn file_to_test_map(&self) -> &HashMap<PathBuf, HashSet<RustTestIdentifier>> {
        &self.file_to_test_map
    }

    pub fn function_to_test_map(&self) -> &HashMap<String, HashSet<RustTestIdentifier>> {
        &self.function_to_test_map
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
}

// pub struct TestFileStatistics {
//     pub input_file_count: usize,
//     pub input_file_total_tests_affected: usize,
//     pub by_file_min_tests_affected_by_change: Option<(PathBuf, usize)>,
//     pub by_file_median_tests_affected_by_change: Option<(PathBuf, usize)>,
//     pub by_file_max_tests_affected_by_change: Option<(PathBuf, usize)>,

//     pub input_function_count: usize,
//     pub input_function_total_tests_affected: usize,
//     pub by_function_min_tests_affected_by_change: Option<(String, usize)>,
//     pub by_function_median_tests_affected_by_change: Option<(String, usize)>,
//     pub by_function_max_tests_affected_by_change: Option<(String, usize)>,
// }

// impl CoverageData {
//     pub fn calculate_statistics(&self) -> TestFileStatistics {
//         // Calculate a lowest, highest, and median test file -- take the file_to_test_map hashmap and create a version that
//         // is sorted by the length of its tests so that we can just pull the first, middle, and last one:
//         let mut sorted_file_to_test_map: Vec<(&PathBuf, &HashSet<RustTestIdentifier>)> =
//             self.file_to_test_map().iter().collect();
//         sorted_file_to_test_map.sort_by_key(|(_, tests)| tests.len());

//         let by_file_min_tests_affected_by_change = sorted_file_to_test_map
//             .first()
//             .map(|(file, tests)| ((*file).clone(), tests.len()));
//         let by_file_median_tests_affected_by_change = if !sorted_file_to_test_map.is_empty() {
//             let middle_index = sorted_file_to_test_map.len() / 2;
//             let (file, tests) = &sorted_file_to_test_map[middle_index];
//             Some(((*file).clone(), tests.len()))
//         } else {
//             None
//         };
//         let by_file_max_tests_affected_by_change = sorted_file_to_test_map
//             .last()
//             .map(|(file, tests)| ((*file).clone(), tests.len()));

//         let input_file_total_tests_affected = sorted_file_to_test_map
//             .iter()
//             .map(|(_, tests)| tests.len())
//             .sum();
//         let input_file_count = sorted_file_to_test_map.len();

//         // Repeat stats calculation by function
//         let mut sorted_function_to_test_map: Vec<(&String, &HashSet<RustTestIdentifier>)> =
//             self.function_to_test_map().iter().collect();
//         sorted_function_to_test_map.sort_by_key(|(_, tests)| tests.len());

//         let by_function_min_tests_affected_by_change = sorted_function_to_test_map
//             .first()
//             .map(|(function, tests)| ((*function).to_string(), tests.len()));
//         let by_function_median_tests_affected_by_change = if !sorted_function_to_test_map.is_empty()
//         {
//             let middle_index = sorted_function_to_test_map.len() / 2;
//             let (function, tests) = &sorted_function_to_test_map[middle_index];
//             Some(((*function).to_string(), tests.len()))
//         } else {
//             None
//         };
//         let by_function_max_tests_affected_by_change = sorted_function_to_test_map
//             .last()
//             .map(|(function, tests)| ((*function).to_string(), tests.len()));

//         let input_function_total_tests_affected = sorted_function_to_test_map
//             .iter()
//             .map(|(_, tests)| tests.len())
//             .sum();
//         let input_function_count = sorted_function_to_test_map.len();

//         TestFileStatistics {
//             input_file_count,
//             input_file_total_tests_affected,
//             by_file_min_tests_affected_by_change,
//             by_file_median_tests_affected_by_change,
//             by_file_max_tests_affected_by_change,

//             input_function_count,
//             input_function_total_tests_affected,
//             by_function_min_tests_affected_by_change,
//             by_function_median_tests_affected_by_change,
//             by_function_max_tests_affected_by_change,
//         }
//     }
// }

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
        let coverage_data = CoverageData::new();
        assert!(coverage_data.executed_test_set().is_empty());
        assert!(coverage_data.file_to_test_map().is_empty());
        assert!(coverage_data.function_to_test_map().is_empty());
    }

    #[test]
    fn test_add_executed_test() {
        let mut coverage_data = CoverageData::new();
        coverage_data.add_executed_test(test1.clone());
        coverage_data.add_executed_test(test2.clone());
        assert_eq!(coverage_data.executed_test_set().len(), 2);
        assert!(coverage_data.executed_test_set().contains(&test1));
        assert!(coverage_data.executed_test_set().contains(&test2));
    }

    #[test]
    fn test_add_existing_test() {
        let mut coverage_data = CoverageData::new();
        coverage_data.add_existing_test(test1.clone());
        coverage_data.add_existing_test(test2.clone());
        assert_eq!(coverage_data.existing_test_set().len(), 2);
        assert!(coverage_data.existing_test_set().contains(&test1));
        assert!(coverage_data.existing_test_set().contains(&test2));
    }

    #[test]
    fn test_add_file_to_test() {
        let mut coverage_data = CoverageData::new();
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
        let mut coverage_data = CoverageData::new();
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

    // #[test]
    // fn test_calculate_statistics_empty() {
    //     let coverage_data = CoverageData::new();
    //     let stats = coverage_data.calculate_statistics();

    //     assert_eq!(stats.input_file_count, 0);
    //     assert_eq!(stats.input_file_total_tests_affected, 0);
    //     assert_eq!(stats.by_file_min_tests_affected_by_change, None);
    //     assert_eq!(stats.by_file_median_tests_affected_by_change, None);
    //     assert_eq!(stats.by_file_max_tests_affected_by_change, None);

    //     assert_eq!(stats.input_function_count, 0);
    //     assert_eq!(stats.input_function_total_tests_affected, 0);
    //     assert_eq!(stats.by_function_min_tests_affected_by_change, None);
    //     assert_eq!(stats.by_function_median_tests_affected_by_change, None);
    //     assert_eq!(stats.by_function_max_tests_affected_by_change, None);
    // }

    // #[test]
    // fn test_calculate_statistics_by_file() {
    //     let mut coverage_data = CoverageData::new();

    //     // Add some test data
    //     coverage_data.add_test(test1.clone()); // touches 1 file
    //     coverage_data.add_test(test2.clone()); // touches 2 files
    //     coverage_data.add_test(test3.clone()); // touches 3 files

    //     coverage_data.add_file_to_test(FileCoverage {
    //         file_name: PathBuf::from("file1.rs"),
    //         test_identifier: test1.clone(),
    //     });

    //     coverage_data.add_file_to_test(FileCoverage {
    //         file_name: PathBuf::from("file1.rs"),
    //         test_identifier: test2.clone(),
    //     });
    //     coverage_data.add_file_to_test(FileCoverage {
    //         file_name: PathBuf::from("file2.rs"),
    //         test_identifier: test2.clone(),
    //     });

    //     coverage_data.add_file_to_test(FileCoverage {
    //         file_name: PathBuf::from("file1.rs"),
    //         test_identifier: test3.clone(),
    //     });
    //     coverage_data.add_file_to_test(FileCoverage {
    //         file_name: PathBuf::from("file2.rs"),
    //         test_identifier: test3.clone(),
    //     });
    //     coverage_data.add_file_to_test(FileCoverage {
    //         file_name: PathBuf::from("file3.rs"),
    //         test_identifier: test3.clone(),
    //     });

    //     let stats = coverage_data.calculate_statistics();

    //     assert_eq!(stats.input_file_count, 3);
    //     assert_eq!(stats.input_file_total_tests_affected, 6);
    //     assert_eq!(
    //         stats.by_file_min_tests_affected_by_change,
    //         Some((PathBuf::from("file3.rs"), 1))
    //     );
    //     assert_eq!(
    //         stats.by_file_median_tests_affected_by_change,
    //         Some((PathBuf::from("file2.rs"), 2))
    //     );
    //     assert_eq!(
    //         stats.by_file_max_tests_affected_by_change,
    //         Some((PathBuf::from("file1.rs"), 3))
    //     );
    // }

    // #[test]
    // fn test_calculate_statistics_by_function() {
    //     let mut coverage_data = CoverageData::new();

    //     // Add some test data
    //     coverage_data.add_test(test1.clone()); // touches 1 file
    //     coverage_data.add_test(test2.clone()); // touches 2 files
    //     coverage_data.add_test(test3.clone()); // touches 3 files

    //     coverage_data.add_function_to_test(FunctionCoverage {
    //         function_name: "function1".to_string(),
    //         test_identifier: test1.clone(),
    //     });

    //     coverage_data.add_function_to_test(FunctionCoverage {
    //         function_name: "function1".to_string(),
    //         test_identifier: test2.clone(),
    //     });
    //     coverage_data.add_function_to_test(FunctionCoverage {
    //         function_name: "function2".to_string(),
    //         test_identifier: test2.clone(),
    //     });

    //     coverage_data.add_function_to_test(FunctionCoverage {
    //         function_name: "function1".to_string(),
    //         test_identifier: test3.clone(),
    //     });
    //     coverage_data.add_function_to_test(FunctionCoverage {
    //         function_name: "function2".to_string(),
    //         test_identifier: test3.clone(),
    //     });
    //     coverage_data.add_function_to_test(FunctionCoverage {
    //         function_name: "function3".to_string(),
    //         test_identifier: test3.clone(),
    //     });

    //     let stats = coverage_data.calculate_statistics();

    //     assert_eq!(stats.input_function_count, 3);
    //     assert_eq!(stats.input_function_total_tests_affected, 6);
    //     assert_eq!(
    //         stats.by_function_min_tests_affected_by_change,
    //         Some(("function3".to_string(), 1))
    //     );
    //     assert_eq!(
    //         stats.by_function_median_tests_affected_by_change,
    //         Some(("function2".to_string(), 2))
    //     );
    //     assert_eq!(
    //         stats.by_function_max_tests_affected_by_change,
    //         Some(("function1".to_string(), 3))
    //     );
    // }
}
