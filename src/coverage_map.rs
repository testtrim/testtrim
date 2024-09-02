use std::collections::{HashMap, HashSet};

pub struct CoverageData {
    test_set: HashSet<String>,
    file_to_test_map: HashMap<String, HashSet<String>>,
    function_to_test_map: HashMap<String, HashSet<String>>,
}

pub struct FileCoverage {
    pub file_name: String, // FIXME: change to PathBuf in the future -- rework everything using file paths to just stick with PathBuf
    pub test_name: String,
}

pub struct FunctionCoverage {
    pub function_name: String,
    pub test_name: String,
}

impl CoverageData {
    pub fn new() -> Self {
        CoverageData {
            test_set: HashSet::new(),
            file_to_test_map: HashMap::new(),
            function_to_test_map: HashMap::new(),
        }
    }

    pub fn test_set(&self) -> &HashSet<String> {
        &self.test_set
    }

    pub fn file_to_test_map(&self) -> &HashMap<String, HashSet<String>> {
        &self.file_to_test_map
    }

    pub fn function_to_test_map(&self) -> &HashMap<String, HashSet<String>> {
        &self.function_to_test_map
    }

    pub fn add_test(&mut self, test_name: &str) {
        self.test_set.insert(test_name.to_string());
    }

    pub fn add_file_to_test(&mut self, coverage: FileCoverage) {
        // "FileCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents the
        // two strings from being passed in the wrong order by making them named.
        self.file_to_test_map
            .entry(coverage.file_name)
            .or_default()
            .insert(coverage.test_name);
    }

    pub fn add_function_to_test(&mut self, coverage: FunctionCoverage) {
        // "FunctionCoverage" is slightly over engineered compared to just having two &str arguments, but it prevents
        // the two strings from being passed in the wrong order by making them named.
        self.function_to_test_map
            .entry(coverage.function_name)
            .or_default()
            .insert(coverage.test_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_coverage_data() {
        let coverage_data = CoverageData::new();
        assert!(coverage_data.test_set().is_empty());
        assert!(coverage_data.file_to_test_map().is_empty());
        assert!(coverage_data.function_to_test_map().is_empty());
    }

    #[test]
    fn test_add_test() {
        let mut coverage_data = CoverageData::new();
        coverage_data.add_test("test1");
        coverage_data.add_test("test2");
        assert_eq!(coverage_data.test_set().len(), 2);
        assert!(coverage_data.test_set().contains("test1"));
        assert!(coverage_data.test_set().contains("test2"));
    }

    #[test]
    fn test_add_file_to_test() {
        let mut coverage_data = CoverageData::new();
        coverage_data.add_file_to_test(FileCoverage {
            file_name: "file1.rs".to_string(),
            test_name: "test1".to_string(),
        });
        coverage_data.add_file_to_test(FileCoverage {
            file_name: "file1.rs".to_string(),
            test_name: "test2".to_string(),
        });
        coverage_data.add_file_to_test(FileCoverage {
            file_name: "file2.rs".to_string(),
            test_name: "test1".to_string(),
        });

        assert_eq!(coverage_data.file_to_test_map().len(), 2);
        assert_eq!(coverage_data.file_to_test_map().get("file1.rs").unwrap().len(), 2);
        assert_eq!(coverage_data.file_to_test_map().get("file2.rs").unwrap().len(), 1);
        assert!(coverage_data.file_to_test_map().get("file1.rs").unwrap().contains("test1"));
        assert!(coverage_data.file_to_test_map().get("file1.rs").unwrap().contains("test2"));
        assert!(coverage_data.file_to_test_map().get("file2.rs").unwrap().contains("test1"));
    }

    #[test]
    fn test_add_function_to_test() {
        let mut coverage_data = CoverageData::new();
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_name: "test1".to_string(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func1".to_string(),
            test_name: "test2".to_string(),
        });
        coverage_data.add_function_to_test(FunctionCoverage {
            function_name: "func2".to_string(),
            test_name: "test1".to_string(),
        });

        assert_eq!(coverage_data.function_to_test_map().len(), 2);
        assert_eq!(coverage_data.function_to_test_map().get("func1").unwrap().len(), 2);
        assert_eq!(coverage_data.function_to_test_map().get("func2").unwrap().len(), 1);
        assert!(coverage_data.function_to_test_map().get("func1").unwrap().contains("test1"));
        assert!(coverage_data.function_to_test_map().get("func1").unwrap().contains("test2"));
        assert!(coverage_data.function_to_test_map().get("func2").unwrap().contains("test1"));
    }
}
