use std::{collections::{HashMap, HashSet}, fs, path::Path};
use lcov::{Record, Reader};

fn main() {
    let coverage_dir = Path::new("/home/mfenniak/Dev/alacritty/coverage-output");
    let coverage_data = process_coverage_files(coverage_dir);

    print_analysis_results(&coverage_data);
}

struct CoverageData {
    test_set: HashSet<String>,
    file_to_test_map: HashMap<String, HashSet<String>>,
}

fn process_coverage_files(coverage_dir: &Path) -> CoverageData {
    let mut test_set: HashSet<String> = HashSet::new();
    let mut file_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();

    for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
        let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
        println!("Test executor binary: {}", test_executor_path.display());

        process_test_executor_directory(&test_executor_path, &mut file_to_test_map, &mut test_set);
    }

    CoverageData {
        test_set,
        file_to_test_map,
    }
}

fn process_test_executor_directory(test_executor_path: &Path, file_to_test_map: &mut HashMap<String, HashSet<String>>, test_set: &mut HashSet<String>) {
    for test_output_entry in fs::read_dir(test_executor_path).expect("Failed to read test executor directory") {
        let test_output_path = test_output_entry.expect("Failed to read directory entry").path();

        if let Some("lcov") = test_output_path.extension().and_then(|ext| ext.to_str()) {
            println!("\tTest case: {}", test_output_path.display());
            process_lcov_file(&test_output_path, file_to_test_map, test_set);
        }
    }
}

fn process_lcov_file(lcov_path: &Path, file_to_test_map: &mut HashMap<String, HashSet<String>>, test_set: &mut HashSet<String>) {
    let test_name = lcov_path.file_stem()
        .and_then(|stem| stem.to_str())
        .expect("Failed to extract test name")
        .to_string();

    // FIXME: in the future, store some kind of structure representing the "Address" of this test (eg. for rust, the
    // project/workspace/test-executor then fully-qualified name).  For now, the lcov path will stand-in for that.
    test_set.insert(lcov_path.to_str().unwrap().to_string());

    let reader = Reader::open_file(lcov_path).expect("Failed to open LCOV file");
    let mut current_source_file = None;
    let mut current_source_file_is_hit = false;

    for record in reader {
        match record {
            Ok(Record::SourceFile { path }) => {
                update_file_to_test_map(file_to_test_map, &current_source_file, &test_name, current_source_file_is_hit);
                current_source_file = Some(path.to_str().expect("Invalid UTF-8 in path").to_string());
                current_source_file_is_hit = false;
            }
            Ok(Record::LineData { count, .. }) if count > 0 => {
                current_source_file_is_hit = true;
            }
            Ok(Record::EndOfRecord) => {
                update_file_to_test_map(file_to_test_map, &current_source_file, &test_name, current_source_file_is_hit);
            }
            _ => {}
        }
    }
}

fn update_file_to_test_map(
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    current_source_file: &Option<String>,
    test_name: &str,
    is_hit: bool,
) {
    match (is_hit, current_source_file) {
        (true, Some(source_file)) => {
            file_to_test_map
                .entry(source_file.clone())
                .or_insert_with(HashSet::new)
                .insert(test_name.to_string());
        }
        (_, _) => {}
    }
}

fn print_analysis_results(coverage_data: &CoverageData) {
    let total_tests = coverage_data.test_set.len();
    // let total_tests = file_to_test_map.values().map(|tests| tests.len()).sum::<usize>();

    // Example analysis (unchanged)
    if let Some(tests_affected) = coverage_data.file_to_test_map.get("/home/mfenniak/Dev/alacritty/alacritty_terminal/src/term/cell.rs") {
        println!(
            "If alacritty_terminal/src/term/cell.rs is changed, {} tests need to be rerun, out of {} tests; {}% of tests",
            tests_affected.len(),
            total_tests,
            100 * tests_affected.len() / total_tests
        );
    }

    let stats = calculate_statistics(&coverage_data);

    println!(
        "On average, for each source file, we'd have to rerun {} tests ({}%)",
        stats.input_file_total_tests_affected / stats.input_file_count,
        100 * stats.input_file_total_tests_affected / stats.input_file_count / total_tests
    );
    println!("Minimum tests affected count = {:?}", stats.min_tests_affected_by_change);
    println!("Median tests affected count = {:?}", stats.median_tests_affected_by_change);
    println!("Maximum tests affected count = {:?}", stats.max_tests_affected_by_change);

    // Display every input file, and the number of tests that would need to be re-executed:
    println!("file\ttests-to-rerun\ttotal-tests");
    for (file, tests_affected) in &coverage_data.file_to_test_map {
        println!(
            "{}\t{}\t{}",
            file,
            tests_affected.len(),
            total_tests,
        );
    }
}

struct TestFileStatistics {
    input_file_count: usize,
    input_file_total_tests_affected: usize,
    min_tests_affected_by_change: Option<(String, usize)>,
    median_tests_affected_by_change: Option<(String, usize)>,
    max_tests_affected_by_change: Option<(String, usize)>,
}

fn calculate_statistics(coverage_data: &CoverageData) -> TestFileStatistics {

    // Calculate a lowest, highest, and median test file -- take the file_to_test_map hashmap and create a version that
    // is sorted by the length of its tests so that we can just pull the first, middle, and last one:
    let mut sorted_file_to_test_map: Vec<(&String, &HashSet<String>)> = coverage_data.file_to_test_map.iter().collect();
    sorted_file_to_test_map.sort_by_key(|(_, tests)| tests.len());

    let min_tests_affected_by_change = sorted_file_to_test_map.first().map(|(file, tests)| ((*file).to_string(), tests.len()));
    let median_tests_affected_by_change = if !sorted_file_to_test_map.is_empty() {
        let middle_index = sorted_file_to_test_map.len() / 2;
        let (file, tests) = &sorted_file_to_test_map[middle_index];
        Some(((*file).to_string(), tests.len()))
    } else {
        None
    };
    let max_tests_affected_by_change = sorted_file_to_test_map.last().map(|(file, tests)| ((*file).to_string(), tests.len()));

    let input_file_total_tests_affected = sorted_file_to_test_map.iter().map(|(_, tests)| tests.len()).sum();
    let input_file_count = sorted_file_to_test_map.len();

    TestFileStatistics {
        input_file_count,
        input_file_total_tests_affected,
        min_tests_affected_by_change,
        median_tests_affected_by_change,
        max_tests_affected_by_change,
    }
}

fn function1() {
    println!("Function 1");

    // Just to create some coverage data, let's check if a specific file exists and print some other lines.
    let path = std::path::Path::new("src/main.rs");
    if path.exists() {
        println!("File exists!");
    } else {
        println!("File does not exist!");
    }
}

fn function2() {
    println!("Function 2");
}

fn function3() {
    println!("Function 3");
}

// unit tests, fake
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function1() {
        function1();
    }

    #[test]
    fn test_function2() {
        function2();
    }

    #[test]
    fn test_function3() {
        function3();
    }
}
