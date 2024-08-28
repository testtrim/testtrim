use std::{collections::HashMap, fs, path::Path};
use lcov::{Record, Reader};

fn main() {
    let coverage_dir = Path::new("/home/mfenniak/Dev/alacritty/coverage-output");
    let file_to_test_map = process_coverage_files(coverage_dir);

    print_analysis_results(&file_to_test_map);
}

fn process_coverage_files(coverage_dir: &Path) -> HashMap<String, Vec<String>> {
    let mut file_to_test_map: HashMap<String, Vec<String>> = HashMap::new();

    for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
        let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
        println!("Test executor binary: {}", test_executor_path.display());

        process_test_executor_directory(&test_executor_path, &mut file_to_test_map);
    }

    file_to_test_map
}

fn process_test_executor_directory(test_executor_path: &Path, file_to_test_map: &mut HashMap<String, Vec<String>>) {
    for test_output_entry in fs::read_dir(test_executor_path).expect("Failed to read test executor directory") {
        let test_output_path = test_output_entry.expect("Failed to read directory entry").path();

        if let Some("lcov") = test_output_path.extension().and_then(|ext| ext.to_str()) {
            println!("\tTest case: {}", test_output_path.display());
            process_lcov_file(&test_output_path, file_to_test_map);
        }
    }
}

fn process_lcov_file(lcov_path: &Path, file_to_test_map: &mut HashMap<String, Vec<String>>) {
    let test_name = lcov_path.file_stem()
        .and_then(|stem| stem.to_str())
        .expect("Failed to extract test name")
        .to_string();

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
    file_to_test_map: &mut HashMap<String, Vec<String>>,
    current_source_file: &Option<String>,
    test_name: &str,
    is_hit: bool,
) {
    match (is_hit, current_source_file) {
        (true, Some(source_file)) => {
            file_to_test_map
                .entry(source_file.clone())
                .or_insert_with(Vec::new)
                .push(test_name.to_string());
        }
        (_, _) => {}
    }
}

fn print_analysis_results(file_to_test_map: &HashMap<String, Vec<String>>) {
    let total_tests = file_to_test_map.values().map(|tests| tests.len()).sum::<usize>();

    // Example analysis (unchanged)
    if let Some(tests_affected) = file_to_test_map.get("/home/mfenniak/Dev/alacritty/alacritty_terminal/src/term/cell.rs") {
        println!(
            "If alacritty_terminal/src/term/cell.rs is changed, {} tests need to be rerun, out of {} tests",
            tests_affected.len(),
            total_tests
        );
    }

    let (src_file_sum_tests_affected, src_file_count, lowest_count, highest_count) = calculate_statistics(file_to_test_map);

    println!(
        "On average, for each source file, we'd have to rerun {} tests ({}%)",
        src_file_sum_tests_affected / src_file_count,
        100 * src_file_sum_tests_affected / src_file_count / total_tests
    );
    println!("Lowest count = {:?}", lowest_count);
    println!("Highest count = {:?}", highest_count);
}

fn calculate_statistics(file_to_test_map: &HashMap<String, Vec<String>>) -> (usize, usize, Option<(String, usize)>, Option<(String, usize)>) {
    let mut src_file_sum_tests_affected = 0;
    let src_file_count = file_to_test_map.len();
    let mut lowest_count = None;
    let mut highest_count = None;

    for (src_file, tests_affected) in file_to_test_map {
        let test_count = tests_affected.len();
        src_file_sum_tests_affected += test_count;

        lowest_count = match lowest_count {
            None => Some((src_file.clone(), test_count)),
            Some((_, lowest)) if test_count < lowest => Some((src_file.clone(), test_count)),
            _ => lowest_count,
        };

        highest_count = match highest_count {
            None => Some((src_file.clone(), test_count)),
            Some((_, highest)) if test_count > highest => Some((src_file.clone(), test_count)),
            _ => highest_count,
        };
    }

    (src_file_sum_tests_affected, src_file_count, lowest_count, highest_count)
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
