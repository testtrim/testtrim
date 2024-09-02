use std::{collections::{HashMap, HashSet}, fs, io::{BufReader, Read}, path::Path};
use lcov::{Reader, Record};
use clap::{Parser, Subcommand, Args};
use rust_llvm::{CoverageLibrary, ProfilingData};
use tar::Archive;
use bzip2::read::BzDecoder;
use sevenz_rust::{Password, SevenZReader};

mod rust_llvm;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}


#[derive(Subcommand)]
enum Commands {
    /// Print stats on the coverage
    PrintStats(CoverageSource),
    /// Analyze and output the tests to execute
    AnalyzeTests {
        #[clap(flatten)]
        coverage_source: CoverageSource,
        /// The file containing the diff
        #[clap(short, long, value_parser)]
        diff_file: String,
        /// Root directory of the repository; used to normalize file names between the coverage data and the diff file.
        #[clap(short, long, value_parser)]
        repository_root: String,
    },

    PrintStats2 {
        #[clap(flatten)]
        coverage_source: CoverageSource,

        /// Path of one or more binaries to read LLVM instrumentation data from
        #[clap(short, long, value_parser)]
        binaries: Vec<String>,
    }
}

#[derive(Args)]
#[clap(group = clap::ArgGroup::new("coverage_source").required(true).multiple(false))]
struct CoverageSource {
    /// The directory containing coverage files
    #[clap(short = 'd', long, value_parser, group = "coverage_source")]
    coverage_dir: Option<String>,
    /// The archive containing coverage files
    #[clap(short = 'a', long, value_parser, group = "coverage_source")]
    coverage_archive: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::PrintStats(coverage_source) => {
            let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
                let coverage_dir = Path::new(dir);
                process_coverage_files(coverage_dir)
            } else if let Some(archive) = &coverage_source.coverage_archive {
                let archive_path = Path::new(archive);
                process_coverage_archive(archive_path)
            } else {
                unreachable!("Either coverage_dir or coverage_archive must be provided")
            };
            print_analysis_results(&coverage_data);
        },
        Commands::AnalyzeTests { coverage_source, diff_file, repository_root } => {
            let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
                let coverage_dir = Path::new(dir);
                process_coverage_files(coverage_dir)
            } else if let Some(archive) = &coverage_source.coverage_archive {
                let archive_path = Path::new(archive);
                process_coverage_archive(archive_path)
            } else {
                unreachable!("Either coverage_dir or coverage_archive must be provided")
            };

            process_diff_file(&coverage_data, diff_file, repository_root);
        },
        Commands::PrintStats2 { coverage_source, binaries } => {

            let mut coverage_library = CoverageLibrary::new();
            for binary in binaries {
                println!("Loading binary ...");
                let binary_path = Path::new(binary);
                coverage_library.load_binary(binary_path).expect("load_binary");
                // let coverage_data = read_object_file(binary_path, &coverage_library).expect("Failed to read object file");
                // println!("Coverage data for {}: {:?}", binary, coverage_data);
            }

            let coverage_data = if let Some(dir) = &coverage_source.coverage_dir {
                let coverage_dir = Path::new(dir);
                process_profraw_coverage_files(&coverage_library, coverage_dir)
            } else if let Some(archive) = &coverage_source.coverage_archive {
                let archive_path = Path::new(archive);
                process_profraw_coverage_archive(&coverage_library, archive_path)
            } else {
                unreachable!("Either coverage_dir or coverage_archive must be provided")
            };
            print_analysis_results(&coverage_data);

            // let test_file = "/home/mfenniak/Dev/alacritty/coverage-output/alacritty-96e68ef375a5c974/string::tests::into_shortened_with_shortener.profraw";
            // let test_data = ProfilingData::new_from_profraw(Path::new(test_file)).expect("new_from_profraw");

            // for point in test_data.get_hit_instrumentation_points() {
            //     println!("found point...");

            //     let metadata = coverage_library.search_metadata(&point).expect("search_metadata");
            //     println!("metadata: {:?}", metadata);
            // }



            // coverage_source.coverage_dir.unwrap()

            // for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
            //     let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
            //     println!("Test executor binary: {}", test_executor_path.display());

            //     process_test_executor_directory(&test_executor_path, &mut file_to_test_map, &mut test_set, &mut function_to_test_map);
            // }


        },
    }
}

fn process_diff_file(coverage_data: &CoverageData, diff_file: &str, repository_root: &str) {
    // FIXME: diff_file is not truly a diff (right now), but just a EOL terminated list of files that are modified for
    // simplicity.  Make it a diff later.
    //
    // For now, read that list of files:
    let diff_content = fs::read_to_string(diff_file).expect("Failed to read diff file");
    let files_changed: Vec<&str> = diff_content.lines().collect();
    println!("files_changed: {:?}", files_changed);

    // Get the absolute path of repository root.
    let repository_root_abs = fs::canonicalize(repository_root).expect("Failed to canonicalize repository root");
    println!("repository_root_abs: {:?}", repository_root_abs);

    // Now search coverage data for all the tests that we need to run.
    let mut tests_to_run = HashSet::new();
    for file in files_changed {
        // Treat the file name as relative to the repository_root_abs; don't canonicalize it because it might not exist
        // and apparently that's a requirement for that func.
        let file_abs = repository_root_abs.join(file);
        println!("changed file, abs: {:?}", file_abs);

        if let Some(tests) = coverage_data.file_to_test_map.get(file_abs.to_str().unwrap()) {
            println!("\tFound {} tests", tests.len());
            tests_to_run.extend(tests.iter().cloned());
        }
    }

    println!("{} tests to execute", tests_to_run.len());
    for test in &tests_to_run {
        println!("\t{}", test);
    }
    if coverage_data.test_set.is_empty() {
        println!("can't compute %age");
    } else {
        println!(
            "Analysis shows there were {} tests, so this is {}%",
            coverage_data.test_set.len(),
            100 * tests_to_run.len() / coverage_data.test_set.len()
        );
    }
}

struct CoverageData {
    test_set: HashSet<String>,
    file_to_test_map: HashMap<String, HashSet<String>>,
    function_to_test_map: HashMap<String, HashSet<String>>,
}

fn process_coverage_files(coverage_dir: &Path) -> CoverageData {
    let mut test_set: HashSet<String> = HashSet::new();
    let mut file_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();
    let mut function_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();

    for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
        let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
        println!("Test executor binary: {}", test_executor_path.display());

        process_test_executor_directory(&test_executor_path, &mut file_to_test_map, &mut test_set, &mut function_to_test_map);
    }

    CoverageData {
        test_set,
        file_to_test_map,
        function_to_test_map,
    }
}

fn process_test_executor_directory(
    test_executor_path: &Path,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    test_set: &mut HashSet<String>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    for test_output_entry in fs::read_dir(test_executor_path).expect("Failed to read test executor directory") {
        let test_output_path = test_output_entry.expect("Failed to read directory entry").path();

        if let Some("lcov") = test_output_path.extension().and_then(|ext| ext.to_str()) {
            println!("\tTest case: {}", test_output_path.display());

            let test_name = test_output_path.file_stem()
                .and_then(|stem| stem.to_str())
                .expect("Failed to extract test name")
                .to_string();

            test_set.insert(test_output_path.to_str().unwrap().to_string());

            let file = fs::File::open(&test_output_path).expect("Failed to open LCOV file");
            process_lcov(file, &test_name, file_to_test_map, function_to_test_map);
        }
    }
}

fn process_profraw_coverage_files(coverage_library: &CoverageLibrary, coverage_dir: &Path) -> CoverageData {
    let mut test_set: HashSet<String> = HashSet::new();
    let mut file_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();
    let mut function_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();

    for test_executor_entry in fs::read_dir(coverage_dir).expect("Failed to read coverage directory") {
        let test_executor_path = test_executor_entry.expect("Failed to read directory entry").path();
        println!("Test executor binary: {}", test_executor_path.display());

        process_profraw_test_executor_directory(&test_executor_path, coverage_library, &mut file_to_test_map, &mut test_set, &mut function_to_test_map);
    }

    CoverageData {
        test_set,
        file_to_test_map,
        function_to_test_map,
    }
}

fn process_profraw_test_executor_directory(
    test_executor_path: &Path,
    coverage_library: &CoverageLibrary,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    test_set: &mut HashSet<String>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    for test_output_entry in fs::read_dir(test_executor_path).expect("Failed to read test executor directory") {
        let test_output_path = test_output_entry.expect("Failed to read directory entry").path();

        if let Some("profraw") = test_output_path.extension().and_then(|ext| ext.to_str()) {
            println!("\tTest case: {}", test_output_path.display());

            let test_name = test_output_path.file_stem()
                .and_then(|stem| stem.to_str())
                .expect("Failed to extract test name")
                .to_string();

            test_set.insert(test_output_path.to_str().unwrap().to_string());

            let file = fs::File::open(&test_output_path).expect("Failed to open LCOV file");
            process_profraw(file, &test_name, coverage_library, file_to_test_map, function_to_test_map);
        }
    }
}

fn process_coverage_archive(archive_path: &Path) -> CoverageData {
    let mut test_set: HashSet<String> = HashSet::new();
    let mut file_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();
    let mut function_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();

    let extension = archive_path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

    match extension {
        "bz2" => process_tar_bz2(archive_path, &mut test_set, &mut file_to_test_map, &mut function_to_test_map),
        "7z" => process_7z(archive_path, &mut test_set, &mut file_to_test_map, &mut function_to_test_map),
        _ => panic!("Unsupported archive format"),
    }

    CoverageData {
        test_set,
        file_to_test_map,
        function_to_test_map,
    }
}

fn process_profraw_coverage_archive(coverage_library: &CoverageLibrary, archive_path: &Path) -> CoverageData {
    let mut test_set: HashSet<String> = HashSet::new();
    let mut file_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();
    let mut function_to_test_map: HashMap<String, HashSet<String>> = HashMap::new();

    let extension = archive_path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

    match extension {
        "bz2" => process_profraw_tar_bz2(coverage_library, archive_path, &mut test_set, &mut file_to_test_map, &mut function_to_test_map),
        "7z" => process_profraw_7z(coverage_library, archive_path, &mut test_set, &mut file_to_test_map, &mut function_to_test_map),
        _ => panic!("Unsupported archive format"),
    }

    CoverageData {
        test_set,
        file_to_test_map,
        function_to_test_map,
    }
}

fn process_tar_bz2(
    archive_path: &Path,
    test_set: &mut HashSet<String>,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    let file = fs::File::open(archive_path).expect("Failed to open archive file");
    let bz2 = BzDecoder::new(file);
    let mut archive = Archive::new(bz2);

    for entry in archive.entries().expect("Failed to read archive entries") {
        let mut entry = entry.expect("Failed to read archive entry");
        let path = entry.path().unwrap().to_str().unwrap().to_string();
        println!("bz2: {}", path);
        process_archive_entry(&path, &mut entry, test_set, file_to_test_map, function_to_test_map);
    }
}

fn process_profraw_tar_bz2(
    coverage_library: &CoverageLibrary,
    archive_path: &Path,
    test_set: &mut HashSet<String>,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    let file = fs::File::open(archive_path).expect("Failed to open archive file");
    let bz2 = BzDecoder::new(file);
    let mut archive = Archive::new(bz2);

    for entry in archive.entries().expect("Failed to read archive entries") {
        let mut entry = entry.expect("Failed to read archive entry");
        let path = entry.path().unwrap().to_str().unwrap().to_string();
        println!("bz2: {}", path);
        process_profraw_archive_entry(coverage_library, &path, &mut entry, test_set, file_to_test_map, function_to_test_map);
    }
}

fn process_7z(
    archive_path: &Path,
    test_set: &mut HashSet<String>,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    // let file = fs::File::open(archive_path).expect("Failed to open archive file");
    let mut sz = SevenZReader::open(archive_path, Password::empty()).expect("Failed to create 7z reader");

    sz.for_each_entries(|entry, reader| {
        println!("7z: {}", entry.name());
        process_archive_entry(entry.name(), reader, test_set, file_to_test_map, function_to_test_map);
        Ok(true) // FIXME: not sure if true or false is needed here
    }).expect("for_each_entries");
}

fn process_profraw_7z(
    coverage_library: &CoverageLibrary,
    archive_path: &Path,
    test_set: &mut HashSet<String>,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    // let file = fs::File::open(archive_path).expect("Failed to open archive file");
    let mut sz = SevenZReader::open(archive_path, Password::empty()).expect("Failed to create 7z reader");

    sz.for_each_entries(|entry, reader| {
        println!("7z: {}", entry.name());
        process_profraw_archive_entry(coverage_library, entry.name(), reader, test_set, file_to_test_map, function_to_test_map);
        Ok(true) // FIXME: not sure if true or false is needed here
    }).expect("for_each_entries");
}

fn process_archive_entry<R: Read + ?Sized>(
    entry_name: &str,
    entry: &mut R,
    test_set: &mut HashSet<String>,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    // check if lcov, and if so, extract the test name...
    if entry_name.ends_with(".lcov") {
        let test_name = Path::new(entry_name)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("Failed to extract test name")
            .to_string();
        test_set.insert(test_name.clone());
        process_lcov(entry, &test_name, file_to_test_map, function_to_test_map);
    }
}

fn process_profraw_archive_entry<R: Read + ?Sized>(
    coverage_library: &CoverageLibrary,
    entry_name: &str,
    entry: &mut R,
    test_set: &mut HashSet<String>,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    if entry_name.ends_with(".profraw") {
        let test_name = Path::new(entry_name)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("Failed to extract test name")
            .to_string();
        test_set.insert(test_name.clone());
        process_profraw(entry, &test_name, coverage_library, file_to_test_map, function_to_test_map);
    }
}

fn process_lcov<T: Read>(
    reader: T,
    test_name: &str,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    let buf_reader = BufReader::new(reader);
    let reader = Reader::new(buf_reader);
    let mut current_source_file = None;
    let mut current_source_file_is_hit = false;

    for record in reader {
        match record {
            Ok(Record::SourceFile { path }) => {
                update_file_to_test_map(file_to_test_map, &current_source_file, test_name, current_source_file_is_hit);
                current_source_file = Some(path.to_str().expect("Invalid UTF-8 in path").to_string());
                current_source_file_is_hit = false;
            }
            Ok(Record::LineData { count, .. }) if count > 0 => {
                current_source_file_is_hit = true;
            }
            Ok(Record::EndOfRecord) => {
                update_file_to_test_map(file_to_test_map, &current_source_file, test_name, current_source_file_is_hit);
            }
            Ok(Record::FunctionData { name: function_name, count }) if count > 0 => {
                update_function_to_test_map(function_to_test_map, &function_name, test_name);
            }
            _ => {}
        }
    }
}

fn process_profraw<T: Read>(
    reader: T,
    test_name: &str,
    coverage_library: &CoverageLibrary,
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
) {
    let profiling_data = ProfilingData::new_from_profraw_reader(reader).expect("new_from_profraw_reader");

    for point in profiling_data.get_hit_instrumentation_points() {
        // println!("found point...");

        let metadata = coverage_library.search_metadata(&point)
            .expect("search_metadata success")
            .expect("search_metadata returned value");
        // println!("metadata: {:?}", metadata);

        for file in metadata.file_paths {
            update_file_to_test_map(file_to_test_map, &Some(file.to_str().expect("path->str").to_string()), test_name, true);
        }
        update_function_to_test_map(function_to_test_map, &metadata.function_name, test_name);
    }
}

fn update_file_to_test_map(
    file_to_test_map: &mut HashMap<String, HashSet<String>>,
    current_source_file: &Option<String>,
    test_name: &str,
    is_hit: bool,
) {
    if let (true, Some(source_file)) = (is_hit, current_source_file) {
        file_to_test_map
            .entry(source_file.clone())
            .or_default()
            .insert(test_name.to_string());
    }
}

fn update_function_to_test_map(
    function_to_test_map: &mut HashMap<String, HashSet<String>>,
    function_name: &str,
    test_name: &str,
) {
    function_to_test_map
        .entry(function_name.to_string())
        .or_default()
        .insert(test_name.to_string());
}

fn print_analysis_results(coverage_data: &CoverageData) {
    let total_tests = coverage_data.test_set.len();
    // let total_tests = file_to_test_map.values().map(|tests| tests.len()).sum::<usize>();

    // Example analysis (unchanged)
    if let Some(tests_affected) = coverage_data.file_to_test_map.get("/home/mfenniak/Dev/rust-coverage-thingy/src/main.rs") {
        println!(
            "If src/main.rs is changed, {} tests need to be rerun ({:?})",
            tests_affected.len(),
            tests_affected,
        );
    } else if let Some(tests_affected) = coverage_data.file_to_test_map.get("src/main.rs") {
        println!(
            "If src/main.rs is changed, {} tests need to be rerun ({:?})",
            tests_affected.len(),
            tests_affected,
        );
    } else {
        println!("can't find src/main.rs");
    }

    if let Some(tests_affected) = coverage_data.file_to_test_map.get("/home/mfenniak/Dev/rust-coverage-thingy/src/rust_llvm.rs") {
        println!(
            "If src/rust_llvm.rs is changed, {} tests need to be rerun ({:?})",
            tests_affected.len(),
            tests_affected,
        );
    } else if let Some(tests_affected) = coverage_data.file_to_test_map.get("src/rust_llvm.rs") {
        println!(
            "If src/rust_llvm.rs is changed, {} tests need to be rerun ({:?})",
            tests_affected.len(),
            tests_affected,
        );
    } else {
        println!("can't find src/rust_llvm.rs");
    }

    let stats = calculate_statistics(coverage_data);

    if stats.input_file_count == 0 || total_tests == 0 {
        // Avoid division by zero
        println!("No input source files ({}) or tests ({}) found.", stats.input_file_count, total_tests);
    } else {
        println!(
            "On average, for each source file, we'd have to rerun {} tests ({}%)",
            stats.input_file_total_tests_affected / stats.input_file_count,
            100 * stats.input_file_total_tests_affected / stats.input_file_count / total_tests
        );
        println!("By file: Minimum tests affected count = {:?}", stats.by_file_min_tests_affected_by_change);
        println!("By file: Median tests affected count = {:?}", stats.by_file_median_tests_affected_by_change);
        println!("By file: Maximum tests affected count = {:?}", stats.by_file_max_tests_affected_by_change);
    }

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

    if stats.input_function_count == 0 || total_tests == 0 {
        println!("No input source functions ({}) or tests ({}) found.", stats.input_function_count, total_tests);
    } else {
        println!(
            "On average, for each source function, we'd have to rerun {} tests ({}%)",
            stats.input_function_total_tests_affected / stats.input_function_count,
            100 * stats.input_function_total_tests_affected / stats.input_function_count / total_tests
        );
    }
    println!("By function: Minimum tests affected count = {:?}", stats.by_function_min_tests_affected_by_change);
    println!("By function: Median tests affected count = {:?}", stats.by_function_median_tests_affected_by_change);
    println!("By function: Maximum tests affected count = {:?}", stats.by_function_max_tests_affected_by_change);

    // Display every input function, and the number of tests that would need to be re-executed:
    println!("function\ttests-to-rerun\ttotal-tests");
    for (function, tests_affected) in &coverage_data.function_to_test_map {
        println!(
            "{}\t{}\t{}",
            function,
            tests_affected.len(),
            total_tests,
        );
    }
}

struct TestFileStatistics {
    input_file_count: usize,
    input_file_total_tests_affected: usize,
    by_file_min_tests_affected_by_change: Option<(String, usize)>,
    by_file_median_tests_affected_by_change: Option<(String, usize)>,
    by_file_max_tests_affected_by_change: Option<(String, usize)>,

    input_function_count: usize,
    input_function_total_tests_affected: usize,
    by_function_min_tests_affected_by_change: Option<(String, usize)>,
    by_function_median_tests_affected_by_change: Option<(String, usize)>,
    by_function_max_tests_affected_by_change: Option<(String, usize)>,
}

fn calculate_statistics(coverage_data: &CoverageData) -> TestFileStatistics {
    // Calculate a lowest, highest, and median test file -- take the file_to_test_map hashmap and create a version that
    // is sorted by the length of its tests so that we can just pull the first, middle, and last one:
    let mut sorted_file_to_test_map: Vec<(&String, &HashSet<String>)> = coverage_data.file_to_test_map.iter().collect();
    sorted_file_to_test_map.sort_by_key(|(_, tests)| tests.len());

    let by_file_min_tests_affected_by_change = sorted_file_to_test_map.first().map(|(file, tests)| ((*file).to_string(), tests.len()));
    let by_file_median_tests_affected_by_change = if !sorted_file_to_test_map.is_empty() {
        let middle_index = sorted_file_to_test_map.len() / 2;
        let (file, tests) = &sorted_file_to_test_map[middle_index];
        Some(((*file).to_string(), tests.len()))
    } else {
        None
    };
    let by_file_max_tests_affected_by_change = sorted_file_to_test_map.last().map(|(file, tests)| ((*file).to_string(), tests.len()));

    let input_file_total_tests_affected = sorted_file_to_test_map.iter().map(|(_, tests)| tests.len()).sum();
    let input_file_count = sorted_file_to_test_map.len();

    // Repeat stats calculation by function
    let mut sorted_function_to_test_map: Vec<(&String, &HashSet<String>)> = coverage_data.function_to_test_map.iter().collect();
    sorted_function_to_test_map.sort_by_key(|(_, tests)| tests.len());

    let by_function_min_tests_affected_by_change = sorted_function_to_test_map.first().map(|(function, tests)| ((*function).to_string(), tests.len()));
    let by_function_median_tests_affected_by_change = if !sorted_function_to_test_map.is_empty() {
        let middle_index = sorted_function_to_test_map.len() / 2;
        let (function, tests) = &sorted_function_to_test_map[middle_index];
        Some(((*function).to_string(), tests.len()))
    } else {
        None
    };
    let by_function_max_tests_affected_by_change = sorted_function_to_test_map.last().map(|(function, tests)| ((*function).to_string(), tests.len()));

    let input_function_total_tests_affected = sorted_function_to_test_map.iter().map(|(_, tests)| tests.len()).sum();
    let input_function_count = sorted_function_to_test_map.len();

    TestFileStatistics {
        input_file_count,
        input_file_total_tests_affected,
        by_file_min_tests_affected_by_change,
        by_file_median_tests_affected_by_change,
        by_file_max_tests_affected_by_change,

        input_function_count,
        input_function_total_tests_affected,
        by_function_min_tests_affected_by_change,
        by_function_median_tests_affected_by_change,
        by_function_max_tests_affected_by_change,
    }
}

#[cfg(test)]
mod tests {
    use crate::rust_llvm::sentinel_function;

    /// This is a sentinel test that doesn't reach outside of this project, but does go from main.rs -> rust_llvm.rs.
    /// As a result, this test should be considered for re-run if rust_llvm.rs changes or main.rs changes, but nothing
    /// else.
    #[test]
    fn sentinel_internal_file() {
        let x = sentinel_function();
        assert_eq!(x, 2);
    }
}
