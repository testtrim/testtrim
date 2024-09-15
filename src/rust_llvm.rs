use anyhow::Result;
use llvm_profparser::{
    coverage_mapping::read_object_file,
    instrumentation_profile::types::{InstrumentationProfile, NamedInstrProfRecord},
    CoverageMappingInfo,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

// #[derive(Error, Debug)]
// pub enum RustLlvmError {
//     #[error("unexpected format in coverage map: {0}")]
//     CoverageMapUnexpectedFormat(String),
// }

/// Multiple Rust binaries can be loaded into a coverage catalog.  After one of the binaries is executed, the resulting
/// profraw or profdata can be parsed, and the coverage library can be used to lookup metadata about the instrumentation
/// points from those profiling data sources.
pub struct CoverageLibrary {
    object_files: Vec<CoverageMappingInfo>,
}

impl Default for CoverageLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageLibrary {
    /// Create a new, blank coverage library.
    pub fn new() -> Self {
        CoverageLibrary {
            object_files: Vec::new(),
        }
    }

    /// Load a binary into the coverage library.  This binary will be used to lookup metadata about instrumentation
    /// points from profiling data sources.
    pub fn load_binary(&mut self, path: &Path) -> Result<()> {
        // FIXME: is the version 10 provided here... meaningful?  I guessed a random number and it worked.
        let object_file = read_object_file(path, 10)?;
        self.object_files.push(object_file);
        Ok(())
    }

    pub fn search_metadata(
        &self,
        point: &InstrumentationPoint,
    ) -> Result<Option<InstrumentationPointMetadata>> {
        match (point.rec.name_hash, point.rec.hash) {
            (Some(name_hash), Some(fn_hash)) => {
                // FIXME: This is a linear search; should build more efficient data structures in the future as object
                // files are loaded.
                for object_file in &self.object_files {
                    for c in &object_file.cov_fun {
                        if c.header.name_hash == name_hash && c.header.fn_hash == fn_hash {
                            // Find the file that matches the function
                            match object_file.cov_map.get(&c.header.filenames_ref) {
                                Some(file) => {
                                    // FIXME: I don't know if the multiple file paths here are right... need to create
                                    // some synthetic test cases and verify that the references make sense to me, and
                                    // maybe verify some of the test-project cases to understand them.
                                    return Ok(Some(InstrumentationPointMetadata {
                                        file_paths: file.clone(),
                                        function_name: point.rec.name.clone().unwrap(),
                                    }));
                                }
                                None => {
                                    println!("\t\tNo file found for function");
                                }
                            }
                        }
                    }
                }

                // Couldn't find it... FIXME: maybe this should be an error
                Ok(None)
            }
            _ => {
                // Function point didn't have a hash; FIXME: maybe this should be an error
                Ok(None)
            }
        }
    }
}

/// ProfilingData is currently just a wrapper around llvm_profparser's InstrumentationProfile.  Wrapping these objects
/// lightly in the rust_llvm module allows future complexity (which will likely be needed) to be isolated here.
pub struct ProfilingData {
    instrumentation_profile: InstrumentationProfile,
}

impl ProfilingData {
    /// Parse a profraw file.
    pub fn new_from_profraw(path: &Path) -> Result<Self> {
        Ok(ProfilingData {
            instrumentation_profile: llvm_profparser::parse(path)?,
        })
    }

    /// Parse a profraw file.
    pub fn new_from_profraw_reader<T: Read>(mut reader: T) -> Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(ProfilingData {
            instrumentation_profile: llvm_profparser::parse_bytes(&buf)?,
        })
    }

    /// Return a list of instrumentation points that were hit during the profiling run.
    pub fn get_hit_instrumentation_points(&self) -> Vec<InstrumentationPoint> {
        let mut res = Vec::new();
        for rec in self.instrumentation_profile.records() {
            for c in rec.counts() {
                if *c > 0 {
                    res.push(InstrumentationPoint { rec: rec.clone() });
                    break;
                }
            }
        }
        res
    }
}

/// Wrapper around NamedInstrProfRecord, which represents an instrumentation codepoint that may have been hit during an
/// instrumented profiling run.
#[derive(Debug)]
pub struct InstrumentationPoint {
    rec: NamedInstrProfRecord,
}

/// Metadata about an instrumentation point.  This is used to map the instrumentation point to a source file, and can
/// have more specific information (probably in the future) like the function name.
#[derive(Debug)]
pub struct InstrumentationPointMetadata {
    // I'm not *quite* sure what this indicates in Rust, but the LLVM format allows mapping one instrumentation point to multiple files.  In C I think this would be used for something like a preprocessor expansion where the "#define" can be in a header, which can be used in a function, resulting in something that is really defined in two files.  In Rust?  I have some kind of example in
    // that I see multiple files being referred to in one test:
    // /home/mfenniak/Dev/alacritty/coverage-output/ref-5e9cb37821ba6702/alt_reset.profraw
    // ->
    // ["/home/mfenniak/Dev/alacritty", "/home/mfenniak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/vte-0.13.0/src/definitions.rs", "/home/mfenniak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/vte-0.13.0/src/lib.rs"]
    // The root directory of the project seems to almost always be present, but also at least some codepoints in this have multiple files.
    pub file_paths: Vec<PathBuf>,
    pub function_name: String,
}

/// This function is just used for internal testing of coverage reporting, and should be ignored otherwise.
#[allow(dead_code)]
pub fn sentinel_function() -> i32 {
    1 + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::current_exe;

    #[test]
    fn load_binary() {
        let mut lib = CoverageLibrary::new();
        lib.load_binary(&current_exe().expect("current_exe()"))
            .expect("failed to load binary");
    }

    /// This is a sentinel test that doesn't reach outside of this module, and should only have this file (eg.
    /// rust_llvm.rs) as a dependency for execution.
    #[test]
    fn sentinel_local_file() {
        let x = 1 + 1;
        assert_eq!(x, 2);
    }
}
