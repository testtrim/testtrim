// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use llvm_profparser::{
    coverage_mapping::read_object_file,
    instrumentation_profile::types::{InstrumentationProfile, NamedInstrProfRecord},
    CoverageMappingInfo,
};
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
};

use crate::errors::RustLlvmError;

/// Multiple Rust binaries can be loaded into a coverage catalog.  After one of the binaries is executed, the resulting
/// profraw or profdata can be parsed, and the coverage library can be used to lookup metadata about the instrumentation
/// points from those profiling data sources.
pub struct CoverageLibrary {
    object_files: HashMap<PathBuf, CoverageMappingInfo>,
    lookup_map: HashMap<PathBuf, HashMap<CoverageFunctionLocator, FilenamesRef>>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct CoverageFunctionLocator {
    name_hash: u64,
    fn_hash: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct FilenamesRef(u64);

impl Default for CoverageLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageLibrary {
    /// Create a new, blank coverage library.
    pub fn new() -> Self {
        CoverageLibrary {
            object_files: HashMap::new(),
            lookup_map: HashMap::new(),
        }
    }

    /// Load a binary into the coverage library.  This binary will be used to lookup metadata about instrumentation
    /// points from profiling data sources.
    pub fn load_binary(&mut self, path: &Path) -> Result<()> {
        // FIXME: is the version 10 provided here... meaningful?  I guessed a random number and it worked.
        let object_file = read_object_file(path, 10)?;

        let mut object_file_lookup_map = HashMap::new();
        for c in &object_file.cov_fun {
            let key = CoverageFunctionLocator {
                name_hash: c.header.name_hash,
                fn_hash: c.header.fn_hash,
            };
            let previous_value =
                object_file_lookup_map.insert(key, FilenamesRef(c.header.filenames_ref));
            assert!(previous_value.is_none()); // must never have duplicate/conflicting hashes
        }

        self.lookup_map
            .insert(PathBuf::from(path), object_file_lookup_map);
        self.object_files.insert(PathBuf::from(path), object_file);

        Ok(())
    }

    pub fn search_metadata(
        &self,
        point: &InstrumentationPoint,
    ) -> Result<Option<InstrumentationPointMetadata>> {
        match (point.rec.name_hash, point.rec.hash) {
            (Some(name_hash), Some(fn_hash)) => {
                match self.lookup_map.get(point.binary_path) {
                    Some(object_file_lookup_map) => {
                        match object_file_lookup_map
                            .get(&CoverageFunctionLocator { name_hash, fn_hash })
                        {
                            Some(r) => {
                                let object_file = self
                                    .object_files
                                    .get(point.binary_path)
                                    .expect("must be stored in both internal members");
                                match object_file.cov_map.get(&r.0) {
                                    Some(file) => {
                                        // FIXME: I don't know if the multiple file paths here are right... need to
                                        // create some synthetic test cases and verify that the references make sense to
                                        // me, and maybe verify some of the test-project cases to understand them.
                                        Ok(Some(InstrumentationPointMetadata {
                                            file_paths: file.clone(),
                                            function_name: point.rec.name.clone().unwrap(),
                                        }))
                                    }
                                    None => {
                                        // coverage point didn't have any files asociated with it
                                        Ok(None)
                                    }
                                }
                            }
                            None => {
                                // coverage point found in profiling data was not found in binary's coverage map
                                Err(RustLlvmError::CoverageMismatch.into())
                            }
                        }
                    }
                    None => {
                        Err(RustLlvmError::LibraryMissingBinary(point.binary_path.clone()).into())
                        // Err(anyhow!("attempted to read data about a binary file that was not in the coverage library: {:?}", point.binary_path))
                    }
                }
            }
            _ => {
                // Function point didn't have a hash; this comes pretty straight from the llvm parser so I don't think
                // there's much to do here.
                Ok(None)
            }
        }
    }
}

/// ProfilingData is currently just a wrapper around llvm_profparser's InstrumentationProfile.  Wrapping these objects
/// lightly in the rust_llvm module allows future complexity (which will likely be needed) to be isolated here.
pub struct ProfilingData {
    instrumentation_profile: InstrumentationProfile,
    binary_path: PathBuf,
}

impl ProfilingData {
    /// Parse a profraw file.
    pub fn new_from_profraw_reader<T: Read>(mut reader: T, binary_path: &Path) -> Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(ProfilingData {
            instrumentation_profile: llvm_profparser::parse_bytes(&buf)?,
            binary_path: PathBuf::from(binary_path),
        })
    }

    /// Return a list of instrumentation points that were hit during the profiling run.
    pub fn get_hit_instrumentation_points(&self) -> Vec<InstrumentationPoint<'_>> {
        let mut res = Vec::new();
        for rec in self.instrumentation_profile.records() {
            for c in rec.counts() {
                if *c > 0 {
                    res.push(InstrumentationPoint {
                        rec: rec.clone(),
                        binary_path: &self.binary_path,
                    });
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
pub struct InstrumentationPoint<'a> {
    rec: NamedInstrProfRecord,
    binary_path: &'a PathBuf,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::current_exe;

    /// The unit test rust_llvm::tests::load_binary works by loading this executable and verifying that we can read Rust
    /// binary coverage data with the rust_llvm module.  For this to work, the binary has to be compiled with
    /// RUSTFLAGS="-C instrument-coverage".  As a side-effect of that, running testtrim itself will output profiling
    /// data to the path $LLVM_PROFILE_FILE, which defaults to "default_%m_%p.profraw" if not provided.
    ///
    /// This causes any run of testtrim which takes place inside a project directory to create garbage which makes it
    /// dirty, which then affects the testtrim's detection of whether the project is dirty.
    ///
    /// I attempted a few workarounds; (a) setting LLVM_PROFILE_FILE automatically in main.rs, no effect; (b) disabling
    /// the RUSTFLAGS in .cargo/config.toml and Cargo.toml conditionally but there's no supported way; (c) a Rust build
    /// script but there's no supported way.
    ///
    /// Well, since this test works currently, the current workaround is to leave it ignored.
    #[test]
    #[ignore = "needs testtrim to be build with instrument-coverage"]
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
