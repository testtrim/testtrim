// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use llvm_profparser::{
    CoverageMappingInfo,
    coverage_mapping::read_object_file,
    instrumentation_profile::types::{InstrumentationProfile, NamedInstrProfRecord},
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
struct FilenamesRef(u64, usize);

impl Default for CoverageLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// Note: We're reproducing a bunch of work that could be done by the llvm_profparser library's
// CoverageMapping::generate_report function.  The reason is: (a) we have more profiling data files than we do binary
// objects, so we store and optimize our data differently, (b) we don't need fine-grained region-specific coverage
// counts at this time.
//
// As a downside, this implementation is nowhere close to being fine-grained -- if we wanted to get branch-level detail
// we'd need to reimplement (or adapt) the expression-based supposed that CoverageMapping implements.  But while we might
// go function-level in the future, branch-level is quite optimistic.
//
// The important part of this note is that if something starts breaking in this implementation, we can likely review
// CoverageMapping for what we're doing wrong.

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
            // Every function has a variety of regions associated with it.  Those regions represent the branches in the
            // function that can have separate instrumentation profiling data.  Each region has a `file_id`, which is
            // going to be an index into an array of filenames for a translation unit, which in short, means that it's
            // going to point to a specific file name.
            //
            // For our needs in Rust language profiling, and based upon the current project experience, all the regions
            // within a function are expected to have the same file_id.  If there are cases that violate this, we'll
            // have to come across them experimentally.
            let mut file_id: Option<usize> = None;
            for region in &c.regions {
                match file_id {
                    Some(existing_file_id) if existing_file_id != region.file_id => {
                        panic!(
                            "llvm coverage region had multiple file_ids for a single function -- this isn't currently supported"
                        );
                    }
                    _ => {
                        file_id = Some(region.file_id);
                    }
                }
            }
            let Some(file_id) = file_id else {
                // A function with no regions?  Let's crash for now because that seems suspiciously wrong and I want to
                // bring attention to it to understand it, if it happens.
                panic!(
                    "llvm coverage region file_id could not be identified -- this suggests no regions in this function?"
                );
            };
            let key = CoverageFunctionLocator {
                name_hash: c.header.name_hash,
                fn_hash: c.header.fn_hash,
            };
            let previous_value =
                object_file_lookup_map.insert(key, FilenamesRef(c.header.filenames_ref, file_id));
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
        let (Some(name_hash), Some(fn_hash)) = (point.rec.name_hash, point.rec.hash) else {
            // Function point didn't have a hash; this comes pretty straight from the llvm parser so I don't think
            // there's much to do here.
            return Ok(None);
        };

        let object_file_lookup_map = self
            .lookup_map
            .get(point.binary_path)
            // binary provided was never loaded in?
            .ok_or_else(|| RustLlvmError::LibraryMissingBinary(point.binary_path.clone()))?;

        let coverage_locator = CoverageFunctionLocator { name_hash, fn_hash };
        let filenames_ref = object_file_lookup_map
            .get(&coverage_locator)
            // coverage point found in profiling data was not found in binary's coverage map
            .ok_or(RustLlvmError::CoverageMismatch)?;

        let object_file = self
            .object_files
            .get(point.binary_path)
            .expect("must be stored in both internal members");

        match object_file.cov_map.get(&filenames_ref.0) {
            Some(file) => {
                // file[0] is the root which relative paths should be interpreted against -- "The first entry in the
                // filename list is the compilation directory. When the filename is relative, the compilation directory
                // is combined with the relative path to get an absolute path. This can reduce size by omitting the
                // duplicate prefix in filenames." (https://llvm.org/docs/CoverageMappingFormat.html#function-record)
                // It should be safe for testtrim to assume that's the cwd since we just built the project as part of
                // test discovery?
                Ok(Some(InstrumentationPointMetadata {
                    file_path: file[filenames_ref.1].clone(),
                    function_name: point.rec.name.clone().unwrap(),
                }))
            }
            None => {
                // coverage point didn't have any files associated with it
                Ok(None)
            }
        }
    }
}

/// `ProfilingData` is currently just a wrapper around `llvm_profparser`'s `InstrumentationProfile`.  Wrapping these
/// objects lightly in the `rust_llvm` module allows future complexity (which will likely be needed) to be isolated
/// here.
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

/// Wrapper around `NamedInstrProfRecord`, which represents an instrumentation codepoint that may have been hit during
/// an instrumented profiling run.
#[derive(Debug)]
pub struct InstrumentationPoint<'a> {
    rec: NamedInstrProfRecord,
    binary_path: &'a PathBuf,
}

/// Metadata about an instrumentation point.  This is used to map the instrumentation point to a source file, and can
/// have more specific information (probably in the future) like the function name.
#[derive(Debug)]
pub struct InstrumentationPointMetadata {
    pub file_path: PathBuf,
    pub function_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::current_exe;

    // The unit test rust_llvm::tests::load_binary works by loading this executable and verifying that we can read Rust
    // binary coverage data with the rust_llvm module.  For this to work, the binary has to be compiled with
    // RUSTFLAGS="-C instrument-coverage".  As a side-effect of that, running testtrim itself will output profiling data
    // to the path $LLVM_PROFILE_FILE, which defaults to "default_%m_%p.profraw" if not provided.
    //
    // This causes any run of testtrim which takes place inside a project directory to create garbage which makes it
    // dirty, which then affects the testtrim's detection of whether the project is dirty.
    //
    // I attempted a few workarounds; (a) setting LLVM_PROFILE_FILE automatically in main.rs, no effect; (b) disabling
    // the RUSTFLAGS in .cargo/config.toml and Cargo.toml conditionally but there's no supported way; (c) a Rust build
    // script but there's no supported way.
    //
    // Well, since this test works currently, the current workaround is to leave it ignored.
    #[test]
    #[ignore = "needs testtrim to be build with instrument-coverage"]
    fn load_binary() {
        let mut lib = CoverageLibrary::new();
        lib.load_binary(&current_exe().expect("current_exe()"))
            .expect("failed to load binary");
    }

    // This is a sentinel test that doesn't reach outside of this module, and should only have this file (eg.
    // rust_llvm.rs) as a dependency for execution.
    #[test]
    fn sentinel_local_file() {
        let x = 1 + 1;
        assert_eq!(x, 2);
    }
}
