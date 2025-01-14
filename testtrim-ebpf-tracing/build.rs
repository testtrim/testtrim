// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "testtrim-ebpf-program")
        .ok_or_else(|| anyhow!("testtrim-ebpf-program package not found"))?;
    // If building under testtrim, where we effectively run the root cargo command w/ RUSTFLAGS="-C
    // instrument-coverage", we'll get an error in the eBPF build that we "can't find crate for `profiler_builtins`" as
    // it tries to pass instrument-coverage into the eBPF build, and presumably the eBPF platform doesn't support
    // instrumentation.  In order to prevent this we trim out the CARGO_ENCODED_RUSTFLAGS which would contain this
    // option at this point.
    unsafe { std::env::remove_var("CARGO_ENCODED_RUSTFLAGS") };
    aya_build::build_ebpf([ebpf_package])
}
