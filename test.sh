#!/usr/bin/env bash

set -eux -o pipefail

# cargo test --tests
cargo run

cargo profdata -- merge -sparse default.profraw -o default.profdata

cargo cov -- show \
    -Xdemangler=rustfilt \
    target/debug/rust-coverage-thingy \
    --instr-profile=default.profdata \
    --show-line-counts-or-regions \
    --show-instantiations

cargo cov -- report \
    -Xdemangler=rustfilt \
    target/debug/rust-coverage-thingy \
    --instr-profile=default.profdata
