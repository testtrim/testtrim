#!/usr/bin/env bash

set -eux -o pipefail

# cargo run
# cargo profdata -- merge -sparse default.profraw -o default.profdata
# cargo cov -- show \
#     -Xdemangler=rustfilt \
#     target/debug/rust-coverage-thingy \
#     --instr-profile=default.profdata \
#     --show-line-counts-or-regions \
#     --show-instantiations
# cargo cov -- report \
#     -Xdemangler=rustfilt \
#     target/debug/rust-coverage-thingy \
#     --instr-profile=default.profdata

rm *.profraw
rm *.profdata

LLVM_PROFILE_FILE="default_%m_%p.profraw" RUSTFLAGS="-C instrument-coverage" \
  cargo test --tests

cargo profdata -- merge -sparse default_*_*.profraw -o default.profdata

BINARIES=$( \
  for file in \
    $( \
      RUSTFLAGS="-C instrument-coverage" \
        cargo test --tests --no-run --message-format=json \
          | jq -r "select(.profile.test == true) | .filenames[]" \
          | grep -v dSYM - \
    ); \
  do \
    printf "%s %s " -object $file; \
  done \
)

cargo cov -- show \
  -Xdemangler=rustfilt \
  $BINARIES \
  --instr-profile=default.profdata \
  --show-line-counts-or-regions \
  --show-instantiations

cargo cov -- report \
    -Xdemangler=rustfilt \
    $BINARIES \
    --instr-profile=default.profdata

cargo cov -- export \
    -Xdemangler=rustfilt \
    $BINARIES \
    --format=lcov \
    --instr-profile=default.profdata \
    > default.lcov

# cargo cov -- report \
#     -Xdemangler=rustfilt \
#     $BINARIES \
#     --instr-profile=default.profdata \
#     --summary-only

# llvm-cov report \
#     $( \
#       for file in \
#         $( \
#           RUSTFLAGS="-C instrument-coverage" \
#             cargo test --tests --no-run --message-format=json \
#               | jq -r "select(.profile.test == true) | .filenames[]" \
#               | grep -v dSYM - \
#         ); \
#       do \
#         printf "%s %s " -object $file; \
#       done \
#     ) \
#   --instr-profile=json5format.profdata --summary-only # and/or other options
