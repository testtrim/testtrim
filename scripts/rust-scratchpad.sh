#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -eux -o pipefail

# cargo run
# cargo profdata -- merge -sparse default.profraw -o default.profdata
# cargo cov -- show \
#     -Xdemangler=rustfilt \
#     target/debug/testtrim \
#     --instr-profile=default.profdata \
#     --show-line-counts-or-regions \
#     --show-instantiations
# cargo cov -- report \
#     -Xdemangler=rustfilt \
#     target/debug/testtrim \
#     --instr-profile=default.profdata

rm *.profraw
rm *.profdata

LLVM_PROFILE_FILE="default_%m_%p.profraw" RUSTFLAGS="-C instrument-coverage" \
  cargo test --tests

cargo profdata -- merge -sparse default*.profraw -o default.profdata

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
