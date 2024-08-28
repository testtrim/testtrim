#!/usr/bin/env bash

set -eu -o pipefail
# set -x

BINARIES=$( \
  RUSTFLAGS="-C instrument-coverage" \
    cargo test --workspace --tests --no-run --message-format=json \
      | jq -r "select(.profile.test == true) | .filenames[]" \
      | grep -v dSYM -
)


rm -rf coverage-output
mkdir coverage-output

for b in $BINARIES;
do
  echo $b
  bname=$(basename $b)

  mkdir -p coverage-output/$bname
  $b --list | grep ": test" | sed -e 's/: test//' > coverage-output/$bname/test-list.txt

  for t in $(cat coverage-output/$bname/test-list.txt);
  do
    set +e
    LLVM_PROFILE_FILE="coverage-output/$bname/$t.profraw" \
      RUSTFLAGS="-C instrument-coverage" \
      $b --exact $t
    test_result=$?
    set -e
    # FIXME: do something with test failure?

    cargo profdata -- merge -sparse coverage-output/$bname/$t.profraw -o coverage-output/$bname/$t.profdata

    cargo cov -- export \
      -Xdemangler=rustfilt \
      $BINARIES \
      --format=lcov \
      --instr-profile=coverage-output/$bname/$t.profdata \
      > coverage-output/$bname/$t.lcov
  done
done

# cargo cov -- report \
#     -Xdemangler=rustfilt \
#     ./target/debug/deps/alacritty_terminal-9aa76ce6cd8a2b47 \
#     --instr-profile=./coverage-output/alacritty_terminal-9aa76ce6cd8a2b47/term::tests::simple_selection_works.profdata
