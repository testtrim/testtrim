#!/usr/bin/env bash

set -eu -o pipefail
# set -x

BINARY_ARRAY=($( \
  RUSTFLAGS="-C instrument-coverage" \
    cargo test --workspace --tests --no-run --message-format=json \
      | jq -r "select(.profile.test == true) | .filenames[]" \
      | grep -v dSYM -
))

# Create a new array with "--binary" before each binary
BINARY_ARGS=()
for binary in "${BINARY_ARRAY[@]}"; do
  BINARY_ARGS+=("-object" "$binary")
done

rm -rf coverage-output
mkdir coverage-output

for b in "${BINARY_ARRAY[@]}"
do
  echo $b
  bname=$(basename $b)

  mkdir -p coverage-output/$bname
  $b --list | (grep ": test" || true) | sed -e 's/: test//' > coverage-output/$bname/test-list.txt

  for t in $(cat coverage-output/$bname/test-list.txt);
  do
    echo "Execute test $t..."
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
      "${BINARY_ARGS[@]}" \
      --format=lcov \
      --instr-profile=coverage-output/$bname/$t.profdata \
      > coverage-output/$bname/$t.lcov
  done
done

# cargo cov -- report \
#     -Xdemangler=rustfilt \
#     ./target/debug/deps/alacritty_terminal-9aa76ce6cd8a2b47 \
#     --instr-profile=./coverage-output/alacritty_terminal-9aa76ce6cd8a2b47/term::tests::simple_selection_works.profdata
