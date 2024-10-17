#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu -o pipefail
# set -x


COMMIT=$1

echo "Preparing data for commit $COMMIT..."

# I need two pieces of data:
# - the "test coverage map" from the commit before $COMMIT, which is what rust-test-runner.sh produces
# - the files modified in $COMMIT (in the future, maybe the functions too)
#
# This would accurately represent the situation where we know the coverage data from the last commit, but want to figure
# out what to run for tests in this commit.

# For the "test coverage map"; checkout the commit from before $COMMIT and generate it.

git archive --format=tgz --output=archive-pre-$COMMIT.tgz $COMMIT^

rm -rf tmp-$COMMIT
mkdir -p tmp-$COMMIT
pushd tmp-$COMMIT

tar -xvf ../archive-pre-$COMMIT.tgz
rm ../archive-pre-$COMMIT.tgz
../rust-test-runner.sh

# tar -jcvf ../coverage-output-pre-$COMMIT.tar.bz2 coverage-output
7z a ../coverage-output-pre-$COMMIT.7z coverage-output

# That concludes the "test coverage map"; now I just need to know what files were affected.  That's easy:
git diff --name-only $COMMIT^ $COMMIT > ../coverage-files-changed-$COMMIT.txt

popd
# rm -rf tmp-$COMMIT # Need to keep this around for the test binaries
