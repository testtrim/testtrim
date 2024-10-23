<!--
SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>

SPDX-License-Identifier: GPL-3.0-or-later
-->

testtrim targets software automated tests for execution based upon previous code-coverage data and git changes.  It's in early development, but it's looking quite promising with evaluations showing that on-average 90% of tests can be safely skipped with this strategy.

I've also published an introductory video (in two formats):

[Short Introduction Video, 10 minutes](https://youtu.be/wNPeTxf3xFw)

[Deep-dive Introduction Video, 37 minutes](https://youtu.be/YQKc58dTR1M)

# testtrim's Equation

1. Just like you would use to report test coverage (eg. "75% of our code is tested!"), run tests with a coverage tool.  But rather than running the entire test suite and reporting generalized coverage, run each individual test to get the coverage for each test.

2. Invert the data; change "test case touches code" into "code was touched by test case", and then store it into a database.

3. Look at a source control diff since the last time you did #2 to find out what changes occurred to the code, then look them up in the database to see what test cases need to be run.

This is the core concept behind [testtrim](https://codeberg.org/testtrim/testtrim).

# How well does it work?

It's early days for testtrim.

## alacritty evaluation

To evaluate how well it worked, I took an Open Source project ([alacritty](https://github.com/alacritty/alacritty)), and I ran the last 100 commits through testtrim.  testtrim has a command `simulate-history` that does this automatically and generates a CSV file with the output data, which can be easily analyzed:

| # Commits:                           |       100 |
|--------------------------------------|----------:|
| # Commits Successful Build & Test:   |        83 |
| # Commits Analyzed w/ Ancestor Data: |        82 |
| Average Tests to Run per Commit:     | **14.5%** |
| Median Tests to Run per Commit:      |  **1.6%** |
| P90 Tests to Run per Commit:         | **54.6%** |

For each commit, testtrim identified that an average of only 14.5% of tests needed to be executed to fully test the code change that was being made.

I could list a dozen reasons why this analysis isn't generalizable... and so I will:

- alacritty is a pretty mature project that isn't undergoing rapid development.
- alacritty has some tests that work through reading static files; changes to those files wouldn't be considered as requiring reruns of the related tests because they don't appear in code coverage and testtrim doesn't do anything else to compensate for that.
- There's no evidence that a test on a single project will generalize to lots of other projects.
- The only guarantee of correctness in this analysis is my own eyeballing of the changes and proposed tests.

## ripgrep evaluation

The same evaluation was performed on [ripgrep](https://github.com/BurntSushi/ripgrep), which has a slightly larger test base (>1000 unit tests) than alacritty, using the `simulate-history` command on the past 100 commits:

| # Commits:                           |       100 |
|--------------------------------------|----------:|
| # Commits Successful Build & Test:   |       100 |
| # Commits Analyzed w/ Ancestor Data: |        99 |
| Average Tests to Run per Commit:     |  **6.0%** |
| Median Tests to Run per Commit:      |  **0.0%** |
| P90 Tests to Run per Commit:         | **12.7%** |

These results are also great, but suffer from some of the same reasons listed above for why it may not be generalizable to every project

Between the results of both projects, I think it's **promising**, but not **promised**.

# How to use?

Oh, well, I'm not quite sure I'd recommend that right now.  But it could be fun to experiment with.

- Clone the git repo:
    ```
    git clone https://codeberg.org/testtrim/testtrim.git
    ```

- Build the project with `cargo`; might as well use the release mode for optimizations:
    ```
    cargo build --release
    ```

- Change directory into a Rust project that you'd like to test.

- Using the built testtrim binary from wherever you put the repo, run the `run-tests` command.

    **Clean working directory**: run at least once with a clean working directory and verify that the output says `save_coverage_data: true` in order to get a baseline for future runs.

    Use `-vv` for verbose output.

    Example:

    ```
    $ ~/Dev/testtrim/target/release/testtrim run-tests -vv
    19:11:19 [INFO] source_mode: Automatic, save_coverage_data: true, ancestor_search_mode: SkipHeadCommit
    19:11:19 [WARN] no base commit identified with coverage data to work from
    19:11:19 [INFO] successfully ran tests
    ```

- Make some changes to your project, and rerun testtrim.

    ```
    $ ~/Dev/testtrim/target/release/testtrim run-tests -vv
    19:12:05 [INFO] source_mode: Automatic, save_coverage_data: false, ancestor_search_mode: AllCommits
    19:12:06 [INFO] relevant test cases will be computed base upon commit "c15667fe0655a2fcb43b4c88cd900ede3921f23c"
    relevant test cases are 2 of 8, 25%
    19:12:06 [INFO] successfully ran tests
    ```

    Hopefully you'll see the output "relevant test cases" which indicates how many tests were relevant for the change you made.

- Note that testtrim will pollute your home directory with `~/testtrim.db` that could grow quite large, quite quickly.
