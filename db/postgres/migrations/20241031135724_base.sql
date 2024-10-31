-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

-- Normalized data representing a testtrim run on a commit...

CREATE EXTENSION "uuid-ossp"; -- not directly used in schema (maybe in future for defaults), but used in inserts

CREATE TABLE project (
    id UUID PRIMARY KEY NOT NULL
);

CREATE TABLE scm_commit (
    id UUID PRIMARY KEY NOT NULL,
    project_id UUID NOT NULL
        REFERENCES project (id)
        ON DELETE CASCADE,
    ancestor_scm_commit_id UUID NULL
        REFERENCES scm_commit (id)
        ON DELETE RESTRICT,
    scm_identifier JSONB NOT NULL,
    UNIQUE (project_id, scm_identifier)
);

CREATE TABLE test_case (
    id UUID PRIMARY KEY NOT NULL,
    project_id UUID NOT NULL
        REFERENCES project (id)
        ON DELETE CASCADE,
    test_identifier JSONB NOT NULL,
    UNIQUE (project_id, test_identifier)
);

CREATE TABLE commit_test_case (
    scm_commit_id UUID NOT NULL
        REFERENCES scm_commit (id)
        ON DELETE CASCADE,
    test_case_id UUID NOT NULL
        REFERENCES test_case (id)
        ON DELETE CASCADE,
    PRIMARY KEY (scm_commit_id, test_case_id)
);

CREATE TABLE test_case_execution (
    id UUID PRIMARY KEY NOT NULL,
    test_case_id UUID NOT NULL
        REFERENCES test_case (id)
        ON DELETE CASCADE
);

CREATE TABLE commit_test_case_executed (
    scm_commit_id UUID NOT NULL
        REFERENCES scm_commit (id)
        ON DELETE CASCADE,
    test_case_execution_id UUID NOT NULL
        REFERENCES test_case_execution (id)
        ON DELETE CASCADE,
    PRIMARY KEY (scm_commit_id, test_case_execution_id)
);

CREATE TABLE test_case_file_covered (
    test_case_execution_id UUID NOT NULL
        REFERENCES test_case_execution (id)
        ON DELETE CASCADE,
    file_identifier JSONB NOT NULL,
    PRIMARY KEY (test_case_execution_id, file_identifier)
);

CREATE TABLE test_case_function_covered (
    test_case_execution_id UUID NOT NULL
        REFERENCES test_case_execution (id)
        ON DELETE CASCADE,
    function_identifier JSONB NOT NULL,
    PRIMARY KEY (test_case_execution_id, function_identifier)
);

CREATE TABLE test_case_coverage_identifier_covered (
    test_case_execution_id UUID NOT NULL
        REFERENCES test_case_execution (id)
        ON DELETE CASCADE,
    coverage_identifier JSONB NOT NULL,
    PRIMARY KEY (test_case_execution_id, coverage_identifier)
);

-- This is likely to be much smaller than the test-case -> {file,function} maps, so it's much simpler -- a complete
-- record of all known cross-file references at a specific commit.
CREATE TABLE commit_file_reference (
    id UUID PRIMARY KEY NOT NULL,
    scm_commit_id UUID NOT NULL
        REFERENCES scm_commit (id)
        ON DELETE CASCADE,
    referencing_filepath TEXT NOT NULL,
    target_filepath TEXT NOT NULL,
    UNIQUE (scm_commit_id, referencing_filepath, target_filepath)
);

-- Denormalized data allowing for the quick and (hopefully) efficient lookup of test cases that need to be run...

CREATE TABLE coverage_map (
    id UUID PRIMARY KEY NOT NULL,
    scm_commit_id UUID NOT NULL UNIQUE
        REFERENCES scm_commit (id)
        ON DELETE CASCADE,
    last_read_timestamp TIMESTAMP NULL -- unix epoch time
);

CREATE TABLE coverage_map_test_case_executed (
    coverage_map_id UUID NOT NULL
        REFERENCES coverage_map (id)
        ON DELETE CASCADE,
    test_case_execution_id UUID NOT NULL
        REFERENCES test_case_execution (id)
        ON DELETE CASCADE,
    PRIMARY KEY (coverage_map_id, test_case_execution_id)
);
