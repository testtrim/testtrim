-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

-- can't drop a unique constraint in SQLite, so, just rebuild the table and related tables...
DROP TABLE scm_commit;
DROP TABLE commit_test_case;
DROP TABLE commit_test_case_executed;
DROP TABLE commit_file_reference;
DROP TABLE coverage_map;
DROP TABLE coverage_map_test_case_executed;

CREATE TABLE scm_commit (
    id TEXT PRIMARY KEY NOT NULL, -- ideally should be UUID
    project_id TEXT REFERENCES project (id) NOT NULL, -- ideally should be UUID
    ancestor_scm_commit_id TEXT REFERENCES scm_commit (id) NULL, -- ideally should be UUID
    -- Ideally this would be JSON -- support in Diesel incoming https://github.com/diesel-rs/diesel/blob/381be195688db339fe2927e49bc818ab86754dd9/CHANGELOG.md?plain=1#L23
    scm_identifier TEXT NOT NULL,
    -- Ideally this would be JSON -- support in Diesel incoming https://github.com/diesel-rs/diesel/blob/381be195688db339fe2927e49bc818ab86754dd9/CHANGELOG.md?plain=1#L23
    tags TEXT NOT NULL,
    UNIQUE (project_id, scm_identifier, tags)
);

CREATE TABLE commit_test_case (
    scm_commit_id TEXT REFERENCES scm_commit (id) NOT NULL, -- ideally should be UUID
    test_case_id TEXT REFERENCES test_case (id) NOT NULL, -- ideally should be UUID
    PRIMARY KEY (scm_commit_id, test_case_id)
);

CREATE TABLE commit_test_case_executed (
    scm_commit_id TEXT REFERENCES scm_commit (id) NOT NULL, -- ideally should be UUID
    test_case_execution_id TEXT REFERENCES test_case_execution (id) NOT NULL, -- ideally should be UUID
    PRIMARY KEY (scm_commit_id, test_case_execution_id)
);

CREATE TABLE commit_file_reference (
    id TEXT PRIMARY KEY NOT NULL, -- ideally should be UUID
    scm_commit_id TEXT REFERENCES scm_commit (id) NOT NULL, -- ideally should be UUID
    referencing_filepath TEXT NOT NULL,
    target_filepath TEXT NOT NULL,
    UNIQUE (scm_commit_id, referencing_filepath, target_filepath)
);

CREATE TABLE coverage_map (
    id TEXT PRIMARY KEY NOT NULL, -- ideally should be UUID
    scm_commit_id TEXT REFERENCES scm_commit (id) NOT NULL UNIQUE, -- ideally should be UUID
    last_read_timestamp TIMESTAMP NULL -- unix epoch time
);

CREATE TABLE coverage_map_test_case_executed (
    coverage_map_id TEXT REFERENCES coverage_map (id) NOT NULL, -- ideally should be UUID
    test_case_execution_id TEXT REFERENCES test_case_execution (id) NOT NULL, -- ideally should be UUID
    PRIMARY KEY (coverage_map_id, test_case_execution_id)
);
