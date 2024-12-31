// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

// @generated automatically by Diesel CLI.

diesel::table! {
    commit_file_reference (id) {
        id -> Text,
        scm_commit_id -> Text,
        referencing_filepath -> Text,
        target_filepath -> Text,
    }
}

diesel::table! {
    commit_test_case (scm_commit_id, test_case_id) {
        scm_commit_id -> Text,
        test_case_id -> Text,
    }
}

diesel::table! {
    commit_test_case_executed (scm_commit_id, test_case_execution_id) {
        scm_commit_id -> Text,
        test_case_execution_id -> Text,
    }
}

diesel::table! {
    coverage_map (id) {
        id -> Text,
        scm_commit_id -> Text,
        last_read_timestamp -> Timestamp,
    }
}

diesel::table! {
    coverage_map_test_case_executed (coverage_map_id, test_case_execution_id) {
        coverage_map_id -> Text,
        test_case_execution_id -> Text,
    }
}

diesel::table! {
    project (id) {
        id -> Text,
        name -> Text,
    }
}

diesel::table! {
    scm_commit (id) {
        id -> Text,
        project_id -> Text,
        ancestor_scm_commit_id -> Nullable<Text>,
        scm_identifier -> Text,
        tags -> Text,
    }
}

diesel::table! {
    test_case (id) {
        id -> Text,
        project_id -> Text,
        test_identifier -> Text,
    }
}

diesel::table! {
    test_case_coverage_identifier_covered (test_case_execution_id, coverage_identifier) {
        test_case_execution_id -> Text,
        coverage_identifier -> Text,
    }
}

diesel::table! {
    test_case_execution (id) {
        id -> Text,
        test_case_id -> Text,
    }
}

diesel::table! {
    test_case_file_covered (test_case_execution_id, file_identifier) {
        test_case_execution_id -> Text,
        file_identifier -> Text,
    }
}

diesel::table! {
    test_case_function_covered (test_case_execution_id, function_identifier) {
        test_case_execution_id -> Text,
        function_identifier -> Text,
    }
}

diesel::joinable!(commit_file_reference -> scm_commit (scm_commit_id));
diesel::joinable!(commit_test_case -> scm_commit (scm_commit_id));
diesel::joinable!(commit_test_case -> test_case (test_case_id));
diesel::joinable!(commit_test_case_executed -> scm_commit (scm_commit_id));
diesel::joinable!(commit_test_case_executed -> test_case_execution (test_case_execution_id));
diesel::joinable!(coverage_map -> scm_commit (scm_commit_id));
diesel::joinable!(coverage_map_test_case_executed -> coverage_map (coverage_map_id));
diesel::joinable!(coverage_map_test_case_executed -> test_case_execution (test_case_execution_id));
diesel::joinable!(scm_commit -> project (project_id));
diesel::joinable!(test_case -> project (project_id));
diesel::joinable!(test_case_coverage_identifier_covered -> test_case_execution (test_case_execution_id));
diesel::joinable!(test_case_execution -> test_case (test_case_id));
diesel::joinable!(test_case_file_covered -> test_case_execution (test_case_execution_id));
diesel::joinable!(test_case_function_covered -> test_case_execution (test_case_execution_id));

diesel::allow_tables_to_appear_in_same_query!(
    commit_file_reference,
    commit_test_case,
    commit_test_case_executed,
    coverage_map,
    coverage_map_test_case_executed,
    project,
    scm_commit,
    test_case,
    test_case_coverage_identifier_covered,
    test_case_execution,
    test_case_file_covered,
    test_case_function_covered,
);
