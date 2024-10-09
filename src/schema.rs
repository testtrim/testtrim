// @generated automatically by Diesel CLI.

diesel::table! {
    commit_test_case (scm_commit_id, test_case_id) {
        scm_commit_id -> Text,
        test_case_id -> Text,
    }
}

diesel::table! {
    denormalized_coverage_map (id) {
        id -> Text,
        scm_commit_id -> Text,
        last_read_timestamp -> Nullable<Text>,
    }
}

diesel::table! {
    denormalized_coverage_map_test_case (id) {
        id -> Text,
        denormalized_coverage_map_id -> Text,
        test_case_id -> Text,
    }
}

diesel::table! {
    denormalized_coverage_map_test_case_file_covered (denormalized_coverage_map_test_case_id, file_identifier) {
        denormalized_coverage_map_test_case_id -> Text,
        file_identifier -> Text,
    }
}

diesel::table! {
    denormalized_coverage_map_test_case_function_covered (denormalized_coverage_map_test_case_id, function_identifier) {
        denormalized_coverage_map_test_case_id -> Text,
        function_identifier -> Text,
    }
}

diesel::table! {
    project (id) {
        id -> Text,
    }
}

diesel::table! {
    scm_commit (id) {
        id -> Text,
        project_id -> Text,
        ancestor_scm_commit_id -> Nullable<Text>,
        scm_identifier -> Text,
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
    test_case_execution (id) {
        id -> Text,
        test_case_id -> Text,
        scm_commit_id -> Text,
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

diesel::joinable!(commit_test_case -> scm_commit (scm_commit_id));
diesel::joinable!(commit_test_case -> test_case (test_case_id));
diesel::joinable!(denormalized_coverage_map -> scm_commit (scm_commit_id));
diesel::joinable!(denormalized_coverage_map_test_case -> denormalized_coverage_map (denormalized_coverage_map_id));
diesel::joinable!(denormalized_coverage_map_test_case -> test_case (test_case_id));
diesel::joinable!(denormalized_coverage_map_test_case_file_covered -> denormalized_coverage_map_test_case (denormalized_coverage_map_test_case_id));
diesel::joinable!(denormalized_coverage_map_test_case_function_covered -> denormalized_coverage_map_test_case (denormalized_coverage_map_test_case_id));
diesel::joinable!(scm_commit -> project (project_id));
diesel::joinable!(test_case -> project (project_id));
diesel::joinable!(test_case_execution -> scm_commit (scm_commit_id));
diesel::joinable!(test_case_execution -> test_case (test_case_id));
diesel::joinable!(test_case_file_covered -> test_case_execution (test_case_execution_id));
diesel::joinable!(test_case_function_covered -> test_case_execution (test_case_execution_id));

diesel::allow_tables_to_appear_in_same_query!(
    commit_test_case,
    denormalized_coverage_map,
    denormalized_coverage_map_test_case,
    denormalized_coverage_map_test_case_file_covered,
    denormalized_coverage_map_test_case_function_covered,
    project,
    scm_commit,
    test_case,
    test_case_execution,
    test_case_file_covered,
    test_case_function_covered,
);
