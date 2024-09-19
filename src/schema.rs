// @generated automatically by Diesel CLI.

diesel::table! {
    coverage_data (commit_sha) {
        commit_sha -> Text,
        raw_coverage_data -> Text,
    }
}
