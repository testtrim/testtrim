use diesel::prelude::*;

#[derive(Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::coverage_data)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct CoverageDataModel {
    pub commit_sha: String,
    pub raw_coverage_data: String,
}
