CREATE TABLE coverage_data (
  commit_sha TEXT NOT NULL PRIMARY KEY,

  -- FIXME: would like this to be 'jsonb', but Diesel gives error "Unsupported type: jsonb".  I guess it introspects the
  -- DB after a migration to generate src/schema.rs.  I can live with this being text for now, but it could be fun to
  -- enhance Diesel in the future.
  raw_coverage_data TEXT NOT NULL
);
