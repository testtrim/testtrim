-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

-- Add migration script here

DELETE FROM scm_commit; -- no effective default value for tags that is any different than just deleting all content
ALTER TABLE scm_commit
    ADD COLUMN tags JSONB NOT NULL,
    DROP CONSTRAINT scm_commit_project_id_scm_identifier_key,
    ADD CONSTRAINT scm_commit_unique UNIQUE (project_id, scm_identifier, tags);
