-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

DELETE FROM scm_commit; -- no effective default value for tags that is any different than just deleting all content
ALTER TABLE scm_commit
    DROP CONSTRAINT scm_commit_unique,
    DROP COLUMN tags,
    DROP ADD CONSTRAINT scm_commit_project_id_scm_identifier_key UNIQUE (project_id, scm_identifier);
