-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

ALTER TABLE scm_commit
DROP CONSTRAINT scm_commit_ancestor_scm_commit_id_fkey;

ALTER TABLE scm_commit
ADD CONSTRAINT scm_commit_ancestor_scm_commit_id_fkey
    FOREIGN KEY (ancestor_scm_commit_id)
    REFERENCES scm_commit (id)
    ON DELETE CASCADE;
