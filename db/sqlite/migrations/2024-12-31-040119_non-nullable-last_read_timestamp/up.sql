-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

ALTER TABLE coverage_map DROP COLUMN last_read_timestamp;
ALTER TABLE coverage_map ADD COLUMN last_read_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL;
