-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

UPDATE coverage_map SET last_read_timestamp = now() WHERE last_read_timestamp IS NULL;
ALTER TABLE coverage_map
    ALTER COLUMN last_read_timestamp SET DEFAULT now(),
    ALTER COLUMN last_read_timestamp SET NOT NULL;
