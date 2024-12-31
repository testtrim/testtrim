-- SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

ALTER TABLE coverage_map
    ALTER COLUMN last_read_timestamp DROP DEFAULT,
    ALTER COLUMN last_read_timestamp SET NULL;
