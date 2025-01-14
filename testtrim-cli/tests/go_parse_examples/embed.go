// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package server

import "embed"

//go:embed file1.txt
//go:embed file2.txt file3.txt
//go:embed dir1
//go:embed dir2/*.txt
//go:embed "dir \"3\""
//go:embed `dir "4"`
var content embed.FS
