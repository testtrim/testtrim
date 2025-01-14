// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub root_pid: u32,
    pub actual_pid: u32,
    pub actual_tgid: u32,
    pub event_data: EventData,
}

#[derive(Debug)]
#[repr(C, u8)]
pub enum EventData {
    OpenAt {
        dirfd: i32,
        filename: [u8; 256],
        filename_len: usize,
    } = 0u8,
}
