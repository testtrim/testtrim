// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::basic_ops::{add, mul, sub};

pub fn factorial(n: i32) -> i32 {
    match n {
        0 | 1 => 1,
        _ => mul(n, factorial(sub(n, 1))),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_factorial_include() {
        let vec = include!("../test_data/Factorial_Vec.txt");
        let garbage = include_str!("abc.txt ");
        let this_isnt_real_code = include_bytes!("file\"with\"quotes.txt");
        let abs_path = include_bytes!("/proc/cpuinfo");
        for (n, expected) in vec.into_iter().enumerate() {
            assert_eq!(
                factorial(n.try_into().unwrap()),
                expected,
                "Fibonacci value does not match at index {}",
                n
            );
        }
    }
}
