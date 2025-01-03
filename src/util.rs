// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{fmt, ops::RangeInclusive, time::Duration};

use serde::{
    Deserializer, Serializer,
    de::{self, Visitor},
};

pub fn duration_to_seconds<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

/// Deserializes a string "n-m" into a Range<u16>{ start: n, end: m}
pub fn inline_range<'de, D>(deserializer: D) -> Result<RangeInclusive<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RangeVisitor;

    impl Visitor<'_> for RangeVisitor {
        type Value = RangeInclusive<u16>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a range specified as 'start-end'")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let parts: Vec<&str> = value.split('-').collect();
            if parts.len() != 2 {
                return Err(E::custom("expected a range with exactly two parts"));
            }

            let start = parts[0]
                .parse::<u16>()
                .map_err(|_| E::custom("invalid start value"))?;
            let end = parts[1]
                .parse::<u16>()
                .map_err(|_| E::custom("invalid end value"))?;

            Ok(start..=end)
        }
    }

    deserializer.deserialize_str(RangeVisitor)
}
