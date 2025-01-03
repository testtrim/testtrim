// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::cmp::Ordering;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};

#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

impl std::str::FromStr for Tag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(2, '=').collect();
        if parts.len() == 2 {
            Ok(Tag {
                key: parts[0].to_owned(),
                value: parts[1].to_owned(),
            })
        } else {
            Err(format!("Invalid key-value pair: {s}"))
        }
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

/// `TagArray` serializes an array of Tags into json as `{key: value, ...}` rather than `[{key, value}]`
pub struct TagArray<'a>(pub &'a [Tag]);

impl Serialize for TagArray<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for kv in self.0 {
            map.serialize_entry(&kv.key, &kv.value)?;
        }
        map.end()
    }
}

/// `SortedTagArray` serializes an array of Tags into json as `{key: value, ...}` rather than `[{key, value}]`, and
/// guarantees consistent order of the map values
pub struct SortedTagArray<'a>(pub &'a [Tag]);

impl Serialize for SortedTagArray<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // This is a bit ugly because the
        let mut sorted = Vec::from(self.0);
        sorted.sort(); // Sorting by key

        let mut map = serializer.serialize_map(Some(sorted.len()))?;
        for kv in sorted {
            map.serialize_entry(&kv.key, &kv.value)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_key_values() {
        let key_values = vec![
            Tag {
                key: "xyz".to_string(),
                value: "789".to_string(),
            },
            Tag {
                key: "abc".to_string(),
                value: "123".to_string(),
            },
            Tag {
                key: "def".to_string(),
                value: "456".to_string(),
            },
        ];
        let wrapped_key_values = SortedTagArray(&key_values);
        let serialized = serde_json::to_string(&wrapped_key_values).unwrap();

        assert_eq!(serialized, r#"{"abc":"123","def":"456","xyz":"789"}"#);
    }
}
