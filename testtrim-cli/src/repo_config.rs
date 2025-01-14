// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;

use anyhow::Result;
use serde::Deserialize;

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RepoConfig {
    network_policy: Vec<crate::network::Policy>,
}

impl RepoConfig {
    pub fn network_policy(&self) -> &[crate::network::Policy] {
        &self.network_policy
    }
}

pub fn get_repo_config() -> Result<RepoConfig> {
    let path = ".config/testtrim.toml";
    if fs::exists(path)? {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    } else {
        Ok(RepoConfig::default())
    }
}
