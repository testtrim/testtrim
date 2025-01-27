// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;

use anyhow::{Result, anyhow};
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

pub fn get_repo_config(override_config: Option<&String>) -> Result<RepoConfig> {
    let path = match override_config {
        Some(path) => path,
        None => ".config/testtrim.toml",
    };
    // let path = ".config/testtrim.toml";
    if fs::exists(path)? {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    } else {
        if let Some(override_config) = override_config {
            return Err(anyhow!(
                "override config path {override_config} could not be opened"
            ));
        }
        Ok(RepoConfig::default())
    }
}
