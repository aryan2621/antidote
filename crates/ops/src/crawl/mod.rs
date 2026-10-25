pub mod clawhub;
pub mod mcp_registry;
pub mod npm;
pub mod pypi;

use serde::{Deserialize, Serialize};

/// One artifact version to analyze.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Item {
    pub source: String,
    /// corpus ecosystem: npm | PyPI | clawhub
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Where the archive comes from; resolved lazily for npm/PyPI (needs a metadata fetch).
    pub download: Option<String>,
}

impl Item {
    pub fn key(&self) -> String {
        format!("{}:{}", self.ecosystem, self.name)
    }
}
