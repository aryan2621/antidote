pub mod clawhub;
pub mod github;
pub mod mcp_registry;
pub mod npm;
pub mod pypi;
pub mod smithery;

use serde::{Deserialize, Serialize};

/// One artifact version to analyze.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Item {
    pub source: String,
    /// corpus ecosystem: npm | PyPI | clawhub | smithery | GitHub
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Where the archive comes from; resolved lazily for npm/PyPI (needs a metadata fetch).
    pub download: Option<String>,
    /// MCP tools as `[{name, description}]` when the registry lists them (Smithery); scanned as text
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

impl Item {
    pub fn key(&self) -> String {
        format!("{}:{}", self.ecosystem, self.name)
    }
}
