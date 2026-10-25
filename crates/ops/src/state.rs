use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Everything the crawler remembers between runs; lives on the `crawl-state` branch.
// shortcut: one JSON file, fine to ~50k packages; move to SQLite when load/save gets slow.
#[derive(Serialize, Deserialize, Default)]
pub struct State {
    /// source → opaque cursor / high-water mark
    #[serde(default)]
    pub cursors: BTreeMap<String, String>,
    /// "ecosystem:name" → last analyzed version
    #[serde(default)]
    pub seen: BTreeMap<String, Seen>,
    /// PyPI names learned from the MCP registry, watched in the RSS feeds
    #[serde(default)]
    pub pypi_watch: Vec<String>,
    /// ecosystem → most-downloaded names, for typosquat checks
    #[serde(default)]
    pub popular: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Seen {
    pub version: String,
    #[serde(default)]
    pub install_script: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub tools_hash: Option<String>,
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match fs::read(path) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(tmp, path)?; // atomic, so a killed job never leaves half a state file
        Ok(())
    }

    pub fn is_new(&self, key: &str, version: &str) -> bool {
        self.seen.get(key).is_none_or(|s| s.version != version)
    }
}
