use anyhow::{Context, Result};
use serde::Deserialize;

use crate::feed::{self, Feed};

#[derive(Deserialize)]
pub struct Entry {
    pub id: String,
    pub summary: String,
    #[serde(default)]
    pub affected: Vec<Affected>,
    pub database_specific: Option<DbSpecific>,
}

#[derive(Deserialize)]
pub struct Affected {
    pub package: Package,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ranges: Vec<Range>,
}

#[derive(Deserialize)]
pub struct Range {
    pub events: Vec<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct DbSpecific {
    pub classification: String,
    #[serde(default)]
    pub indicators: Indicators,
}

#[derive(Deserialize, Default)]
pub struct Indicators {
    #[serde(default)]
    pub sha256: Vec<String>,
}

impl Entry {
    pub fn severity(&self) -> &'static str {
        match self.database_specific.as_ref().map(|d| d.classification.as_str()) {
            Some("malicious") => "critical",
            Some("vulnerable") => "high",
            _ => "medium",
        }
    }
}

pub struct Corpus {
    pub version: u64,
    pub entries: Vec<Entry>,
    pub rules: yara_x::Rules,
    /// prompt-injection classifier; None if the feed has none or the user turned it off
    pub model: Option<crate::classify::Model>,
}

/// The newest verified corpus: cached feed from `antidote update`, else the built-in one.
pub fn load() -> Result<Corpus> {
    let embedded = Feed::embedded();
    compile(&feed::cached(embedded.version).unwrap_or(embedded))
}

pub fn compile(feed: &Feed) -> Result<Corpus> {
    let mut entries = Vec::new();
    for e in &feed.entries {
        let id = e["id"].as_str().unwrap_or("?");
        entries.push(serde_json::from_value(e.clone()).with_context(|| format!("corpus entry {id}"))?);
    }
    let mut compiler = yara_x::Compiler::new();
    for (name, src) in &feed.rules {
        compiler.new_namespace(name);
        compiler.add_source(src.as_str()).with_context(|| format!("compiling rules/{name}.yar"))?;
    }
    // shortcut: last by name wins, which breaks at injection-v10; pick by parsed version then.
    let model = match feed.models.iter().next_back() {
        Some((name, src)) => Some(crate::classify::Model::from_json(src).with_context(|| format!("model {name}"))?),
        None => None,
    };
    Ok(Corpus { version: feed.version, entries, rules: compiler.build(), model })
}
