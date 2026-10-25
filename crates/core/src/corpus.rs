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
    /// overrides the classification default, e.g. a low-severity CVE
    #[serde(default)]
    pub severity: Option<String>,
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
        if let Some(s) = self.database_specific.as_ref().and_then(|d| d.severity.as_deref()) {
            if let Some(s) = ["critical", "high", "medium", "low"].into_iter().find(|x| *x == s) {
                return s;
            }
        }
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
    /// ecosystem (lowercase) → popular package names, for typosquat checks
    pub popular: std::collections::BTreeMap<String, Vec<String>>,
    /// tree-sitter code rules
    pub code: Vec<crate::code::Rule>,
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
    let mut code = Vec::new();
    for (name, src) in &feed.queries {
        code.extend(crate::code::compile(name, src)?);
    }
    Ok(Corpus { version: feed.version, entries, rules: compiler.build(), model, popular: feed.popular.clone(), code })
}

/// UTC (year, month, day).
pub fn today() -> (i64, u32, u32) {
    let days = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 / 86_400;
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Next free id with `prefix` (e.g. `AGT-2026-`, `AGT-INC-2026-`) in a corpus entries dir.
pub fn next_id(entries_dir: &std::path::Path, prefix: &str) -> Result<String> {
    let mut max = 0;
    for e in std::fs::read_dir(entries_dir)? {
        let name = e?.file_name().to_string_lossy().into_owned();
        if let Some(n) = name.strip_prefix(prefix).and_then(|s| s.strip_suffix(".json")).and_then(|s| s.parse::<u32>().ok()) {
            max = max.max(n);
        }
    }
    Ok(format!("{prefix}{:04}", max + 1))
}
