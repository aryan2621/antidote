use anyhow::{Context, Result};
use include_dir::{include_dir, Dir};
use serde::Deserialize;

// shortcut: corpus is baked into the binary, add `antidote update` + signed feed in phase 2.
static CORPUS: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../corpus");

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
    pub entries: Vec<Entry>,
    pub rules: yara_x::Rules,
}

pub fn load() -> Result<Corpus> {
    let mut entries = Vec::new();
    for f in CORPUS.get_dir("entries").map(|d| d.files()).into_iter().flatten() {
        entries.push(
            serde_json::from_slice(f.contents())
                .with_context(|| format!("corpus entry {}", f.path().display()))?,
        );
    }
    let mut compiler = yara_x::Compiler::new();
    for f in CORPUS.get_dir("rules").map(|d| d.files()).into_iter().flatten() {
        let name = f.path().file_stem().unwrap().to_string_lossy();
        compiler.new_namespace(&name);
        compiler
            .add_source(f.contents_utf8().context("rule file not utf-8")?)
            .with_context(|| format!("compiling {}", f.path().display()))?;
    }
    Ok(Corpus { entries, rules: compiler.build() })
}
