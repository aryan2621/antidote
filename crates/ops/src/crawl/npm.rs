use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

use super::Item;
use crate::http;
use crate::state::State;

const REPLICATE: &str = "https://replicate.npmjs.com";

/// Changed package names whose name mentions MCP, and the feed's `last_seq`.
/// MCP servers without "mcp" in the name are covered by the MCP-registry crawl.
pub fn parse_changes(page: &Value) -> (Vec<String>, Option<u64>) {
    let names = page["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["id"].as_str())
        .filter(|id| id.to_ascii_lowercase().contains("mcp"))
        .map(String::from)
        .collect();
    (names, page["last_seq"].as_u64())
}

/// Walk the replication `_changes` feed since the last run (1–2 requests per hour of npm traffic),
/// then resolve each MCP-named package's latest version.
pub fn crawl(state: &mut State, limit: usize) -> Result<Vec<Item>> {
    refresh_popular(state);
    let mut seq: u64 = match state.cursors.get("npm").and_then(|s| s.parse().ok()) {
        Some(s) => s,
        // first run starts at "now"; history is the corpus's job, not the crawler's
        None => http::get_json(&format!("{REPLICATE}/"))?["update_seq"].as_u64().context("no update_seq")?,
    };
    let mut names = Vec::new();
    for _ in 0..50 {
        let page = http::get_json(&format!("{REPLICATE}/_changes?since={seq}&limit=10000"))?;
        let (found, last) = parse_changes(&page);
        names.extend(found);
        match last {
            Some(l) if l > seq => seq = l,
            _ => break,
        }
        if page["results"].as_array().is_none_or(|r| r.len() < 10_000) {
            break;
        }
    }
    names.sort();
    names.dedup();

    let mut out = Vec::new();
    let mut truncated = false;
    for name in names {
        if out.len() >= limit {
            truncated = true;
            break;
        }
        let doc = match http::get_json(&format!("https://registry.npmjs.org/{}", name.replace('/', "%2F"))) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("npm {name}: {e:#}");
                continue;
            }
        };
        // unpublished packages have no dist-tags
        let Some(version) = doc["dist-tags"]["latest"].as_str() else { continue };
        let item = Item { source: "npm".into(), ecosystem: "npm".into(), name, version: version.into(), download: None };
        if state.is_new(&item.key(), &item.version) {
            out.push(item);
        }
    }
    // if `limit` cut us short, replay the same changes next run (seen versions are skipped)
    if !truncated {
        state.cursors.insert("npm".into(), seq.to_string());
    }
    Ok(out)
}

/// Top ~500 MCP packages by popularity, for typosquat checks. Best effort: keeps the old list on failure.
fn refresh_popular(state: &mut State) {
    let mut names = Vec::new();
    for from in [0, 250] {
        let url = format!("https://registry.npmjs.org/-/v1/search?text=keywords:mcp&size=250&from={from}&popularity=1.0&quality=0&maintenance=0");
        match http::get_json(&url) {
            Ok(page) => names.extend(page["objects"].as_array().into_iter().flatten().filter_map(|o| o["package"]["name"].as_str().map(String::from))),
            Err(e) => {
                eprintln!("npm popular list not refreshed: {e:#}");
                return;
            }
        }
        sleep(Duration::from_secs(1));
    }
    if !names.is_empty() {
        state.popular.insert("npm".into(), names);
    }
}

/// Tarball URL and `sha512-<base64>` integrity for one version.
pub struct Meta {
    pub tarball: String,
    pub integrity: Option<String>,
    /// when the package (not this version) was first published
    pub created: Option<String>,
}

pub fn meta(name: &str, version: &str) -> Result<Meta> {
    // scoped names keep the `@` but encode the slash
    let doc = http::get_json(&format!("https://registry.npmjs.org/{}", name.replace('/', "%2F")))?;
    parse_meta(&doc, version)
}

pub fn parse_meta(doc: &Value, version: &str) -> Result<Meta> {
    let v = &doc["versions"][version];
    Ok(Meta {
        tarball: v["dist"]["tarball"].as_str().with_context(|| format!("no tarball for {version}"))?.to_string(),
        integrity: v["dist"]["integrity"].as_str().map(String::from),
        created: doc["time"]["created"].as_str().map(String::from),
    })
}
