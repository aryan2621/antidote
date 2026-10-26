use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{Item, Tool};
use crate::http;
use crate::state::State;

const API: &str = "https://api.smithery.ai";

fn key() -> Option<String> {
    std::env::var("SMITHERY_API_KEY").ok().filter(|k| !k.is_empty())
}

/// `(qualifiedName, createdAt)` per server in one list page, plus whether more pages follow.
pub fn parse_list(page: &Value) -> (Vec<(String, String)>, bool) {
    let servers = page["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s["qualifiedName"].as_str()?.to_string(), s["createdAt"].as_str().unwrap_or("").to_string())))
        .collect();
    let p = &page["pagination"];
    let more = p["currentPage"].as_u64().unwrap_or(0) < p["totalPages"].as_u64().unwrap_or(0);
    (servers, more)
}

/// One server's detail as an item. Smithery has no versions, so the version is a hash of what an
/// agent would get (stdio bundle + tool descriptions): a changed description is a new version.
pub fn parse_server(s: &Value) -> Option<Item> {
    let name = s["qualifiedName"].as_str()?.to_string();
    let bundle = s["connections"].as_array().into_iter().flatten().find(|c| c["type"] == "stdio").and_then(|c| c["bundleUrl"].as_str()).map(String::from);
    let tools: Vec<Tool> = s["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| Some(Tool { name: t["name"].as_str()?.into(), description: t["description"].as_str().unwrap_or("").into() }))
        .collect();
    let mut h = Sha256::new();
    h.update(bundle.as_deref().unwrap_or(""));
    for t in &tools {
        h.update([0]);
        h.update(&t.name);
        h.update([0]);
        h.update(&t.description);
    }
    let version = format!("{:x}", h.finalize())[..16].to_string();
    Some(Item { source: "smithery".into(), ecosystem: "smithery".into(), name, version, download: bundle, tools: Some(tools) })
}

pub fn fetch(name: &str) -> Result<Item> {
    let k = key().context("SMITHERY_API_KEY is not set")?;
    let s = http::get_json_auth(&format!("{API}/servers/{}", http::enc(name)), Some("application/json"), Some(&k))?;
    parse_server(&s).context("Smithery server without qualifiedName")
}

/// Servers not analyzed yet, newest first. The list has no sort order or change feed, so every
/// run pages through all of it; a server whose detail fetch fails is simply retried next run.
// shortcut: servers already analyzed are not re-fetched, so later tool-description changes are
// only caught by `antidote inspect`/`guard` on users' machines; re-check old servers in rotation if needed.
pub fn crawl(state: &mut State, limit: usize) -> Result<Vec<Item>> {
    let Some(k) = key() else {
        eprintln!("smithery: SMITHERY_API_KEY not set, skipping");
        return Ok(vec![]);
    };
    let mut fresh = Vec::new();
    for page in 1.. {
        let url = format!("{API}/servers?pageSize=100&page={page}");
        let (servers, more) = parse_list(&http::get_json_auth(&url, Some("application/json"), Some(&k))?);
        fresh.extend(servers.into_iter().filter(|(n, _)| !state.seen.contains_key(&format!("smithery:{n}"))));
        if !more {
            break;
        }
    }
    fresh.sort_by(|a, b| b.1.cmp(&a.1));
    let mut out = Vec::new();
    for (name, _) in fresh.into_iter().take(limit) {
        match fetch(&name) {
            Ok(i) => out.push(i),
            Err(e) => eprintln!("smithery: skip {name}: {e:#}"),
        }
    }
    Ok(out)
}
