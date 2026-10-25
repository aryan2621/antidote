use anyhow::Result;
use serde_json::Value;

use super::Item;
use crate::http;
use crate::state::State;

const API: &str = "https://registry.modelcontextprotocol.io/v0.1/servers";

/// npm / PyPI packages behind servers in one page; remote-only servers have nothing to download.
pub fn parse_page(page: &Value) -> (Vec<Item>, Option<String>, Option<String>) {
    let mut items = Vec::new();
    let mut newest: Option<String> = None;
    for s in page["servers"].as_array().into_iter().flatten() {
        let meta = &s["_meta"]["io.modelcontextprotocol.registry/official"];
        if let Some(u) = meta["updatedAt"].as_str() {
            if newest.as_deref().is_none_or(|n| u > n) {
                newest = Some(u.to_string());
            }
        }
        // older versions are listed too; state tracks one version per package
        if meta["isLatest"] != true {
            continue;
        }
        for p in s["server"]["packages"].as_array().into_iter().flatten() {
            let (Some(name), Some(version)) = (p["identifier"].as_str(), p["version"].as_str()) else { continue };
            let ecosystem = match p["registryType"].as_str() {
                Some("npm") => "npm",
                Some("pypi") => "PyPI",
                _ => continue, // shortcut: OCI/nuget/cargo/mcpb not analyzed yet
            };
            items.push(Item {
                source: "mcp-registry".into(),
                ecosystem: ecosystem.into(),
                name: name.into(),
                version: version.into(),
                download: None,
            });
        }
    }
    let next = page["metadata"]["nextCursor"].as_str().map(String::from);
    (items, next, newest)
}

pub fn crawl(state: &mut State, limit: usize) -> Result<Vec<Item>> {
    let since = state.cursors.get("mcp-registry").cloned().unwrap_or_else(|| "2025-01-01T00:00:00Z".into());
    let (mut out, mut cursor, mut newest) = (Vec::new(), None::<String>, since.clone());
    let mut complete = false;
    loop {
        let mut url = format!("{API}?limit=100&updated_since={}", http::enc(&since));
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={}", http::enc(c)));
        }
        let (items, next, page_newest) = parse_page(&http::get_json(&url)?);
        out.extend(items.into_iter().filter(|i| state.is_new(&i.key(), &i.version)));
        if let Some(n) = page_newest.filter(|n| *n > newest) {
            newest = n;
        }
        match next {
            Some(_) if out.len() >= limit => break,
            Some(n) => cursor = Some(n),
            None => {
                complete = true;
                break;
            }
        }
    }
    for i in &out {
        if i.ecosystem == "PyPI" && !state.pypi_watch.contains(&i.name) {
            state.pypi_watch.push(i.name.clone());
        }
    }
    // pages are sorted by name, not time: only a full sweep may move `updated_since` forward,
    // otherwise the next run re-reads the same window and already-seen items no longer count
    if complete {
        state.cursors.insert("mcp-registry".into(), newest);
    }
    out.truncate(limit);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_recorded_page() {
        let page = serde_json::from_str(include_str!("../../tests/fixtures/mcp-registry/servers.json")).unwrap();
        let (items, next, newest) = super::parse_page(&page);
        let names: Vec<_> = items.iter().map(|i| format!("{}:{}@{}", i.ecosystem, i.name, i.version)).collect();
        assert_eq!(names, ["npm:@achromat-ai/mcp-server@0.1.2", "PyPI:bowmark-mcp@2.1.0", "npm:@bowmark/mcp@2.1.0"], "older 0.1.1 is skipped");
        assert!(next.is_some());
        assert!(newest.unwrap().starts_with("2026-"));
    }
}
