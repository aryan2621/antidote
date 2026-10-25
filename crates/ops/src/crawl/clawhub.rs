use anyhow::Result;
use serde_json::Value;

use super::Item;
use crate::http;
use crate::state::State;

const API: &str = "https://clawhub.ai/api/v1";

/// Skills in one `sort=updated` page plus their `updatedAt` (ms since epoch).
pub fn parse_page(page: &Value) -> (Vec<(Item, u64)>, Option<String>) {
    let items = page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| {
            let slug = s["slug"].as_str()?;
            let owner = s["ownerHandle"].as_str()?;
            let version = s["latestVersion"]["version"].as_str()?;
            let item = Item {
                source: "clawhub".into(),
                ecosystem: "clawhub".into(),
                // slugs are not unique across publishers, and look-alike owners are the attack
                name: format!("{owner}/{slug}"),
                version: version.into(),
                download: Some(download_url(owner, slug, version)),
            };
            Some((item, s["updatedAt"].as_u64().unwrap_or(0)))
        })
        .collect();
    (items, page["nextCursor"].as_str().map(String::from))
}

pub fn download_url(owner: &str, slug: &str, version: &str) -> String {
    format!("{API}/download?slug={}&ownerHandle={}&version={}", http::enc(slug), http::enc(owner), http::enc(version))
}

/// Newest-first until we reach what the last run already saw. Pages can be short or empty
/// (ClawHub filters after paging), so only an exhausted cursor or the high-water mark stops us.
pub fn crawl(state: &mut State, limit: usize) -> Result<Vec<Item>> {
    let mark: u64 = state.cursors.get("clawhub").and_then(|c| c.parse().ok()).unwrap_or(0);
    let (mut out, mut cursor, mut newest) = (Vec::new(), None::<String>, mark);
    let mut complete = false;
    'pages: for _ in 0..500 {
        let mut url = format!("{API}/skills?limit=50&sort=updated");
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={}", http::enc(c)));
        }
        let (items, next) = parse_page(&http::get_json(&url)?);
        for (item, updated) in items {
            if updated <= mark {
                complete = true;
                break 'pages;
            }
            newest = newest.max(updated);
            if state.is_new(&item.key(), &item.version) {
                out.push(item);
            }
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
    // a run cut short by `limit` keeps the old mark; seen items are skipped on the next pass
    if complete {
        state.cursors.insert("clawhub".into(), newest.to_string());
    }
    Ok(out)
}
