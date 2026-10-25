use anyhow::{Context, Result};
use serde_json::Value;

use super::Item;
use crate::http;
use crate::state::State;

/// `(name, version)` from each `<item><title>name version</title>` in a PyPI RSS feed.
// shortcut: string scan instead of an XML parser; PyPI's feed shape has been stable for years.
pub fn parse_rss(xml: &str) -> Vec<(String, String)> {
    xml.split("<item>")
        .skip(1)
        .filter_map(|it| {
            let title = it.split("<title>").nth(1)?.split("</title>").next()?.trim();
            let (name, version) = title.rsplit_once(' ')?;
            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

fn relevant(name: &str, watch: &[String]) -> bool {
    name.to_ascii_lowercase().contains("mcp") || watch.iter().any(|w| w.eq_ignore_ascii_case(name))
}

/// The feeds only hold the last few minutes of uploads, so this must run often (hourly misses some;
/// the MCP-registry crawl backfills anything listed there).
pub fn crawl(state: &mut State, limit: usize) -> Result<Vec<Item>> {
    refresh_popular(state);
    let mut out = Vec::new();
    // updates.xml includes first releases too; packages.xml titles carry no version
    let xml = String::from_utf8_lossy(&http::get("https://pypi.org/rss/updates.xml", 5 << 20)?).into_owned();
    for (name, version) in parse_rss(&xml) {
        if relevant(&name, &state.pypi_watch) {
            out.push(Item { source: "pypi".into(), ecosystem: "PyPI".into(), name, version, download: None });
        }
    }
    out.dedup();
    Ok(out.into_iter().filter(|i| state.is_new(&i.key(), &i.version)).take(limit).collect())
}

/// MCP-named projects among PyPI's top 15k by downloads, for typosquat checks. The source updates
/// monthly, so this fetches at most once a day. Best effort: keeps the old list on failure.
fn refresh_popular(state: &mut State) {
    let day = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 86_400).to_string();
    if state.cursors.get("pypi-popular") == Some(&day) {
        return;
    }
    match http::get_json("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json") {
        Ok(v) => {
            let names = popular_mcp(&v);
            if !names.is_empty() {
                state.popular.insert("PyPI".into(), names);
                state.cursors.insert("pypi-popular".into(), day);
            }
        }
        Err(e) => eprintln!("PyPI popular list not refreshed: {e:#}"),
    }
}

fn popular_mcp(v: &Value) -> Vec<String> {
    let rows = v["rows"].as_array().into_iter().flatten();
    rows.filter_map(|r| r["project"].as_str()).filter(|n| n.to_ascii_lowercase().split(['-', '_', '.']).any(|t| t.ends_with("mcp"))).map(String::from).collect()
}

/// Download URL + sha256 for a release, preferring the sdist (it holds the build scripts).
pub fn release_file(name: &str, version: &str) -> Result<(String, String)> {
    let doc = http::get_json(&format!("https://pypi.org/pypi/{name}/{version}/json"))?;
    pick_file(&doc)
}

pub fn pick_file(doc: &Value) -> Result<(String, String)> {
    let urls = doc["urls"].as_array().context("no files in release")?;
    let f = urls
        .iter()
        .find(|u| u["packagetype"] == "sdist")
        .or_else(|| urls.first())
        .context("release has no files")?;
    Ok((
        f["url"].as_str().context("file without url")?.to_string(),
        f["digests"]["sha256"].as_str().context("file without sha256")?.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popular_keeps_mcp_names() {
        let v = serde_json::json!({"rows": [{"project": "boto3"}, {"project": "fastmcp"}, {"project": "mcp-server-git"}, {"project": "mcpi"}]});
        assert_eq!(popular_mcp(&v), ["fastmcp", "mcp-server-git"]);
    }

    #[test]
    fn parses_recorded_rss() {
        let items = parse_rss(include_str!("../../tests/fixtures/pypi/updates.xml"));
        assert!(items.len() > 10);
        assert!(items.iter().all(|(n, v)| !n.is_empty() && !v.contains(' ')));
    }

    #[test]
    fn relevance_and_file_choice() {
        assert!(relevant("fastmcp", &[]));
        assert!(relevant("Bowmark", &["bowmark".into()]));
        assert!(!relevant("requests", &[]));
        let doc = serde_json::json!({"urls": [
            {"packagetype": "bdist_wheel", "url": "w", "digests": {"sha256": "a"}},
            {"packagetype": "sdist", "url": "s", "digests": {"sha256": "b"}}
        ]});
        assert_eq!(pick_file(&doc).unwrap(), ("s".to_string(), "b".to_string()));
    }
}
