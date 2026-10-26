use anyhow::Result;
use serde_json::Value;

use super::Item;
use crate::http;
use crate::state::State;

const API: &str = "https://api.github.com";
/// Repos that publish MCP servers or agent skills straight from GitHub, with no registry in between.
pub const TOPICS: [&str; 3] = ["mcp-server", "claude-skills", "agent-skills"];

fn token() -> Option<String> {
    std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty())
}

/// `(full_name, default_branch, pushed_at)` for each repo in one search page.
pub fn parse_page(page: &Value) -> Vec<(String, String, String)> {
    page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            // forks re-publish the same code; archived repos no longer change
            if r["fork"] == true || r["archived"] == true {
                return None;
            }
            Some((r["full_name"].as_str()?.into(), r["default_branch"].as_str()?.into(), r["pushed_at"].as_str()?.into()))
        })
        .collect()
}

pub fn download_url(full_name: &str, sha: &str) -> String {
    format!("https://codeload.github.com/{full_name}/tar.gz/{sha}")
}

/// Head commit of a branch; the sha is the version, so a push is a new version.
pub fn head_sha(full_name: &str, branch: &str) -> Result<String> {
    let url = format!("{API}/repos/{full_name}/commits/{}", http::enc(branch));
    let body = http::get_auth(&url, Some("application/vnd.github.sha"), token().as_deref(), 1 << 10)?;
    Ok(String::from_utf8_lossy(&body).trim().to_string())
}

/// Recently pushed repos per topic, newest first, down to what the last full sweep saw.
pub fn crawl(state: &mut State, limit: usize) -> Result<Vec<Item>> {
    let tok = token();
    if tok.is_none() {
        eprintln!("github: GITHUB_TOKEN not set; unauthenticated search allows 10 requests a minute");
    }
    let (y, m, d) = antidote_core::corpus::today();
    let mut out = Vec::new();
    for topic in TOPICS {
        let key = format!("github:{topic}");
        // first run starts from today rather than backfilling every repo with the topic
        let mark = state.cursors.get(&key).cloned().unwrap_or_else(|| format!("{y:04}-{m:02}-{d:02}T00:00:00Z"));
        let (mut newest, mut complete) = (mark.clone(), false);
        // search returns at most 1000 results (10 pages of 100)
        for page in 1..=10 {
            let q = http::enc(&format!("topic:{topic} pushed:>{mark}"));
            let url = format!("{API}/search/repositories?q={q}&sort=updated&order=desc&per_page=100&page={page}");
            let repos = parse_page(&http::get_json_auth(&url, Some("application/vnd.github+json"), tok.as_deref())?);
            let last_page = repos.len() < 100;
            for (full_name, branch, pushed) in repos {
                if out.len() >= limit {
                    break;
                }
                newest = newest.max(pushed);
                let sha = match head_sha(&full_name, &branch) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("github: skip {full_name}: {e:#}");
                        continue;
                    }
                };
                let item = Item {
                    source: key.clone(),
                    ecosystem: "GitHub".into(),
                    download: Some(download_url(&full_name, &sha)),
                    name: full_name,
                    version: sha,
                    tools: None,
                };
                if state.is_new(&item.key(), &item.version) && !out.iter().any(|i: &Item| i.key() == item.key()) {
                    out.push(item);
                }
            }
            if last_page {
                complete = true;
                break;
            }
            if out.len() >= limit {
                break;
            }
        }
        // a sweep cut short keeps the old mark; already-seen shas are skipped next time
        if complete {
            state.cursors.insert(key, newest);
        }
        if out.len() >= limit {
            break;
        }
    }
    out.truncate(limit);
    Ok(out)
}
