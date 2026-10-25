//! Opt-in usage stats. When on, `scan` sends `{corpus_version, counts: {rule_id: n}}` to the URL the
//! user gave and nothing else: no paths, file contents, hostnames or package names.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use antidote_core::Finding;

fn file() -> PathBuf {
    dirs::config_dir().unwrap_or_else(std::env::temp_dir).join("antidote").join("stats-url")
}

/// The stats endpoint if the user turned stats on.
pub fn url() -> Option<String> {
    Some(std::fs::read_to_string(file()).ok()?.trim().to_string()).filter(|u| !u.is_empty())
}

pub fn set(on: bool, url: Option<String>) -> Result<()> {
    let f = file();
    if !on {
        let _ = std::fs::remove_file(&f);
        eprintln!("stats off");
        return Ok(());
    }
    // shortcut: no hosted API yet, so there is no default endpoint; add one when it's deployed
    let Some(url) = url.filter(|u| u.starts_with("https://") || u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost")) else {
        bail!("pass --url https://<antidote-api host>/v1/stats");
    };
    std::fs::create_dir_all(f.parent().unwrap())?;
    std::fs::write(&f, &url)?;
    eprintln!("stats on: each scan sends rule ids and hit counts (nothing else) to {url}");
    Ok(())
}

pub fn status() {
    match url() {
        Some(u) => println!("on ({u})"),
        None => println!("off"),
    }
}

pub fn body(corpus_version: u64, findings: &[Finding]) -> String {
    let mut counts = BTreeMap::<&str, u64>::new();
    for f in findings {
        *counts.entry(f.id.as_str()).or_default() += 1;
    }
    serde_json::json!({ "corpus_version": corpus_version, "counts": counts }).to_string()
}

/// Best effort: 3-second cap, errors ignored.
pub fn send(url: &str, body: &str) {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(3))).build().into();
    let _ = agent.post(url).header("content-type", "application/json").send(body);
}
