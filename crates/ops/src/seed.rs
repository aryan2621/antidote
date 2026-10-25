//! `antidote-ops seed osv`: import public OSV advisories (GHSA, PYSEC, OpenSSF malicious packages) for
//! MCP packages as corpus entries. Dedupes by alias, so re-runs only add new advisories.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};

use crate::http;

const OSV: &str = "https://api.osv.dev/v1";

/// npm packages tagged `mcp` (top `npm_max` by popularity) and PyPI names with an `mcp` token.
pub fn package_names(npm_max: usize) -> Result<Vec<(&'static str, String)>> {
    let mut out = Vec::new();
    for from in (0..npm_max).step_by(250) {
        let url = format!("https://registry.npmjs.org/-/v1/search?text=keywords:mcp&size=250&from={from}&popularity=1.0&quality=0&maintenance=0");
        let page = http::get_json(&url)?;
        out.extend(page["objects"].as_array().into_iter().flatten().filter_map(|o| Some(("npm", o["package"]["name"].as_str()?.to_string()))));
        sleep(Duration::from_secs(1));
    }
    let index: Value = serde_json::from_slice(&http::get_with("https://pypi.org/simple/", Some("application/vnd.pypi.simple.v1+json"), 200 << 20)?)?;
    out.extend(index["projects"].as_array().into_iter().flatten().filter_map(|p| p["name"].as_str()).filter(|n| mcp_token(n)).map(|n| ("PyPI", n.to_string())));
    Ok(out)
}

/// `mcp`, `fastmcp`, `mcp-server-git`, `dbt_mcp`; not `mcpi` or `mcpython`.
fn mcp_token(name: &str) -> bool {
    name.to_ascii_lowercase().split(['-', '_', '.']).any(|t| t.ends_with("mcp"))
}

/// Advisory ids for these packages, best record first: GHSA (has severity), then MAL, then the rest.
pub fn advisory_ids(names: &[(&str, String)]) -> Result<Vec<String>> {
    let mut ids = BTreeSet::new();
    for chunk in names.chunks(1000) {
        let q = json!({ "queries": chunk.iter().map(|(eco, n)| json!({"package": {"ecosystem": eco, "name": n}})).collect::<Vec<_>>() });
        let r = http::post_json(&format!("{OSV}/querybatch"), &q)?;
        for res in r["results"].as_array().into_iter().flatten() {
            ids.extend(res["vulns"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str().map(String::from)));
        }
    }
    let mut ids: Vec<String> = ids.into_iter().collect();
    ids.sort_by_key(|id| if id.starts_with("GHSA-") { 0 } else if id.starts_with("MAL-") { 1 } else { 2 });
    Ok(ids)
}

/// Every id and alias already in the corpus.
pub fn known_ids(entries_dir: &Path) -> Result<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    for e in fs::read_dir(entries_dir)? {
        let v: Value = serde_json::from_slice(&fs::read(e?.path())?)?;
        seen.extend(v["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)));
    }
    Ok(seen)
}

/// Fetch, dedupe and write new entries; returns the paths written.
pub fn import(corpus: &Path, ids: &[String], max: usize) -> Result<Vec<std::path::PathBuf>> {
    let dir = corpus.join("entries");
    let mut seen = known_ids(&dir)?;
    let mut written = Vec::new();
    for id in ids {
        if written.len() >= max {
            break;
        }
        if seen.contains(id) {
            continue;
        }
        let osv = match http::get_json(&format!("{OSV}/vulns/{id}")) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skip {id}: {e:#}");
                continue;
            }
        };
        let aliases = std::iter::once(id.clone()).chain(osv["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)));
        let aliases: Vec<String> = aliases.collect();
        let dup = aliases.iter().any(|a| seen.contains(a));
        seen.extend(aliases.iter().cloned());
        if dup || osv.get("withdrawn").is_some() {
            continue;
        }
        let Some(entry) = to_entry(&osv, &aliases, &antidote_core::corpus::next_id(&dir, &format!("AGT-{}-", year(&osv)))?) else { continue };
        let path = dir.join(format!("{}.json", entry["id"].as_str().unwrap()));
        fs::write(&path, serde_json::to_string_pretty(&entry)? + "\n")?;
        written.push(path);
        sleep(Duration::from_millis(100));
    }
    Ok(written)
}

fn year(osv: &Value) -> i64 {
    osv["published"].as_str().and_then(|p| p.get(..4)?.parse().ok()).unwrap_or(2026)
}

/// OSV record → AGT entry, keeping only npm/PyPI packages. None if nothing usable is affected.
pub fn to_entry(osv: &Value, aliases: &[String], id: &str) -> Option<Value> {
    let osv_id = osv["id"].as_str()?;
    let malicious = osv_id.starts_with("MAL-");
    let mut names = Vec::new();
    let affected: Vec<Value> = osv["affected"]
        .as_array()?
        .iter()
        .filter_map(|a| {
            let eco = match a["package"]["ecosystem"].as_str()? {
                "npm" => "npm",
                "PyPI" => "PyPI",
                _ => return None,
            };
            let name = a["package"]["name"].as_str()?;
            names.push(name.to_string());
            let ranges: Vec<Value> = a["ranges"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["type"] != "GIT")
                .map(|r| json!({ "type": r["type"], "events": r["events"] }))
                .collect();
            let mut out = json!({ "package": { "ecosystem": eco, "name": name } });
            if !ranges.is_empty() {
                out["ranges"] = json!(ranges);
            } else if let Some(v) = a["versions"].as_array().filter(|v| !v.is_empty()) {
                out["versions"] = json!(v);
            }
            Some(out)
        })
        .collect();
    if affected.is_empty() {
        return None;
    }
    let pkg = names.first()?;
    let summary = osv["summary"].as_str().filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| {
        if malicious { format!("Malicious code in {pkg}") } else { osv["details"].as_str().unwrap_or(osv_id).lines().next().unwrap_or(osv_id).to_string() }
    });
    let summary = if summary.to_lowercase().contains(&pkg.to_lowercase()) { summary } else { format!("{pkg}: {summary}") };
    let mut details: String = osv["details"].as_str().unwrap_or("").chars().take(4000).collect();
    details.push_str(&format!("\n\nImported from OSV {osv_id}."));
    let references: Vec<Value> = std::iter::once(json!({"type": "ADVISORY", "url": format!("https://osv.dev/vulnerability/{osv_id}")}))
        .chain(osv["references"].as_array().into_iter().flatten().take(10).filter_map(|r| Some(json!({"type": r["type"].as_str()?, "url": r["url"].as_str()?}))))
        .collect();
    let mut ds = json!({
        "artifact_type": if names.iter().any(|n| mcp_token(n) || n.contains("mcp")) { "mcp_server" } else { "package" },
        "classification": if malicious { "malicious" } else { "vulnerable" },
        "verification": "verified",
        "reporter": "osv-import",
    });
    if let Some(sev) = osv["database_specific"]["severity"].as_str().and_then(severity) {
        ds["severity"] = json!(sev);
    }
    let now = osv["modified"].as_str().unwrap_or("2026-01-01T00:00:00Z");
    Some(json!({
        "schema_version": "0.1.0",
        "id": id,
        "modified": now,
        "published": osv["published"].as_str().unwrap_or(now),
        "aliases": aliases,
        "summary": summary.chars().take(200).collect::<String>(),
        "details": details,
        "references": references,
        "affected": affected,
        "database_specific": ds,
    }))
}

/// GHSA severity words → ours
fn severity(s: &str) -> Option<&'static str> {
    match s.to_ascii_uppercase().as_str() {
        "LOW" => Some("low"),
        "MODERATE" | "MEDIUM" => Some("medium"),
        "HIGH" => Some("high"),
        "CRITICAL" => Some("critical"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        assert!(mcp_token("mcp") && mcp_token("fastmcp") && mcp_token("mcp-server-git") && mcp_token("dbt_mcp"));
        assert!(!mcp_token("mcpi") && !mcp_token("mcpython"));
    }

    #[test]
    fn maps_ghsa_record() {
        let osv = json!({
            "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2025-1"], "summary": "Path traversal",
            "details": "Bad.", "published": "2025-06-01T00:00:00Z", "modified": "2025-06-02T00:00:00Z",
            "database_specific": {"severity": "MODERATE"},
            "references": [{"type": "WEB", "url": "https://example.com/a"}],
            "affected": [
                {"package": {"ecosystem": "npm", "name": "x-mcp"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}, {"type": "GIT", "events": []}]},
                {"package": {"ecosystem": "Go", "name": "ignored"}}
            ]
        });
        let e = to_entry(&osv, &["GHSA-aaaa-bbbb-cccc".into(), "CVE-2025-1".into()], "AGT-2025-0001").unwrap();
        assert_eq!(e["summary"], "x-mcp: Path traversal");
        assert_eq!(e["affected"].as_array().unwrap().len(), 1);
        assert_eq!(e["affected"][0]["ranges"].as_array().unwrap().len(), 1);
        assert_eq!(e["database_specific"]["severity"], "medium");
        assert_eq!(e["database_specific"]["classification"], "vulnerable");
        assert_eq!(e["database_specific"]["artifact_type"], "mcp_server");
        let mal = json!({"id": "MAL-2025-9", "affected": [{"package": {"ecosystem": "npm", "name": "evil"}, "versions": ["1.0.0"]}]});
        let e = to_entry(&mal, &["MAL-2025-9".into()], "AGT-2025-0002").unwrap();
        assert_eq!(e["database_specific"]["classification"], "malicious");
        assert_eq!(e["summary"], "Malicious code in evil");
        assert_eq!(e["affected"][0]["versions"][0], "1.0.0");
    }
}
