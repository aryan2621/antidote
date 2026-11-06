//! Per-rule maintainer decisions: which rules end up confirmed (a corpus entry cites the triage issue) and which
//! end up rejected (closed triage issue with no entry). A rule that is mostly rejected needs tuning or demoting.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;

/// `(confirmed, rejected)` per rule id. `closed_issues` is `gh issue list --state closed --label triage --json number,body`.
pub fn rule_stats(closed_issues: &Value, corpus: &Path) -> Result<BTreeMap<String, (usize, usize)>> {
    let mut stats: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut confirmed_issues = BTreeSet::new();
    for f in fs::read_dir(corpus.join("entries"))? {
        let Ok(entry) = serde_json::from_slice::<Value>(&fs::read(f?.path())?) else { continue };
        let issue = entry["references"].as_array().into_iter().flatten().filter(|r| r["type"] == "REPORT").find_map(|r| r["url"].as_str()?.rsplit_once("/issues/")?.1.parse::<u64>().ok());
        let Some(n) = issue else { continue };
        confirmed_issues.insert(n);
        for id in entry["database_specific"]["detections"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            stats.entry(id.into()).or_default().0 += 1;
        }
    }
    for i in closed_issues.as_array().into_iter().flatten() {
        if i["number"].as_u64().is_some_and(|n| confirmed_issues.contains(&n)) {
            continue;
        }
        // rule/flag ids only (corpus-entry ids are matches, not rules); table rows: `| severity | AGT-X-0001 — summary | where | evidence |`
        let ids: BTreeSet<&str> = i["body"].as_str().unwrap_or("").lines().filter_map(|l| l.split('|').nth(2)?.trim().split_whitespace().next()).filter(|t| ["AGT-R-", "AGT-T-", "AGT-C-", "AGT-F-"].iter().any(|p| t.starts_with(p))).collect();
        for id in ids {
            stats.entry(id.into()).or_default().1 += 1;
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_confirmed_and_rejected_per_rule() {
        let dir = std::env::temp_dir().join(format!("antidote-decisions-{}", std::process::id()));
        fs::create_dir_all(dir.join("entries")).unwrap();
        fs::write(
            dir.join("entries/AGT-2026-1.json"),
            r#"{"references":[{"type":"REPORT","url":"https://github.com/o/r/issues/7"}],"database_specific":{"detections":["AGT-R-0101"]}}"#,
        )
        .unwrap();
        let row = |id: &str| format!("| high | {id} — x | `a.js:1` | `e` |\n");
        let issues = serde_json::json!([
            {"number": 7, "body": row("AGT-R-0101")},
            {"number": 8, "body": row("AGT-T-0005") + &row("AGT-T-0005")},
            {"number": 9, "body": row("AGT-R-0101")},
        ]);
        let s = rule_stats(&issues, &dir).unwrap();
        assert_eq!(s["AGT-R-0101"], (1, 1));
        assert_eq!(s["AGT-T-0005"], (0, 1)); // once per issue, not per row
        let _ = fs::remove_dir_all(&dir);
    }
}
