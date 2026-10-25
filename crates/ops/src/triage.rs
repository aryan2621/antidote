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
