//! `antidote report`: builds a prefilled GitHub issue for a suspicious sample. Nothing is uploaded;
//! the issue carries hashes and rule hits only, never file contents or absolute paths.

use std::fmt::Write;
use std::path::Path;

use anyhow::Result;
use antidote_core::Finding;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const NEW_ISSUE: &str = "https://github.com/antidote-db/antidote/issues/new";
// keeps the URL under GitHub's ~8 KB limit
const MAX_FILES: usize = 40;
const MAX_FINDINGS: usize = 25;

pub fn issue_url(target: &Path, findings: &[Finding]) -> Result<String> {
    let name = target.file_name().map_or("sample".into(), |n| n.to_string_lossy().into_owned());
    let root = if target.is_dir() { target } else { target.parent().unwrap_or(target) };
    let rel = |p: &Path| p.strip_prefix(root).unwrap_or(p).display().to_string();

    let mut files = Vec::new();
    for e in WalkDir::new(target).sort_by_file_name() {
        let e = e?;
        if e.file_type().is_file() {
            files.push((rel(e.path()), hex(&Sha256::digest(std::fs::read(e.path())?))));
        }
    }

    let mut body = String::new();
    writeln!(body, "Reported with `antidote report`. No file contents were uploaded.\n")?;
    writeln!(body, "- **What:** `{name}` (ecosystem, published name, affected versions: please fill in)")?;
    writeln!(body, "- **Classification:** malicious / vulnerable / suspicious")?;
    writeln!(body, "- **Behavior:** what it does, in plain words. Don't paste live payloads; defang domains (`evil[.]example`).")?;
    writeln!(body, "- **Where you found it:** link to the registry page or repo\n")?;
    writeln!(body, "### Files (sha256)")?;
    for (p, h) in files.iter().take(MAX_FILES) {
        writeln!(body, "- `{p}` `{h}`")?;
    }
    if files.len() > MAX_FILES {
        writeln!(body, "- … {} more", files.len() - MAX_FILES)?;
    }
    writeln!(body, "\n### Scanner findings")?;
    if findings.is_empty() {
        writeln!(body, "None.")?;
    }
    // evidence is left out on purpose: it is the matched (possibly live) payload text
    for f in findings.iter().take(MAX_FINDINGS) {
        let at = f.line.map_or(rel(Path::new(&f.path)), |l| format!("{}:{l}", rel(Path::new(&f.path))));
        writeln!(body, "- [{}] {} {} (`{at}`)", f.severity.to_uppercase(), f.id, f.summary)?;
    }
    if findings.len() > MAX_FINDINGS {
        writeln!(body, "- … {} more", findings.len() - MAX_FINDINGS)?;
    }
    Ok(new_issue_url(&format!("Report: {name}"), &body))
}

pub fn new_issue_url(title: &str, body: &str) -> String {
    format!("{NEW_ISSUE}?title={}&body={}", enc(title), enc(body))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
