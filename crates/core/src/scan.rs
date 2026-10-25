use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::corpus::Corpus;
use crate::{mcp, Finding};

const MAX_FILE: u64 = 5 * 1024 * 1024;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".venv", "__pycache__"];

/// Hash + YARA scan every file under `root` (or `root` itself if it's a file).
pub fn scan_tree(c: &Corpus, root: &Path, out: &mut Vec<Finding>) {
    let mut scanner = yara_x::Scanner::new(&c.rules);
    let walker = WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
        e.depth() == 0 || !(e.file_type().is_dir() && SKIP_DIRS.contains(&&*e.file_name().to_string_lossy()))
    });
    for e in walker.filter_map(Result::ok) {
        if !e.file_type().is_file() || e.metadata().map_or(true, |m| m.len() > MAX_FILE) {
            continue;
        }
        let Ok(data) = fs::read(e.path()) else { continue };
        let path = e.path().display().to_string();
        hash_match(c, &data, &path, out);
        // text rules on images/archives only produce byte-coincidence noise
        if data.iter().take(8192).any(|b| *b == 0) {
            continue;
        }
        yara_match(&mut scanner, &data, &path, out);
        if let Some(lang) = crate::code::Lang::of(e.path()) {
            crate::code::scan(&c.code, lang, &data, &path, out);
        }
        if let Some(m) = &c.model {
            classify_file(m, e.path(), &data, &path, out);
        }
        if path.ends_with(".json") {
            mcp_config(c, &data, &path, out);
        }
    }
}

fn classify_file(m: &crate::classify::Model, p: &Path, data: &[u8], path: &str, out: &mut Vec<Finding>) {
    if !crate::classify::is_prompt_file(p) {
        return;
    }
    let text = String::from_utf8_lossy(data);
    for (line, seg) in crate::classify::segments(p, &text) {
        classify_segment(m, &seg, path, Some(line), out);
    }
}

fn classify_segment(m: &crate::classify::Model, seg: &str, path: &str, line: Option<usize>, out: &mut Vec<Finding>) {
    let score = m.score(seg);
    let severity = if score >= m.threshold_high {
        "high"
    } else if score >= m.threshold_medium {
        "medium"
    } else {
        return;
    };
    out.push(Finding {
        severity,
        id: "AGT-C-0001".into(),
        summary: "Text reads like a prompt-injection attempt (classifier)".into(),
        path: path.to_string(),
        line,
        context: None,
        evidence: Some(format!("p={score:.2} {}", snippet(seg.as_bytes()))),
        explanation: None,
        fix: Some("Review this text; remove it if the skill or tool doesn't need it".into()),
    });
}

/// Content rules + classifier on text that isn't a file, e.g. a live MCP tool description.
pub fn scan_text(c: &Corpus, label: &str, text: &str, out: &mut Vec<Finding>) {
    yara_match(&mut yara_x::Scanner::new(&c.rules), text.as_bytes(), label, out);
    if let Some(m) = &c.model {
        classify_segment(m, text, label, None, out);
    }
}

/// Only package matching, no content rules: `~/.claude.json` also holds chat history that would
/// trip injection rules on the user's own prompts.
pub fn scan_mcp_config(c: &Corpus, path: &Path, out: &mut Vec<Finding>) {
    if let Ok(data) = fs::read(path) {
        mcp_config(c, &data, &path.display().to_string(), out);
    }
}

fn mcp_config(c: &Corpus, data: &[u8], path: &str, out: &mut Vec<Finding>) {
    let Ok(cfg) = serde_json::from_slice(data) else { return };
    for (server, r) in mcp::package_refs(&cfg) {
        mcp::check(c, &r, path, Some(&format!("mcp server \"{server}\"")), out);
    }
}

fn hash_match(c: &Corpus, data: &[u8], path: &str, out: &mut Vec<Finding>) {
    let hash = format!("{:x}", Sha256::digest(data));
    for e in &c.entries {
        let Some(db) = &e.database_specific else { continue };
        if db.indicators.sha256.contains(&hash) {
            out.push(Finding {
                severity: e.severity(),
                id: e.id.clone(),
                summary: e.summary.clone(),
                path: path.to_string(),
                line: None,
                context: None,
                evidence: Some(format!("sha256 {hash}")),
                explanation: None,
                fix: Some("Remove this file; it matches a known-bad sample".into()),
            });
        }
    }
}

fn yara_match(scanner: &mut yara_x::Scanner, data: &[u8], path: &str, out: &mut Vec<Finding>) {
    let Ok(results) = scanner.scan(data) else { return };
    for rule in results.matching_rules() {
        let meta = |key: &str| {
            rule.metadata().find_map(|(k, v)| match v {
                yara_x::MetaValue::String(s) if k == key => Some(s.to_string()),
                _ => None,
            })
        };
        let first = rule.patterns().flat_map(|p| p.matches()).next();
        let (line, evidence) = match first {
            Some(m) => {
                let r = m.range();
                (Some(data[..r.start].iter().filter(|b| **b == b'\n').count() + 1), Some(snippet(m.data())))
            }
            None => (None, None),
        };
        out.push(Finding {
            severity: severity(meta("severity").as_deref()),
            id: meta("id").unwrap_or_else(|| rule.identifier().to_string()),
            summary: meta("description").unwrap_or_default(),
            path: path.to_string(),
            line,
            context: None,
            evidence,
            explanation: None,
            fix: Some("Remove it, or review the matched text before using it".into()),
        });
    }
}

fn severity(s: Option<&str>) -> &'static str {
    match s {
        Some("critical") => "critical",
        Some("high") => "high",
        Some("low") => "low",
        _ => "medium",
    }
}

/// Matched bytes as one printable line; invisible and control chars shown as `\u{..}`.
fn snippet(bytes: &[u8]) -> String {
    let mut s = String::new();
    for ch in String::from_utf8_lossy(bytes).chars().take(80) {
        let invisible = ch.is_control()
            || matches!(ch, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}');
        if invisible {
            s.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            s.push(ch);
        }
    }
    s
}
