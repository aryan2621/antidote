//! `antidote guard`: stdio MCP proxy. Scans every `tools/list` answer, pins each tool's definition on
//! first sight, and hides tools that look poisoned or changed since they were pinned (rug pulls).

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use antidote_core::{corpus::Corpus, rank, scan, Finding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn pins_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(std::env::temp_dir).join("antidote").join("pins")
}

pub fn reset(dir: &Path, name: &str) -> Result<()> {
    match std::fs::remove_file(dir.join(format!("{name}.json"))) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Runs until the server exits; returns its exit code.
pub fn run(c: Corpus, name: &str, dir: &Path, warn_only: bool, cmd: &[String]) -> Result<i32> {
    let (prog, args) = cmd.split_first().context("usage: antidote guard --name <server> -- <command> [args]")?;
    let mut child = Command::new(prog).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().with_context(|| format!("starting {prog}"))?;
    let mut to_server = child.stdin.take().unwrap();
    let from_server = child.stdout.take().unwrap();
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let list_ids = Arc::new(Mutex::new(HashSet::<String>::new()));
    let blocked = Arc::new(Mutex::new(BTreeMap::<String, String>::new()));

    {
        let (out, list_ids, blocked) = (out.clone(), list_ids.clone(), blocked.clone());
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines().map_while(Result::ok) {
                if let Ok(m) = serde_json::from_str::<Value>(&line) {
                    match m["method"].as_str() {
                        Some("tools/list") => {
                            list_ids.lock().unwrap().insert(m["id"].to_string());
                        }
                        Some("tools/call") => {
                            let tool = m["params"]["name"].as_str().unwrap_or_default();
                            if let Some(why) = blocked.lock().unwrap().get(tool) {
                                let err = json!({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": format!("blocked by antidote: {why}")}});
                                let _ = writeln!(out.lock().unwrap(), "{err}");
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                if writeln!(to_server, "{line}").is_err() {
                    break;
                }
            }
            // dropping `to_server` closes the server's stdin
        });
    }

    let pin_file = dir.join(format!("{name}.json"));
    for line in BufReader::new(from_server).lines().map_while(Result::ok) {
        let mut line = line;
        if let Ok(mut m) = serde_json::from_str::<Value>(&line) {
            if m["result"]["tools"].is_array() && list_ids.lock().unwrap().remove(&m["id"].to_string()) {
                let mut verdicts = BTreeMap::new();
                for (tool, f) in review(&c, name, &pin_file, m["result"]["tools"].as_array().unwrap())? {
                    if rank(f.severity) > 1 {
                        continue;
                    }
                    let hint = if f.id == RUG_PULL { format!("; review it, then run `antidote guard --name {name} --reset`") } else { String::new() };
                    // keep the worst finding per tool
                    let worse = verdicts.get(&tool).is_none_or(|(r, _)| rank(f.severity) < *r);
                    if worse {
                        verdicts.insert(tool, (rank(f.severity), format!("{} {} [{}]{hint}", f.id, f.summary, f.severity)));
                    }
                }
                let mut b = blocked.lock().unwrap();
                b.clear();
                for (tool, (_, why)) in verdicts {
                    eprintln!("antidote guard [{name}]: {tool}: {why}{}", if warn_only { " (warn only)" } else { "" });
                    if !warn_only {
                        b.insert(tool, why);
                    }
                }
                if !b.is_empty() {
                    m["result"]["tools"].as_array_mut().unwrap().retain(|t| !b.contains_key(t["name"].as_str().unwrap_or_default()));
                    line = m.to_string();
                }
            }
        }
        let mut o = out.lock().unwrap();
        writeln!(o, "{line}")?;
        o.flush()?;
    }
    Ok(child.wait()?.code().unwrap_or(1))
}

pub const RUG_PULL: &str = "AGT-F-RUGPULL";

/// (tool, finding) for every problem with these tools, rug pulls included. Pins new tools, never
/// overwrites a pin. Shared by `guard` and `inspect`, so both agree on what's pinned.
pub fn review(c: &Corpus, server: &str, pin_file: &Path, tools: &[Value]) -> Result<Vec<(String, Finding)>> {
    let mut pins: BTreeMap<String, String> = std::fs::read(pin_file).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default();
    let mut out = Vec::new();
    let mut changed = false;
    for t in tools {
        let tool = t["name"].as_str().unwrap_or_default().to_string();
        let path = format!("mcp:{server}/{tool}");
        let hash = format!("{:x}", Sha256::digest(json!([t["name"], t["description"], t["inputSchema"]]).to_string()));
        match pins.get(&tool) {
            Some(p) if *p != hash => {
                out.push((tool, Finding {
                    severity: "high",
                    id: RUG_PULL.into(),
                    summary: "Tool definition changed since it was pinned (possible rug pull)".into(),
                    path,
                    line: None,
                    context: Some(server.to_string()),
                    evidence: Some(t["description"].as_str().unwrap_or_default().chars().take(200).collect()),
                    explanation: None,
                }));
                continue;
            }
            Some(_) => {}
            None => {
                pins.insert(tool.clone(), hash);
                changed = true;
            }
        }
        let mut findings = Vec::new();
        for text in descriptions(t) {
            scan::scan_text(c, &path, &text, &mut findings);
        }
        out.extend(findings.into_iter().map(|f| (tool.clone(), f)));
    }
    if changed {
        std::fs::create_dir_all(pin_file.parent().unwrap())?;
        std::fs::write(pin_file, serde_json::to_vec_pretty(&pins)?)?;
    }
    Ok(out)
}

/// The tool description plus every `description` inside its input schema.
fn descriptions(t: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, child) in m {
                    match child.as_str() {
                        Some(s) if k == "description" => out.push(s.to_string()),
                        _ => walk(child, out),
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(&json!({"description": t["description"], "s": t["inputSchema"]}), &mut out);
    out
}
