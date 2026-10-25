use serde_json::Value;

use crate::corpus::{Corpus, Range};
use crate::Finding;

#[derive(Debug, PartialEq)]
pub struct PkgRef {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: Option<String>,
}

/// Parse `npm:@scope/name@1.2.0` or `PyPI:name==1.0`.
pub fn parse_ref(s: &str) -> Option<PkgRef> {
    let (eco, spec) = s.split_once(':')?;
    match eco.to_ascii_lowercase().as_str() {
        "npm" => Some(npm_spec(spec)),
        "pypi" => Some(pypi_spec(spec)),
        _ => None,
    }
}

fn npm_spec(spec: &str) -> PkgRef {
    // skip index 0 so the `@` of a scope isn't read as a version separator
    let (name, version) = match spec.get(1..).and_then(|s| s.rfind('@')) {
        Some(i) => (&spec[..=i], Some(spec[i + 2..].to_string())),
        None => (spec, None),
    };
    PkgRef { ecosystem: "npm", name: name.to_string(), version: version.filter(|v| v != "latest") }
}

fn pypi_spec(spec: &str) -> PkgRef {
    let (name, version) = match spec.split_once("==").or_else(|| spec.split_once('@')) {
        Some((n, v)) => (n, Some(v.to_string())),
        None => (spec, None),
    };
    PkgRef { ecosystem: "PyPI", name: pypi_norm(name), version }
}

/// PEP 503: `Mcp_Server.Git` and `mcp-server-git` are the same project.
fn pypi_norm(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars().map(|c| c.to_ascii_lowercase()) {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Every package launched via npx/bunx/pnpm dlx/uvx/pipx in any `mcpServers` block, at any depth
/// (`~/.claude.json` nests them under `projects.<path>`).
pub fn package_refs(cfg: &Value) -> Vec<(String, PkgRef)> {
    servers(cfg).into_iter().filter_map(|(name, def)| Some((name, server_ref(def)?))).collect()
}

/// (name, definition) of every server in any `mcpServers` block, at any depth.
pub fn servers(cfg: &Value) -> Vec<(String, &Value)> {
    fn walk<'a>(v: &'a Value, out: &mut Vec<(String, &'a Value)>) {
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    if k == "mcpServers" {
                        out.extend(child.as_object().into_iter().flatten().map(|(n, d)| (n.clone(), d)));
                    } else {
                        walk(child, out);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(cfg, &mut out);
    out
}

fn server_ref(def: &Value) -> Option<PkgRef> {
    let cmd = def.get("command")?.as_str()?;
    let cmd = cmd.rsplit(['/', '\\']).next()?.trim_end_matches(".cmd").trim_end_matches(".exe");
    let args: Vec<&str> = def.get("args")?.as_array()?.iter().filter_map(|a| a.as_str()).collect();
    // shortcut: takes the first positional arg; misses `uvx --from pkg cmd` style invocations.
    let first = args.iter().copied().find(|a| !a.starts_with('-') && *a != "dlx" && *a != "x" && *a != "run")?;
    match cmd {
        "npx" | "bunx" | "pnpm" | "pnpx" | "yarn" | "bun" => Some(npm_spec(first)),
        "uvx" | "pipx" | "uv" => Some(pypi_spec(first)),
        _ => None,
    }
}

/// "Upgrade to <highest fixed>" when a fix exists, else remove (or pin, for a few bad versions).
fn fix(e: &crate::corpus::Entry, a: &crate::corpus::Affected) -> String {
    let fixed = a.ranges.iter().flat_map(|r| &r.events).filter_map(|ev| ev.get("fixed")).max_by(|x, y| cmp_ver(x, y));
    match fixed {
        Some(v) => format!("Upgrade to {v} or later"),
        None if e.severity() == "critical" || a.versions.is_empty() => "Remove it".into(),
        None => format!("Remove it, or pin a version other than {}", a.versions.join(", ")),
    }
}

pub fn check(c: &Corpus, r: &PkgRef, path: &str, context: Option<&str>, out: &mut Vec<Finding>) {
    let before = out.len();
    for e in &c.entries {
        for a in &e.affected {
            let name = if r.ecosystem == "PyPI" { pypi_norm(&a.package.name) } else { a.package.name.clone() };
            if !a.package.ecosystem.eq_ignore_ascii_case(r.ecosystem) || name != r.name {
                continue;
            }
            let all = a.versions.is_empty() && a.ranges.is_empty();
            let evidence = match &r.version {
                _ if all => format!("{}:{} (all versions affected)", r.ecosystem, r.name),
                Some(v) if a.versions.contains(v) || a.ranges.iter().any(|rg| in_range(v, rg)) => {
                    format!("{}:{}@{v}", r.ecosystem, r.name)
                }
                Some(_) => continue,
                // unpinned resolves to latest, which is only affected if nothing was ever fixed
                None if a.ranges.iter().any(|rg| !rg.events.iter().any(|e| e.contains_key("fixed"))) => {
                    format!("{}:{} is unpinned and no fixed version exists", r.ecosystem, r.name)
                }
                None => continue,
            };
            out.push(Finding {
                severity: e.severity(),
                id: e.id.clone(),
                summary: e.summary.clone(),
                path: path.to_string(),
                line: None,
                context: context.map(String::from),
                evidence: Some(evidence),
                explanation: None,
                fix: Some(fix(e, a)),
            });
        }
    }
    let popular = c.popular.get(&r.ecosystem.to_lowercase()).map_or(&[][..], |v| v.as_slice());
    if out.len() == before {
        if let Some(target) = typosquat_of(&r.name, popular) {
            out.push(Finding {
                severity: "medium",
                id: "AGT-F-TYPOSQUAT".into(),
                summary: format!("Name is one or two characters off popular package `{target}`. Check you meant this one."),
                path: path.to_string(),
                line: None,
                context: context.map(String::from),
                evidence: Some(format!("{}:{} vs {target}", r.ecosystem, r.name)),
                explanation: None,
                fix: Some(format!("Use `{target}` if that's what you meant")),
            });
        }
    }
}

/// A popular name within 1 edit (2 for names of 10+ chars), unless the name is itself popular.
/// Short names are too collision-prone to judge.
pub fn typosquat_of(name: &str, popular: &[String]) -> Option<String> {
    if name.len() < 5 || popular.iter().any(|p| p == name) {
        return None;
    }
    let max = if name.len() < 10 { 1 } else { 2 };
    popular.iter().find(|p| strsim::levenshtein(name, p) <= max).cloned()
}

/// OSV range events, applied in order: `introduced` opens, `fixed` (exclusive) / `last_affected` closes.
fn in_range(v: &str, rg: &Range) -> bool {
    let mut hit = false;
    for e in &rg.events {
        if let Some(i) = e.get("introduced") {
            hit = i == "0" || cmp_ver(v, i).is_ge();
        } else if let Some(f) = e.get("fixed") {
            hit &= cmp_ver(v, f).is_lt();
            if hit {
                return true;
            }
        } else if let Some(l) = e.get("last_affected") {
            hit &= cmp_ver(v, l).is_le();
            if hit {
                return true;
            }
        }
    }
    hit
}

// shortcut: numeric dot-compare, pre-release tags compared as plain strings; use a semver/PEP 440 crate if entries need it.
fn cmp_ver(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| s.trim_start_matches('v').split(['.', '-', '+']).map(str::to_string).collect::<Vec<_>>();
    let (a, b) = (parts(a), parts(b));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).map_or("0", |s| s), b.get(i).map_or("0", |s| s));
        let o = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => x.cmp(y),
        };
        if o.is_ne() {
            return o;
        }
    }
    std::cmp::Ordering::Equal
}
