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
    PkgRef { ecosystem: "PyPI", name: name.to_string(), version }
}

/// Every package launched via npx/bunx/pnpm dlx/uvx/pipx in any `mcpServers` block, at any depth
/// (`~/.claude.json` nests them under `projects.<path>`).
pub fn package_refs(cfg: &Value) -> Vec<(String, PkgRef)> {
    let mut out = Vec::new();
    walk(cfg, &mut out);
    out
}

fn walk(v: &Value, out: &mut Vec<(String, PkgRef)>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if k == "mcpServers" {
                    for (server, def) in child.as_object().into_iter().flatten() {
                        if let Some(r) = server_ref(def) {
                            out.push((server.clone(), r));
                        }
                    }
                } else {
                    walk(child, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
        _ => {}
    }
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

pub fn check(c: &Corpus, r: &PkgRef, path: &str, context: Option<&str>, out: &mut Vec<Finding>) {
    for e in &c.entries {
        for a in &e.affected {
            if !a.package.ecosystem.eq_ignore_ascii_case(r.ecosystem) || a.package.name != r.name {
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
            });
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let rg: Range = serde_json::from_str(r#"{"events":[{"introduced":"0.0.5"},{"fixed":"0.1.16"}]}"#).unwrap();
        assert!(in_range("0.1.15", &rg));
        assert!(in_range("0.0.5", &rg));
        assert!(!in_range("0.1.16", &rg));
        assert!(!in_range("0.0.4", &rg));
        assert!(!in_range("0.10.0", &rg));
        let open: Range = serde_json::from_str(r#"{"events":[{"introduced":"0"}]}"#).unwrap();
        assert!(in_range("9.9", &open));
    }

    #[test]
    fn parses_refs() {
        assert_eq!(
            parse_ref("npm:@scope/pkg@1.2.0").unwrap(),
            PkgRef { ecosystem: "npm", name: "@scope/pkg".into(), version: Some("1.2.0".into()) }
        );
        assert_eq!(parse_ref("npm:@scope/pkg").unwrap().version, None);
        assert_eq!(parse_ref("npm:pkg@latest").unwrap().version, None);
        assert_eq!(parse_ref("pypi:mcp-x==0.3").unwrap().name, "mcp-x");
        assert!(parse_ref("cargo:x").is_none());
    }

    #[test]
    fn finds_nested_servers() {
        let cfg: Value = serde_json::from_str(
            r#"{"projects":{"/p":{"mcpServers":{
                "a":{"command":"npx","args":["-y","mcp-remote@0.1.15","https://x"]},
                "b":{"command":"/usr/bin/uvx","args":["mcp-server-git"]},
                "c":{"command":"node","args":["server.js"]}}}}}"#,
        )
        .unwrap();
        let refs = package_refs(&cfg);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].1, PkgRef { ecosystem: "npm", name: "mcp-remote".into(), version: Some("0.1.15".into()) });
        assert_eq!(refs[1].1.ecosystem, "PyPI");
    }
}
