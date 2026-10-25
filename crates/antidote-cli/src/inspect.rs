//! `antidote inspect`: start each configured MCP server (in a container by default), read its live
//! tool list, scan the descriptions and compare them with the pins `guard` uses (rug pulls).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use antidote_core::{corpus::Corpus, mcp, probe::probe, Finding};
use serde_json::Value;

use crate::guard;

pub struct Opts {
    pub pins: PathBuf,
    pub sandbox: bool,
    pub timeout: Duration,
}

pub fn run(c: &Corpus, config: &Path, o: &Opts, findings: &mut Vec<Finding>) -> Result<()> {
    let cfg: Value = serde_json::from_slice(&std::fs::read(config).with_context(|| format!("reading {}", config.display()))?)
        .with_context(|| format!("{} is not JSON", config.display()))?;
    let runtime = if o.sandbox { container_runtime() } else { None };
    for (name, def) in mcp::servers(&cfg) {
        let Some(prog) = def["command"].as_str() else {
            eprintln!("{name}: skipped (remote server; only stdio servers can be inspected)");
            continue;
        };
        let argv: Vec<String> = std::iter::once(prog.to_string())
            .chain(def["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)))
            .collect();
        let env: Vec<(String, String)> =
            def["env"].as_object().into_iter().flatten().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect();
        let cmd = if o.sandbox {
            let Some(rt) = runtime else {
                anyhow::bail!("no Docker or Podman found; install one, or pass --no-sandbox to run servers directly");
            };
            match container_cmd(rt, &argv, &env) {
                Some(c) => c,
                None => {
                    eprintln!("{name}: skipped (`{prog}` can't run in a container; --no-sandbox runs it directly)");
                    continue;
                }
            }
        } else {
            argv
        };
        eprintln!("inspecting {name}");
        match probe(&cmd, &env, o.timeout) {
            Ok(tools) => {
                let pin_file = o.pins.join(format!("{name}.json"));
                let mut hits = guard::review(c, &name, &pin_file, tools.as_array().map_or(&[][..], |v| v.as_slice()))?;
                for (_, f) in &mut hits {
                    f.context = Some(format!("{name} in {}", config.display()));
                }
                findings.extend(hits.into_iter().map(|(_, f)| f));
            }
            Err(e) => eprintln!("{name}: {e:#}"),
        }
    }
    Ok(())
}

fn container_runtime() -> Option<&'static str> {
    ["docker", "podman"].into_iter().find(|rt| {
        Command::new(rt).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    })
}

/// `docker run` argv for a package-runner command, or None for anything else (a local binary has
/// nothing to run inside an image). No host mounts; env values are read from our environment
/// (`-e KEY`), so secrets don't appear in the process list.
fn container_cmd(rt: &str, argv: &[String], env: &[(String, String)]) -> Option<Vec<String>> {
    let prog = argv.first()?.rsplit(['/', '\\']).next()?.trim_end_matches(".cmd").trim_end_matches(".exe");
    let image = match prog {
        "npx" => "node:22-slim",
        "uvx" | "uv" => "ghcr.io/astral-sh/uv:python3.12-bookworm-slim",
        "bunx" | "bun" => "oven/bun:1-slim",
        _ => return None,
    };
    let mut cmd: Vec<String> = [rt, "run", "--rm", "-i", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only"]
        .into_iter()
        .chain(["--tmpfs", "/tmp:exec", "--tmpfs", "/root:exec", "-e", "HOME=/root", "-e", "npm_config_cache=/tmp/npm"])
        .map(String::from)
        .collect();
    for (k, _) in env {
        cmd.extend(["-e".to_string(), k.clone()]);
    }
    cmd.push(image.into());
    cmd.push(prog.into());
    cmd.extend(argv[1..].iter().cloned());
    Some(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_container_commands() {
        let argv: Vec<String> = ["/usr/local/bin/npx", "-y", "@x/server"].map(String::from).to_vec();
        let cmd = container_cmd("docker", &argv, &[("TOKEN".into(), "s3cret".into())]).unwrap();
        assert_eq!(cmd[..2], ["docker", "run"]);
        assert!(cmd.windows(2).any(|w| w == ["-e", "TOKEN"]));
        assert!(!cmd.iter().any(|a| a.contains("s3cret")));
        assert!(!cmd.iter().any(|a| a == "-v" || a.starts_with("--volume") || a.starts_with("--mount")));
        assert_eq!(cmd[cmd.len() - 4..], ["node:22-slim", "npx", "-y", "@x/server"]);
        assert!(container_cmd("docker", &["node".into(), "server.js".into()], &[]).is_none());
    }
}
