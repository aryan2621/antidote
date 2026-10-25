mod discover;
mod guard;
mod report;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use antidote_core::{corpus, feed, mcp, rank, scan, Finding};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "antidote", version, about = "Scan AI agent skills, MCP servers and prompts against the Antidote threat corpus")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long, value_enum, default_value = "text", global = true)]
    format: Format,
    /// Exit 1 when a finding at or above this severity is reported
    #[arg(long, value_enum, default_value = "high", global = true)]
    fail_on: FailOn,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan folders/files; with no paths, auto-discover Claude Code / Cursor / OpenClaw config
    Scan {
        paths: Vec<PathBuf>,
        /// MCP config file to check (package matching only)
        #[arg(long)]
        mcp: Vec<PathBuf>,
        /// Skip the prompt-injection classifier
        #[arg(long)]
        no_classifier: bool,
        /// Explain findings with a local LLM: `ollama:<model>` or an OpenAI-compatible URL (http://127.0.0.1:8080/v1)
        #[arg(long)]
        llm: Option<String>,
        /// Model name for a URL `--llm`
        #[arg(long)]
        llm_model: Option<String>,
        /// Allow `--llm` to be a non-local server (file excerpts are sent to it; key from ANTIDOTE_LLM_API_KEY)
        #[arg(long)]
        llm_allow_remote: bool,
        /// Max findings sent for review
        #[arg(long, default_value_t = 20)]
        llm_max: usize,
    },
    /// Look up one package, e.g. `npm:mcp-remote@0.1.15` or `pypi:name==1.0`
    Check { package: String },
    /// Run an MCP server behind a filter: hides tools that look poisoned or changed since first seen.
    /// Use as the server command in your MCP config: `antidote guard --name github -- npx -y @x/server`
    Guard {
        /// Server name; pins are kept per name
        #[arg(long)]
        name: String,
        /// Log problems to stderr but don't hide tools
        #[arg(long)]
        warn_only: bool,
        /// Forget this server's pins (after reviewing a changed tool), then exit
        #[arg(long)]
        reset: bool,
        #[arg(long, hide = true)]
        pins_dir: Option<PathBuf>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Scan a suspicious skill/server and print a prefilled report link. Nothing is uploaded:
    /// the report holds file hashes and rule hits, never file contents
    Report { path: PathBuf },
    /// Download and verify the latest signed corpus feed
    Update {
        #[arg(long, default_value = feed::FEED_URL)]
        url: String,
    },
    /// Maintainer tools
    #[command(hide = true, subcommand)]
    Feed(FeedCmd),
}

#[derive(Subcommand)]
enum FeedCmd {
    /// Bundle a corpus checkout into one feed.json (sign it separately with minisign)
    Build {
        corpus: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        /// Unix time of the last corpus commit
        #[arg(long)]
        version: u64,
    },
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Never,
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(1),
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Returns whether a finding at or above `--fail-on` was reported.
fn run() -> Result<bool> {
    let cli = Cli::parse();
    if let Cmd::Feed(FeedCmd::Build { corpus, out, version }) = &cli.cmd {
        let feed = feed::Feed::from_dir(corpus, *version)?;
        corpus::compile(&feed)?; // fail the build on bad entries or rules
        std::fs::write(out, serde_json::to_vec(&feed)?)?;
        eprintln!("wrote {} ({} entries, {} rule files)", out.display(), feed.entries.len(), feed.rules.len());
        return Ok(false);
    }
    let mut c = corpus::load()?;
    let mut findings = Vec::new();
    let mut llm = None;
    match cli.cmd {
        Cmd::Scan { mut paths, mut mcp, no_classifier, llm: llm_spec, llm_model, llm_allow_remote, llm_max } => {
            if no_classifier {
                c.model = None;
            }
            if let Some(spec) = llm_spec {
                llm = Some((antidote_core::review::parse(&spec, llm_model.as_deref(), llm_allow_remote)?, llm_max));
            }
            if paths.is_empty() && mcp.is_empty() {
                (paths, mcp) = discover::targets();
                if matches!(cli.format, Format::Text) {
                    for p in paths.iter().chain(&mcp) {
                        eprintln!("scanning {}", p.display());
                    }
                }
            }
            for p in &paths {
                if !p.exists() {
                    bail!("{} does not exist", p.display());
                }
                scan::scan_tree(&c, p, &mut findings);
            }
            for p in &mcp {
                scan::scan_mcp_config(&c, p, &mut findings);
            }
        }
        Cmd::Check { package } => {
            let Some(r) = mcp::parse_ref(&package) else {
                bail!("expected <npm|pypi>:<name>[@version], got {package}");
            };
            mcp::check(&c, &r, &package, None, &mut findings);
        }
        Cmd::Report { path } => {
            if !path.exists() {
                bail!("{} does not exist", path.display());
            }
            scan::scan_tree(&c, &path, &mut findings);
            findings.sort_by_key(|f| rank(f.severity));
            eprintln!("{} finding(s). Open this link to file the report, then fill in the details:", findings.len());
            println!("{}", report::issue_url(&path, &findings)?);
            return Ok(false);
        }
        Cmd::Guard { name, warn_only, reset, pins_dir, cmd } => {
            let dir = pins_dir.unwrap_or_else(guard::pins_dir);
            if reset {
                guard::reset(&dir, &name)?;
                eprintln!("pins for {name} cleared; they are re-pinned on the next tools/list");
                return Ok(false);
            }
            std::process::exit(guard::run(c, &name, &dir, warn_only, &cmd)?);
        }
        Cmd::Update { url } => {
            let v = feed::update(&url, c.version)?;
            println!("Corpus at version {v}{}.", if v == c.version { " (already current)" } else { "" });
            return Ok(false);
        }
        Cmd::Feed(_) => unreachable!(),
    }
    findings.sort_by_key(|f| rank(f.severity));
    if let Some((l, max)) = &llm {
        antidote_core::review::review(l, &mut findings, *max, std::time::Duration::from_secs(60));
        findings.sort_by_key(|f| rank(f.severity));
    }

    match cli.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&findings)?),
        Format::Sarif => println!("{}", serde_json::to_string_pretty(&sarif(&findings))?),
        Format::Text if findings.is_empty() => {
            println!("No known threats found ({} entries, corpus version {}).", c.entries.len(), c.version)
        }
        Format::Text => {
            for f in &findings {
                let line = f.line.map(|l| format!(":{l}")).unwrap_or_default();
                let ctx = f.context.as_ref().map(|c| format!(" ({c})")).unwrap_or_default();
                println!("[{}] {} {}\n    at {}{line}{ctx}", f.severity.to_uppercase(), f.id, f.summary, f.path);
                if let Some(e) = &f.evidence {
                    println!("    evidence: {e}");
                }
                if let Some(x) = &f.explanation {
                    println!("    LLM: {x}");
                }
            }
            println!("\n{} finding(s).", findings.len());
        }
    }
    let threshold = match cli.fail_on {
        FailOn::Never => return Ok(false),
        FailOn::Critical => 0,
        FailOn::High => 1,
        FailOn::Medium => 2,
        FailOn::Low => 3,
    };
    Ok(findings.iter().any(|f| rank(f.severity) <= threshold))
}

/// SARIF 2.1.0 for GitHub code scanning; paths under the cwd become repo-relative URIs.
fn sarif(findings: &[Finding]) -> Value {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut rules = BTreeMap::new();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            rules.entry(f.id.clone()).or_insert_with(|| {
                json!({ "id": f.id, "shortDescription": { "text": f.summary }, "properties": { "severity": f.severity } })
            });
            let p = Path::new(&f.path);
            let uri = match p.strip_prefix(&cwd).or_else(|_| p.strip_prefix(".")) {
                Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
                Err(_) if p.is_absolute() => format!("file://{}", f.path.replace('\\', "/")),
                Err(_) => f.path.replace('\\', "/"),
            };
            let mut loc = json!({ "artifactLocation": { "uri": uri } });
            if let Some(l) = f.line {
                loc["region"] = json!({ "startLine": l });
            }
            let mut text = f.summary.clone();
            if let Some(c) = &f.context {
                text.push_str(&format!(" ({c})"));
            }
            if let Some(e) = &f.evidence {
                text.push_str(&format!(". Evidence: {e}"));
            }
            if let Some(x) = &f.explanation {
                text.push_str(&format!(". LLM review: {x}"));
            }
            json!({
                "ruleId": f.id,
                "level": match rank(f.severity) { 0 | 1 => "error", 2 => "warning", _ => "note" },
                "message": { "text": text },
                "locations": [{ "physicalLocation": loc }],
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "antidote",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/antidote-db/antidote",
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }],
    })
}
