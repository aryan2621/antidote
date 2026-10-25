mod corpus;
mod discover;
mod mcp;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

#[derive(Parser)]
#[command(name = "antidote", version, about = "Scan AI agent skills, MCP servers and prompts against the Antidote threat corpus")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long, value_enum, default_value = "text", global = true)]
    format: Format,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan folders/files; with no paths, auto-discover Claude Code / Cursor / OpenClaw config
    Scan {
        paths: Vec<PathBuf>,
        /// MCP config file to check (package matching only)
        #[arg(long)]
        mcp: Vec<PathBuf>,
    },
    /// Look up one package, e.g. `npm:mcp-remote@0.1.15` or `pypi:name==1.0`
    Check { package: String },
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub id: String,
    pub summary: String,
    pub location: String,
    pub evidence: Option<String>,
}

fn rank(sev: &str) -> u8 {
    match sev {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    }
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

/// Returns whether any high/critical finding was reported.
fn run() -> Result<bool> {
    let cli = Cli::parse();
    let c = corpus::load()?;
    let mut findings = Vec::new();
    match cli.cmd {
        Cmd::Scan { mut paths, mut mcp } => {
            if paths.is_empty() && mcp.is_empty() {
                (paths, mcp) = discover::targets();
                if !matches!(cli.format, Format::Json) {
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
            mcp::check(&c, &r, &package, &mut findings);
        }
    }
    findings.sort_by_key(|f| rank(f.severity));

    match cli.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&findings)?),
        Format::Text if findings.is_empty() => {
            println!("No known threats found ({} entries, corpus built in).", c.entries.len())
        }
        Format::Text => {
            for f in &findings {
                println!("[{}] {} {}\n    at {}", f.severity.to_uppercase(), f.id, f.summary, f.location);
                if let Some(e) = &f.evidence {
                    println!("    evidence: {e}");
                }
            }
            println!("\n{} finding(s).", findings.len());
        }
    }
    Ok(findings.iter().any(|f| rank(f.severity) <= 1))
}
