mod analyze;
mod crawl;
mod detonate;
mod extract;
mod http;
mod seed;
mod state;
mod triage;

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::analyze::Report;
use crate::crawl::Item;
use crate::state::State;

#[derive(Parser)]
#[command(name = "antidote-ops", about = "Antidote maintainer tooling: crawl registries, analyze artifacts, triage")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum Source {
    McpRegistry,
    Clawhub,
    Npm,
    Pypi,
    Smithery,
    Github,
}

#[derive(Subcommand)]
enum Cmd {
    /// List new/changed items from one source without analyzing or saving anything
    Crawl {
        source: Source,
        #[arg(long, default_value = "state/state.json")]
        state: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Crawl every source, analyze new items, write reports + issue bodies for flagged ones, save state
    Run {
        #[arg(long, default_value = "state/state.json")]
        state: PathBuf,
        #[arg(long, default_value = "out")]
        out: PathBuf,
        #[arg(long, default_value = "corpus/allowlist.json")]
        allowlist: PathBuf,
        /// Open an issue at or above this severity
        #[arg(long, default_value = "high")]
        threshold: String,
        /// Max items analyzed per source per run
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Analyze one package, e.g. `npm:mcp-remote@0.1.16`, `pypi:mcp@1.23.0`, `clawhub:steipete/sonoscli@1.0.0`,
    /// `github:owner/repo@main` (branch, tag or sha), `smithery:namespace/server@latest`
    Analyze {
        spec: String,
        #[arg(long, default_value = "state/state.json")]
        state: PathBuf,
    },
    /// Parse a maintainer comment (stdin) into a JSON command; prints nothing if there is none
    Command {
        #[arg(long)]
        association: String,
    },
    /// Turn a confirmed report into a corpus entry; prints the new file path
    DraftEntry {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        classification: String,
        #[arg(long, default_value = "")]
        summary: String,
        #[arg(long)]
        issue_url: String,
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
    },
    /// Speak MCP to a server command over stdio; prints its `tools/list` result
    McpProbe {
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Score the logs from `detonate/run.sh`; writes report.json and comment.md into the same dir
    DetonationReport {
        dir: PathBuf,
        /// tools_hash from the previous detonation of this package, for rug-pull detection
        #[arg(long)]
        previous_tools_hash: Option<String>,
    },
    /// Import public OSV advisories for MCP packages as corpus entries (skips ones already imported)
    SeedOsv {
        #[arg(long, default_value = "corpus")]
        corpus: PathBuf,
        /// How many top `mcp`-keyword npm packages to look up
        #[arg(long, default_value_t = 2000)]
        npm_max: usize,
        /// Max new entries to write
        #[arg(long, default_value_t = 1000)]
        max: usize,
    },
    /// Allowlist a rejected report's rule hits for that exact version
    Allow {
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long, default_value = "corpus/allowlist.json")]
        allowlist: PathBuf,
    },
}

fn crawl(source: Source, state: &mut State, limit: usize) -> Result<Vec<Item>> {
    match source {
        Source::McpRegistry => crawl::mcp_registry::crawl(state, limit),
        Source::Clawhub => crawl::clawhub::crawl(state, limit),
        Source::Npm => crawl::npm::crawl(state, limit),
        Source::Pypi => crawl::pypi::crawl(state, limit),
        Source::Smithery => crawl::smithery::crawl(state, limit),
        Source::Github => crawl::github::crawl(state, limit),
    }
}

fn file_stem(r: &Report) -> String {
    format!("{}@{}", r.item.key(), r.item.version).chars().map(|c| if c.is_ascii_alphanumeric() || "-_.@".contains(c) { c } else { '_' }).collect()
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Crawl { source, state, limit } => {
            let mut st = State::load(&state)?;
            for i in crawl(source, &mut st, limit)? {
                println!("{}", serde_json::to_string(&i)?);
            }
        }
        Cmd::Run { state, out, allowlist, threshold, limit } => {
            let mut st = State::load(&state)?;
            let corpus = antidote_core::corpus::load()?;
            let allow = analyze::load_allowlist(&allowlist);
            fs::create_dir_all(out.join("reports"))?;
            fs::create_dir_all(out.join("issues"))?;
            // MCP registry first: it teaches the PyPI crawler which names to watch
            let mut items = Vec::new();
            for s in [Source::McpRegistry, Source::Clawhub, Source::Npm, Source::Pypi, Source::Smithery, Source::Github] {
                match crawl(s, &mut st, limit) {
                    Ok(v) => items.extend(v),
                    Err(e) => eprintln!("crawl failed for one source, continuing: {e:#}"),
                }
            }
            let mut done = BTreeSet::new();
            let (mut analyzed, mut flagged) = (0, 0);
            for item in items {
                if !st.is_new(&item.key(), &item.version) || !done.insert((item.key(), item.version.clone())) {
                    continue;
                }
                let r = match analyze::analyze_remote(&corpus, &item, &st, &allow) {
                    Ok(r) => r,
                    Err(e) => {
                        // not marked seen, so the next run retries it
                        eprintln!("skip {}@{}: {e:#}", item.key(), item.version);
                        continue;
                    }
                };
                analyzed += 1;
                st.seen.insert(item.key(), r.seen());
                if r.flagged(&threshold) {
                    flagged += 1;
                    let stem = file_stem(&r);
                    let report_path = format!("reports/{stem}.json");
                    fs::write(out.join(&report_path), serde_json::to_vec_pretty(&r)?)?;
                    let issue = format!("{}\n{}", triage::issue_title(&r), triage::issue_body(&r, &report_path));
                    fs::write(out.join("issues").join(format!("{stem}.md")), issue)?;
                }
            }
            // cursors and seen are saved together, at the end: a crashed run is simply redone
            st.save(&state)?;
            eprintln!("analyzed {analyzed}, flagged {flagged}");
        }
        Cmd::Analyze { spec, state } => {
            let (eco, rest) = spec.split_once(':').context("expected <ecosystem>:<name>@<version>")?;
            let (name, version) = rest.rsplit_once('@').filter(|(n, _)| !n.is_empty()).context("missing @version")?;
            let ecosystem = match eco.to_ascii_lowercase().as_str() {
                "npm" => "npm",
                "pypi" => "PyPI",
                "clawhub" => "clawhub",
                "github" => "GitHub",
                "smithery" => "smithery",
                _ => bail!("ecosystem must be npm, pypi, clawhub, github or smithery"),
            };
            let item = match (ecosystem, name.split_once('/')) {
                // Smithery has no versions; the current listing is analyzed whatever follows the @
                ("smithery", _) => crawl::smithery::fetch(name)?,
                ("clawhub" | "GitHub", None) => bail!("{eco} names are <owner>/<name>"),
                (_, split) => {
                    let (version, download) = match (ecosystem, split) {
                        ("clawhub", Some((owner, slug))) => (version.to_string(), Some(crawl::clawhub::download_url(owner, slug, version))),
                        // a branch or tag is resolved to its commit so the report names exact code
                        ("GitHub", _) => {
                            let sha = if version.len() == 40 && version.bytes().all(|b| b.is_ascii_hexdigit()) { version.to_string() } else { crawl::github::head_sha(name, version)? };
                            (sha.clone(), Some(crawl::github::download_url(name, &sha)))
                        }
                        _ => (version.to_string(), None),
                    };
                    Item { source: "manual".into(), ecosystem: ecosystem.into(), name: name.into(), version, download, tools: None }
                }
            };
            let r = analyze::analyze_remote(&antidote_core::corpus::load()?, &item, &State::load(&state)?, &[])?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Cmd::Command { association } => {
            let mut body = String::new();
            std::io::stdin().read_to_string(&mut body)?;
            if let Some(c) = triage::parse_command(&body, &association) {
                println!("{}", serde_json::to_string(&c)?);
            }
        }
        Cmd::DraftEntry { report, classification, summary, issue_url, corpus } => {
            let r: Report = serde_json::from_slice(&fs::read(&report)?)?;
            println!("{}", triage::draft_entry(&r, &classification, &summary, &issue_url, &corpus)?.display());
        }
        Cmd::SeedOsv { corpus, npm_max, max } => {
            let names = seed::package_names(npm_max)?;
            let ids = seed::advisory_ids(&names)?;
            eprintln!("{} packages, {} advisories", names.len(), ids.len());
            let written = seed::import(&corpus, &ids, max)?;
            eprintln!("wrote {} new entries", written.len());
        }
        Cmd::McpProbe { timeout, cmd } => {
            let tools = antidote_core::probe::probe(&cmd, &[], std::time::Duration::from_secs(timeout))?;
            println!("{}", serde_json::to_string_pretty(&tools)?);
        }
        Cmd::DetonationReport { dir, previous_tools_hash } => {
            let d = detonate::report(&antidote_core::corpus::load()?, &dir, previous_tools_hash.as_deref())?;
            fs::write(dir.join("report.json"), serde_json::to_vec_pretty(&d)?)?;
            fs::write(dir.join("comment.md"), detonate::comment(&d))?;
            eprintln!("detonation score: {}", d.score);
        }
        Cmd::Allow { report, reason, allowlist } => {
            let r: Report = serde_json::from_slice(&fs::read(&report)?)?;
            let n = triage::allow(&r, &reason, &allowlist)?;
            eprintln!("added {n} allowlist rule(s)");
        }
    }
    Ok(())
}
