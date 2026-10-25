//! `antidote incident new`: builds an AGT-INC entry from flags (asking for anything required that's
//! missing, when run in a terminal) and prints it with a prefilled GitHub issue link.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Result};
use antidote_core::corpus::{next_id, today};
use serde_json::{json, Value};

pub const TRIGGERS: &[&str] = &["prompt injection", "misconfiguration", "model error", "malicious tool"];
pub const IMPACTS: &[&str] = &["data loss", "data leak", "sandbox escape", "cost blowout", "code execution"];

#[derive(clap::Args)]
pub struct Args {
    /// One line, ≤200 chars: what happened
    #[arg(long)]
    summary: Option<String>,
    /// e.g. "Claude Code", "Cursor"
    #[arg(long)]
    agent: Option<String>,
    #[arg(long)]
    model: Option<String>,
    /// YYYY-MM or YYYY-MM-DD
    #[arg(long)]
    date: Option<String>,
    /// prompt injection | misconfiguration | model error | malicious tool
    #[arg(long)]
    trigger: Option<String>,
    /// data loss | data leak | sandbox escape | cost blowout | code execution
    #[arg(long)]
    impact: Option<String>,
    #[arg(long)]
    root_cause: Option<String>,
    /// A control that would have prevented it (repeatable)
    #[arg(long)]
    prevented: Vec<String>,
    /// Public source URL (repeatable; at least one)
    #[arg(long = "ref")]
    refs: Vec<String>,
    /// Related AGT entry ids (repeatable)
    #[arg(long)]
    related: Vec<String>,
    /// Maintainers: write the entry into this corpus dir with the next free id instead of printing a link
    #[arg(long)]
    write: Option<PathBuf>,
}

pub fn run(mut a: Args) -> Result<()> {
    let tty = std::io::stdin().is_terminal();
    let ask = |field: &mut Option<String>, prompt: &str| -> Result<()> {
        if field.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return Ok(());
        }
        if !tty {
            bail!("missing --{prompt}");
        }
        eprint!("{prompt}: ");
        std::io::stderr().flush()?;
        let mut l = String::new();
        std::io::stdin().lock().read_line(&mut l)?;
        *field = Some(l.trim().to_string()).filter(|s| !s.is_empty());
        if field.is_none() {
            bail!("{prompt} is required");
        }
        Ok(())
    };
    ask(&mut a.summary, "summary")?;
    ask(&mut a.date, "date")?;
    ask(&mut a.trigger, "trigger")?;
    ask(&mut a.impact, "impact")?;
    if a.refs.is_empty() {
        let mut r = None;
        ask(&mut r, "ref")?;
        a.refs.extend(r);
    }
    let summary = a.summary.unwrap();
    let (trigger, impact) = (a.trigger.unwrap().to_lowercase(), a.impact.unwrap().to_lowercase());
    if summary.chars().count() > 200 {
        bail!("summary is over 200 characters");
    }
    if !TRIGGERS.contains(&trigger.as_str()) {
        bail!("trigger must be one of: {}", TRIGGERS.join(", "));
    }
    if !IMPACTS.contains(&impact.as_str()) {
        bail!("impact must be one of: {}", IMPACTS.join(", "));
    }
    let date = a.date.unwrap();
    let ok_date = |d: &str| matches!(d.len(), 7 | 10) && d.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() });
    if !ok_date(&date) {
        bail!("date must be YYYY-MM or YYYY-MM-DD");
    }
    if let Some(r) = a.refs.iter().find(|r| !r.starts_with("https://") && !r.starts_with("http://")) {
        bail!("--ref must be a URL: {r}");
    }

    let mut e = json!({ "schema_version": "0.1.0", "id": "AGT-INC-YYYY-NNNN", "kind": "incident", "summary": summary, "date": date,
        "trigger": trigger, "impact": impact, "references": a.refs });
    let m = e.as_object_mut().unwrap();
    for (k, v) in [("agent", a.agent), ("model", a.model), ("root_cause", a.root_cause)] {
        if let Some(v) = v {
            m.insert(k.into(), Value::String(v));
        }
    }
    for (k, v) in [("would_have_prevented", a.prevented), ("related_entries", a.related)] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    if let Some(corpus) = a.write {
        let dir = corpus.join("entries");
        let id = next_id(&dir, &format!("AGT-INC-{}-", today().0))?;
        m.insert("id".into(), Value::String(id.clone()));
        let p = dir.join(format!("{id}.json"));
        std::fs::write(&p, serde_json::to_string_pretty(&e)? + "\n")?;
        eprintln!("wrote {}", p.display());
        return Ok(());
    }
    let pretty = serde_json::to_string_pretty(&e)?;
    println!("{pretty}");
    let body = format!("Submitted with `antidote incident new`. A maintainer assigns the id.\n\n```json\n{pretty}\n```\n");
    eprintln!("\nOpen this link to submit it:");
    println!("{}", crate::report::new_issue_url(&format!("Incident: {summary}"), &body));
    Ok(())
}
