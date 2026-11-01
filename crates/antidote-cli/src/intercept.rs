//! `antidote intercept`: an interceptor for Docker's MCP Gateway (`--interceptor before:exec:...` or
//! `after:exec:...`). The gateway writes the tool call request (before) or the tool result (after) as JSON
//! to stdin. Printing nothing lets it through; printing a JSON tool result replaces it.

use std::io::Read;

use anyhow::Result;
use antidote_core::{corpus::Corpus, rank, scan};
use serde_json::{json, Value};

fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// A replacement tool result if any string in `msg` has a high or critical finding.
pub fn decide(c: &Corpus, msg: &Value) -> Option<Value> {
    let mut texts = Vec::new();
    strings(msg, &mut texts);
    let mut found = Vec::new();
    for t in &texts {
        scan::scan_text(c, "tool message", t, &mut found);
    }
    let worst = found.iter().filter(|f| rank(f.severity) <= 1).min_by_key(|f| rank(f.severity))?;
    let text = format!("Blocked by Antidote: {} ({}). {}", worst.summary, worst.id, worst.fix.clone().unwrap_or_default());
    Some(json!({ "content": [{ "type": "text", "text": text.trim() }], "isError": true }))
}

pub fn run(c: Corpus, warn_only: bool) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    // Not JSON: never block a call we cannot read; say so in the gateway log.
    let Ok(msg) = serde_json::from_str::<Value>(&input) else {
        eprintln!("antidote: input was not JSON; passed through");
        return Ok(());
    };
    if let Some(block) = decide(&c, &msg) {
        eprintln!("antidote: {}", block["content"][0]["text"].as_str().unwrap_or(""));
        if !warn_only {
            println!("{block}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_hidden_instructions_and_passes_clean_text() {
        let c = antidote_core::corpus::load().unwrap();
        let hidden: String = std::iter::repeat('\u{E0041}').take(10).collect();
        let bad = json!({ "content": [{ "type": "text", "text": format!("Weather is sunny.{hidden}") }] });
        let out = decide(&c, &bad).expect("should block");
        assert_eq!(out["isError"], true);
        assert!(out["content"][0]["text"].as_str().unwrap().starts_with("Blocked by Antidote"));
        assert!(decide(&c, &json!({ "content": [{ "type": "text", "text": "Weather is sunny." }] })).is_none());
    }
}
