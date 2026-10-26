//! Structural code rules: tree-sitter queries (`corpus/rules/<id>.<js|py|sh>.scm`) run on JS/TS/Python/shell
//! sources. Each query marks the reported node with `@hit`; its header comments give the metadata.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

use crate::Finding;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Lang {
    Js,
    Ts,
    Tsx,
    Py,
    Sh,
}

impl Lang {
    fn language(self) -> Language {
        match self {
            Lang::Js => tree_sitter_javascript::LANGUAGE.into(),
            Lang::Ts => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Lang::Py => tree_sitter_python::LANGUAGE.into(),
            Lang::Sh => tree_sitter_bash::LANGUAGE.into(),
        }
    }

    pub fn of(p: &Path) -> Option<Lang> {
        Some(match p.extension()?.to_str()? {
            "js" | "mjs" | "cjs" | "jsx" => Lang::Js,
            "ts" | "mts" | "cts" => Lang::Ts,
            "tsx" => Lang::Tsx,
            "py" => Lang::Py,
            "sh" | "bash" | "zsh" => Lang::Sh,
            _ => return None,
        })
    }
}

pub struct Rule {
    pub id: String,
    pub severity: &'static str,
    pub description: String,
    lang: Lang,
    query: Query,
    hit: u32,
}

/// `name` is the file stem, e.g. `AGT-T-0001.js`; JS rules also run on TypeScript.
pub fn compile(name: &str, src: &str) -> Result<Vec<Rule>> {
    let header = |key: &str| {
        src.lines().find_map(|l| l.strip_prefix(';')?.trim().strip_prefix(key)?.strip_prefix(':').map(|v| v.trim().to_string()))
    };
    let id = header("id").with_context(|| format!("rules/{name}.scm has no `; id:` line"))?;
    let langs: &[Lang] = match name.rsplit('.').next() {
        Some("js") => &[Lang::Js, Lang::Ts, Lang::Tsx],
        Some("py") => &[Lang::Py],
        Some("sh") => &[Lang::Sh],
        _ => bail!("rules/{name}.scm: name must end in .js.scm, .py.scm or .sh.scm"),
    };
    let severity = match header("severity").as_deref() {
        Some("critical") => "critical",
        Some("high") => "high",
        Some("low") => "low",
        _ => "medium",
    };
    let description = header("description").unwrap_or_default();
    langs
        .iter()
        .map(|&lang| {
            let query = Query::new(&lang.language(), src).with_context(|| format!("compiling rules/{name}.scm for {lang:?}"))?;
            let hit = query.capture_index_for_name("hit").with_context(|| format!("rules/{name}.scm has no @hit capture"))?;
            Ok(Rule { id: id.clone(), severity, description: description.clone(), lang, query, hit })
        })
        .collect()
}

pub fn scan(rules: &[Rule], lang: Lang, src: &[u8], path: &str, out: &mut Vec<Finding>) {
    let mut rules = rules.iter().filter(|r| r.lang == lang).peekable();
    if rules.peek().is_none() {
        return;
    }
    let mut parser = Parser::new();
    if parser.set_language(&lang.language()).is_err() {
        return;
    }
    let Some(tree) = parser.parse(src, None) else { return };
    let mut seen = std::collections::HashSet::new();
    for r in rules {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&r.query, tree.root_node(), src);
        while let Some(m) = matches.next() {
            let Some(c) = m.captures().iter().find(|c| c.index == r.hit) else { continue };
            let line = c.node.start_position().row + 1;
            if !seen.insert((r.id.as_str(), line)) {
                continue;
            }
            let text = String::from_utf8_lossy(&src[c.node.byte_range()]);
            out.push(Finding {
                severity: r.severity,
                id: r.id.clone(),
                summary: r.description.clone(),
                path: path.to_string(),
                line: Some(line),
                context: None,
                evidence: Some(text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(80).collect()),
                explanation: None,
                fix: Some("Don't run this package until you've reviewed this code".into()),
            });
        }
    }
}
