//! HTTP API over a verified feed: the signed feed files, entries, package checks, README badges and
//! opt-in rule-hit counts (`antidote stats on`). Stats hold rule ids and counts only.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use antidote_core::{corpus, feed::Feed, mcp, Finding};
use axum::extract::{DefaultBodyLimit, Path as UrlPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

pub struct Loaded {
    pub version: u64,
    data: Vec<u8>,
    sig: Option<String>,
    corpus: corpus::Corpus,
    entries: HashMap<String, Value>,
}

impl Loaded {
    /// The corpus built into this binary (no signature to serve); for development.
    pub fn embedded() -> Result<Loaded> {
        let feed = Feed::embedded();
        Loaded::new(serde_json::to_vec(&feed)?, None, feed)
    }

    /// `feed.json` plus `feed.json.minisig` next to it, checked against `pubkey`.
    pub fn from_file(path: &Path, pubkey: &str) -> Result<Loaded> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let sig_path = format!("{}.minisig", path.display());
        let sig = std::fs::read_to_string(&sig_path).with_context(|| format!("reading {sig_path}"))?;
        let feed = antidote_core::feed::verify(pubkey, &data, &sig)?;
        Loaded::new(data, Some(sig), feed)
    }

    fn new(data: Vec<u8>, sig: Option<String>, feed: Feed) -> Result<Loaded> {
        let corpus = corpus::compile(&feed)?;
        let entries = feed.entries.iter().filter_map(|e| Some((e["id"].as_str()?.to_string(), e.clone()))).collect();
        Ok(Loaded { version: feed.version, data, sig, corpus, entries })
    }
}

pub struct App {
    pub feed: RwLock<Arc<Loaded>>,
    db: Mutex<rusqlite::Connection>,
}

impl App {
    pub fn new(feed: Loaded, db: rusqlite::Connection) -> Result<Arc<App>> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS hits (rule_id TEXT PRIMARY KEY, n INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS reports (corpus_version INTEGER PRIMARY KEY, n INTEGER NOT NULL);",
        )?;
        Ok(Arc::new(App { feed: RwLock::new(Arc::new(feed)), db: Mutex::new(db) }))
    }

    fn feed(&self) -> Arc<Loaded> {
        self.feed.read().unwrap().clone()
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/feed.json", get(feed_json))
        .route("/v1/feed.json.minisig", get(feed_sig))
        .route("/v1/entries/{id}", get(entry))
        .route("/v1/check/{ecosystem}/{*name}", get(check))
        .route("/badge/{ecosystem}/{*name}", get(badge))
        .route("/v1/stats", get(stats_get).post(stats_post))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(app)
}

async fn feed_json(State(app): State<Arc<App>>) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], app.feed().data.clone()).into_response()
}

async fn feed_sig(State(app): State<Arc<App>>) -> Response {
    match &app.feed().sig {
        Some(s) => ([(header::CONTENT_TYPE, "text/plain")], s.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "this server runs the built-in corpus; it has no signature").into_response(),
    }
}

async fn entry(State(app): State<Arc<App>>, UrlPath(id): UrlPath<String>) -> Response {
    match app.feed().entries.get(id.trim_end_matches(".json")) {
        Some(e) => Json(e.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "no such entry"}))).into_response(),
    }
}

#[derive(Deserialize)]
struct Ver {
    version: Option<String>,
}

fn lookup(app: &App, ecosystem: &str, name: &str, version: Option<&str>) -> Option<Vec<Finding>> {
    let sep = if ecosystem.eq_ignore_ascii_case("pypi") { "==" } else { "@" };
    let spec = format!("{ecosystem}:{name}{}", version.map(|v| format!("{sep}{v}")).unwrap_or_default());
    let r = mcp::parse_ref(&spec)?;
    let mut out = Vec::new();
    mcp::check(&app.feed().corpus, &r, &spec, None, &mut out);
    Some(out)
}

async fn check(State(app): State<Arc<App>>, UrlPath((eco, name)): UrlPath<(String, String)>, Query(q): Query<Ver>) -> Response {
    match lookup(&app, &eco, &name, q.version.as_deref()) {
        Some(f) => Json(f).into_response(),
        None => (StatusCode::BAD_REQUEST, Json(json!({"error": "ecosystem must be npm or pypi"}))).into_response(),
    }
}

/// Shields-style badge for the latest release (`?version=` for a specific one).
async fn badge(State(app): State<Arc<App>>, UrlPath((eco, name)): UrlPath<(String, String)>, Query(q): Query<Ver>) -> Response {
    let Some(name) = name.strip_suffix(".svg") else { return StatusCode::NOT_FOUND.into_response() };
    let Some(f) = lookup(&app, &eco, name, q.version.as_deref()) else { return StatusCode::NOT_FOUND.into_response() };
    let mut ids: Vec<&str> = f.iter().map(|f| f.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    let (msg, color) = if f.iter().any(|f| f.severity == "critical") {
        ("malicious".to_string(), "#e05d44")
    } else if ids.is_empty() {
        ("no known threats".to_string(), "#4c1")
    } else {
        (format!("{} advisor{}", ids.len(), if ids.len() == 1 { "y" } else { "ies" }), "#fe7d37")
    };
    ([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "max-age=3600")], svg("antidote", &msg, color)).into_response()
}

fn svg(label: &str, msg: &str, color: &str) -> String {
    // shortcut: width from a fixed per-char estimate (Verdana 11px ≈ 6.5px); measure glyphs if labels look off
    let w = |s: &str| (s.chars().count() as f32 * 6.5 + 10.0).round() as u32;
    let (lw, mw) = (w(label), w(msg));
    let t = lw + mw;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{t}" height="20" role="img" aria-label="{label}: {msg}"><title>{label}: {msg}</title><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{mw}" height="20" fill="{color}"/><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="{}" y="14">{label}</text><text x="{}" y="14">{msg}</text></g></svg>"##,
        lw / 2,
        lw + mw / 2
    )
}

#[derive(Deserialize)]
struct StatsIn {
    corpus_version: u64,
    counts: BTreeMap<String, u64>,
}

fn valid_id(id: &str) -> bool {
    id.len() <= 40 && id.strip_prefix("AGT-").is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'))
}

async fn stats_post(State(app): State<Arc<App>>, Json(s): Json<StatsIn>) -> Response {
    if s.counts.len() > 500 || !s.counts.iter().all(|(k, n)| valid_id(k) && *n <= 100_000) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "counts must be ≤500 AGT-* rule ids with counts ≤100000"}))).into_response();
    }
    let r = (|| -> rusqlite::Result<()> {
        let mut db = app.db.lock().unwrap();
        let tx = db.transaction()?;
        for (k, n) in &s.counts {
            tx.execute("INSERT INTO hits VALUES (?1, ?2) ON CONFLICT(rule_id) DO UPDATE SET n = n + excluded.n", (k, *n as i64))?;
        }
        tx.execute("INSERT INTO reports VALUES (?1, 1) ON CONFLICT(corpus_version) DO UPDATE SET n = n + 1", [s.corpus_version as i64])?;
        tx.commit()
    })();
    match r {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn stats_get(State(app): State<Arc<App>>) -> Response {
    let r = (|| -> rusqlite::Result<Value> {
        let db = app.db.lock().unwrap();
        let reports: i64 = db.query_row("SELECT COALESCE(SUM(n), 0) FROM reports", [], |r| r.get(0))?;
        let mut q = db.prepare("SELECT rule_id, n FROM hits ORDER BY n DESC")?;
        let counts: serde_json::Map<String, Value> = q.query_map([], |r| Ok((r.get::<_, String>(0)?, json!(r.get::<_, i64>(1)?))))?.collect::<Result<_, _>>()?;
        Ok(json!({ "reports": reports, "counts": counts }))
    })();
    match r {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}
