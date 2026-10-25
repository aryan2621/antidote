//! Antidote desktop: the scanner for people who don't use the CLI. Calls antidote-core directly;
//! everything runs locally, and only "Update" touches the network (signed feed).

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use antidote_core::{corpus, discover, feed, mcp, rank, scan, Finding};
use serde_json::{json, Value};
use tauri::State;

struct App(RwLock<Arc<corpus::Corpus>>);

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn corpus(app: &State<App>) -> Arc<corpus::Corpus> {
    app.0.read().unwrap().clone()
}

fn sorted(mut f: Vec<Finding>) -> Vec<Finding> {
    f.sort_by_key(|f| rank(f.severity));
    f
}

#[tauri::command]
fn info(app: State<App>) -> Value {
    let c = corpus(&app);
    json!({ "version": c.version, "entries": c.entries.len() })
}

/// Folders and MCP configs a bare `antidote scan` would check on this machine.
#[tauri::command]
fn targets() -> Value {
    let (trees, configs) = discover::targets();
    json!({ "trees": trees, "configs": configs })
}

/// Scans run off the UI thread: big folders take seconds.
#[tauri::command]
async fn scan(app: State<'_, App>, trees: Vec<PathBuf>, configs: Vec<PathBuf>) -> Res<Vec<Finding>> {
    let c = corpus(&app);
    tauri::async_runtime::spawn_blocking(move || {
        let mut out = Vec::new();
        for p in &trees {
            scan::scan_tree(&c, p, &mut out);
        }
        for p in &configs {
            scan::scan_mcp_config(&c, p, &mut out);
        }
        sorted(out)
    })
    .await
    .map_err(err)
}

#[tauri::command]
fn check(app: State<App>, package: String) -> Res<Vec<Finding>> {
    let r = mcp::parse_ref(package.trim()).ok_or("Use npm:<name>[@version] or pypi:<name>[==version]")?;
    let mut out = Vec::new();
    mcp::check(&corpus(&app), &r, package.trim(), None, &mut out);
    Ok(sorted(out))
}

/// Fetch and verify the signed feed, then swap in the new corpus.
#[tauri::command]
async fn update(app: State<'_, App>) -> Res<Value> {
    let current = corpus(&app).version;
    let c = tauri::async_runtime::spawn_blocking(move || -> anyhow::Result<corpus::Corpus> {
        feed::update(feed::FEED_URL, current)?;
        corpus::load()
    })
    .await
    .map_err(err)?
    .map_err(|e| format!("{e:#}"))?;
    let v = json!({ "version": c.version, "entries": c.entries.len(), "changed": c.version != current });
    *app.0.write().unwrap() = Arc::new(c);
    Ok(v)
}

pub fn run() {
    let c = corpus::load().expect("built-in corpus is invalid");
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(App(RwLock::new(Arc::new(c))))
        .invoke_handler(tauri::generate_handler![info, targets, scan, check, update])
        .run(tauri::generate_context!())
        .expect("error while running Antidote");
}
