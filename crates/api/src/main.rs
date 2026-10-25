//! `antidote-api [--feed feed.json] [--db stats.sqlite] [--listen 0.0.0.0:8080]`
//! Without --feed it serves the built-in corpus. With it, feed.json.minisig must sit next to it; the
//! pair is re-checked every minute and swapped in when a newer verified feed appears.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};
use antidote_api::{router, App, Loaded};

#[tokio::main]
async fn main() -> Result<()> {
    let (mut feed, mut db, mut listen) = (None::<PathBuf>, PathBuf::from("antidote-stats.sqlite"), "0.0.0.0:8080".to_string());
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| anyhow::anyhow!("{a} needs a value"));
        match a.as_str() {
            "--feed" => feed = Some(val()?.into()),
            "--db" => db = val()?.into(),
            "--listen" => listen = val()?,
            _ => bail!("usage: antidote-api [--feed feed.json] [--db stats.sqlite] [--listen addr]"),
        }
    }
    let pubkey = std::env::var("ANTIDOTE_FEED_PUBKEY").unwrap_or_else(|_| antidote_core::feed::PUBLIC_KEY.to_string());
    let loaded = match &feed {
        Some(p) => Loaded::from_file(p, &pubkey)?,
        None => Loaded::embedded()?,
    };
    eprintln!("serving corpus version {} on {listen}", loaded.version);
    let app = App::new(loaded, rusqlite::Connection::open(&db)?)?;

    if let Some(p) = feed {
        let app = app.clone();
        tokio::spawn(async move {
            let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
            let mut last = mtime(&p);
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let now = mtime(&p);
                if now == last {
                    continue;
                }
                last = now;
                let current = app.feed.read().unwrap().version;
                match Loaded::from_file(&p, &pubkey) {
                    Ok(l) if l.version >= current => {
                        eprintln!("reloaded corpus version {}", l.version);
                        *app.feed.write().unwrap() = std::sync::Arc::new(l);
                    }
                    Ok(l) => eprintln!("ignoring feed version {} older than {current}", l.version),
                    Err(e) => eprintln!("keeping corpus {current}: {e:#}"),
                }
            }
        });
    }
    axum::serve(tokio::net::TcpListener::bind(&listen).await?, router(app)).await?;
    Ok(())
}
