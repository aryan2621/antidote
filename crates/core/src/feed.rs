use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// shortcut: placeholder home, change when the GitHub repo exists.
pub const FEED_URL: &str = "https://antidote-db.github.io/antidote/feed/feed.json";
/// minisign public key (base64 line of the .pub file), set at build time. Empty → `update` refuses.
pub const PUBLIC_KEY: &str = match option_env!("ANTIDOTE_FEED_PUBKEY") {
    Some(k) => k,
    None => "",
};

static CORPUS: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../corpus");

/// The whole corpus as one signable document.
#[derive(Serialize, Deserialize)]
pub struct Feed {
    /// Unix time of the last corpus commit; newer feeds replace older ones, never the reverse.
    pub version: u64,
    pub entries: Vec<Value>,
    /// rule file stem → YARA source
    pub rules: BTreeMap<String, String>,
    /// model file stem → model JSON (see classify.rs); absent in pre-classifier feeds
    #[serde(default)]
    pub models: BTreeMap<String, String>,
    /// ecosystem → popular package names, for typosquat checks; absent in older feeds
    #[serde(default)]
    pub popular: BTreeMap<String, Vec<String>>,
}

impl Feed {
    pub fn embedded() -> Feed {
        let version = option_env!("ANTIDOTE_CORPUS_VERSION").and_then(|v| v.parse().ok()).unwrap_or(0);
        let files = |dir: &str| {
            CORPUS.get_dir(dir).map(|d| d.files()).into_iter().flatten().map(|f| (f.path().to_path_buf(), f.contents().to_vec()))
        };
        Feed::from_files(version, files("entries"), files("rules"), files("models"), files("popular")).expect("built-in corpus is invalid")
    }

    /// Build from a corpus checkout (`entries/*.json`, `rules/*.yar`).
    pub fn from_dir(dir: &Path, version: u64) -> Result<Feed> {
        let files = |sub: &str| -> Result<Vec<(PathBuf, Vec<u8>)>> {
            let mut v = Vec::new();
            for e in fs::read_dir(dir.join(sub)).with_context(|| format!("reading {}", dir.join(sub).display()))? {
                let p = e?.path();
                v.push((p.clone(), fs::read(&p)?));
            }
            Ok(v)
        };
        let models = if dir.join("models").is_dir() { files("models")? } else { vec![] };
        let popular = if dir.join("popular").is_dir() { files("popular")? } else { vec![] };
        Feed::from_files(version, files("entries")?, files("rules")?, models, popular)
    }

    fn from_files(
        version: u64,
        entries: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
        rules: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
        models: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
        popular: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
    ) -> Result<Feed> {
        let mut feed = Feed { version, entries: Vec::new(), rules: BTreeMap::new(), models: BTreeMap::new(), popular: BTreeMap::new() };
        for (p, data) in popular {
            if p.extension().is_some_and(|e| e == "txt") {
                let name = p.file_stem().unwrap().to_string_lossy().into_owned();
                feed.popular.insert(name, String::from_utf8_lossy(&data).lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect());
            }
        }
        for (p, data) in models {
            if p.extension().is_some_and(|e| e == "json") {
                let name = p.file_stem().unwrap().to_string_lossy().into_owned();
                feed.models.insert(name, String::from_utf8(data).with_context(|| format!("model {} not utf-8", p.display()))?);
            }
        }
        for (p, data) in entries {
            if p.extension().is_some_and(|e| e == "json") {
                feed.entries.push(serde_json::from_slice(&data).with_context(|| format!("entry {}", p.display()))?);
            }
        }
        feed.entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        for (p, data) in rules {
            if p.extension().is_some_and(|e| e == "yar") {
                let name = p.file_stem().unwrap().to_string_lossy().into_owned();
                feed.rules.insert(name, String::from_utf8(data).with_context(|| format!("rule {} not utf-8", p.display()))?);
            }
        }
        Ok(feed)
    }
}

/// Check `sig` against `pubkey` before parsing anything in `data`.
pub fn verify(pubkey: &str, data: &[u8], sig: &str) -> Result<Feed> {
    if pubkey.is_empty() {
        bail!("this build has no feed signing key; rebuild with the release key set in feed.rs");
    }
    let pk = minisign_verify::PublicKey::from_base64(pubkey).map_err(|e| anyhow::anyhow!("bad public key: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig).map_err(|e| anyhow::anyhow!("bad signature file: {e}"))?;
    pk.verify(data, &sig, false).map_err(|e| anyhow::anyhow!("feed signature check failed: {e}"))?;
    serde_json::from_slice(data).context("feed is not valid JSON")
}

fn cache_dir() -> PathBuf {
    dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("antidote")
}

/// A verified cached feed that is newer than the built-in corpus, if there is one.
pub fn cached(min_version: u64) -> Option<Feed> {
    let dir = cache_dir();
    let data = fs::read(dir.join("feed.json")).ok()?;
    let sig = fs::read_to_string(dir.join("feed.json.minisig")).ok()?;
    match verify(PUBLIC_KEY, &data, &sig) {
        Ok(f) if f.version > min_version => Some(f),
        Ok(_) => None,
        Err(e) => {
            eprintln!("warning: ignoring cached feed in {}: {e:#}", dir.display());
            None
        }
    }
}

/// Verify a downloaded feed and store it if newer. Returns the version now in use.
pub fn install(pubkey: &str, data: &[u8], sig: &str, current: u64, dir: &Path) -> Result<u64> {
    let feed = verify(pubkey, data, sig)?;
    if feed.version < current {
        bail!("feed version {} is older than the installed {current}; refusing rollback", feed.version);
    }
    if feed.version == current {
        return Ok(current);
    }
    fs::create_dir_all(dir)?;
    // signature first, so a crash between writes leaves a pair that fails verification, not a stale-but-valid one
    fs::write(dir.join("feed.json.minisig"), sig)?;
    fs::write(dir.join("feed.json"), data)?;
    Ok(feed.version)
}

pub fn update(url: &str, current: u64) -> Result<u64> {
    let get = |u: &str| -> Result<Vec<u8>> {
        Ok(ureq::get(u).call().with_context(|| format!("GET {u}"))?.body_mut().read_to_vec()?)
    };
    let data = get(url)?;
    let sig = String::from_utf8(get(&format!("{url}.minisig"))?).context("signature not utf-8")?;
    install(PUBLIC_KEY, &data, &sig, current, &cache_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(feed: &Feed) -> (String, Vec<u8>, String) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let data = serde_json::to_vec(feed).unwrap();
        let sig = minisign::sign(None, &kp.sk, &data[..], None, None).unwrap().into_string();
        (kp.pk.to_base64(), data, sig)
    }

    #[test]
    fn signed_feed_round_trips_and_rejects_tampering_and_rollback() {
        let mut feed = Feed::embedded();
        feed.version = 100;
        let (pk, data, sig) = signed(&feed);
        let dir = std::env::temp_dir().join(format!("antidote-test-{}", std::process::id()));

        assert_eq!(verify(&pk, &data, &sig).unwrap().entries.len(), feed.entries.len());
        assert_eq!(install(&pk, &data, &sig, 99, &dir).unwrap(), 100);

        let mut tampered = data.clone();
        *tampered.last_mut().unwrap() = b' ';
        assert!(verify(&pk, &tampered, &sig).is_err());
        assert_eq!(install(&pk, &data, &sig, 100, &dir).unwrap(), 100, "same version is a no-op");
        assert!(install(&pk, &data, &sig, 101, &dir).is_err(), "rollback");

        let (other_pk, _, _) = signed(&feed);
        assert!(verify(&other_pk, &data, &sig).is_err());
        assert!(verify("", &data, &sig).is_err());
        fs::remove_dir_all(dir).ok();
    }
}
