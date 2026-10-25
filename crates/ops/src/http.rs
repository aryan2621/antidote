use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Context, Result};

const UA: &str = "antidote-crawler/0.1 (+https://github.com/antidote-db/antidote)";

/// GET with a polite User-Agent, retrying 429/5xx (honours `Retry-After`) and capping the body size.
pub fn get(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    for attempt in 0..4u32 {
        let mut resp = agent.get(url).header("User-Agent", UA).call().with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();
        if status == 429 || status >= 500 {
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                .unwrap_or(0)
                .max(2u64.pow(attempt + 1)) // some registries send `Retry-After: 0`
                .min(120);
            eprintln!("{status} from {url}, retrying in {wait}s");
            sleep(Duration::from_secs(wait));
            continue;
        }
        if status != 200 {
            bail!("GET {url}: HTTP {status}");
        }
        return Ok(resp.body_mut().with_config().limit(max_bytes).read_to_vec()?);
    }
    bail!("GET {url}: still failing after retries")
}

pub fn get_json(url: &str) -> Result<serde_json::Value> {
    serde_json::from_slice(&get(url, 20 << 20)?).with_context(|| format!("{url} returned invalid JSON"))
}

/// Minimal percent-encoding for query values (cursors contain JSON).
pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
