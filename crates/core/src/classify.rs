//! Prompt-injection classifier: sklearn `HashingVectorizer(analyzer="char_wb")` + logistic regression,
//! re-implemented here so the scanner needs no ML runtime. `ml/train.py` exports the weights.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

#[derive(Deserialize)]
struct ModelFile {
    version: String,
    n_features: usize,
    ngram: (usize, usize),
    bias: f32,
    threshold_medium: f32,
    threshold_high: f32,
    /// little-endian float16, base64
    weights: String,
}

pub struct Model {
    pub version: String,
    n_features: usize,
    ngram: (usize, usize),
    bias: f32,
    pub threshold_medium: f32,
    pub threshold_high: f32,
    weights: Vec<f32>,
}

impl Model {
    pub fn from_json(s: &str) -> Result<Model> {
        let m: ModelFile = serde_json::from_str(s).context("model file")?;
        let raw = base64::engine::general_purpose::STANDARD.decode(&m.weights).context("model weights")?;
        if raw.len() != m.n_features * 2 {
            bail!("model has {} weight bytes, expected {}", raw.len(), m.n_features * 2);
        }
        let weights = raw.chunks_exact(2).map(|b| f16_to_f32(u16::from_le_bytes([b[0], b[1]]))).collect();
        Ok(Model {
            version: m.version,
            n_features: m.n_features,
            ngram: m.ngram,
            bias: m.bias,
            threshold_medium: m.threshold_medium,
            threshold_high: m.threshold_high,
            weights,
        })
    }

    /// Probability that `text` is a prompt-injection attempt.
    pub fn score(&self, text: &str) -> f32 {
        let mut counts: std::collections::HashMap<usize, f32> = std::collections::HashMap::new();
        char_wb_ngrams(&text.to_lowercase(), self.ngram, |g| {
            *counts.entry(index(g, self.n_features)).or_default() += 1.0;
        });
        let norm = counts.values().map(|v| v * v).sum::<f32>().sqrt();
        if norm == 0.0 {
            return sigmoid(self.bias);
        }
        let dot: f32 = counts.iter().map(|(i, v)| self.weights[*i] * v / norm).sum();
        sigmoid(dot + self.bias)
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// sklearn `_char_wb_ngrams`: pad each whitespace-split word with one space on each side.
fn char_wb_ngrams(text: &str, (lo, hi): (usize, usize), mut emit: impl FnMut(&str)) {
    let mut buf = String::new();
    for word in text.split_whitespace() {
        let w: Vec<char> = std::iter::once(' ').chain(word.chars()).chain(std::iter::once(' ')).collect();
        for n in lo..=hi {
            let mut offset = 0;
            loop {
                buf.clear();
                buf.extend(&w[offset..(offset + n).min(w.len())]);
                emit(&buf);
                if offset + n >= w.len() {
                    break;
                }
                offset += 1;
            }
            if offset == 0 {
                break; // a word shorter than n is counted once, like sklearn
            }
        }
    }
}

/// sklearn `_hashing_fast`: signed MurmurHash3 x86_32 (seed 0), `abs(h) % n`, with its special case for i32::MIN.
fn index(token: &str, n: usize) -> usize {
    let h = murmur3_32(token.as_bytes(), 0) as i32;
    if h == i32::MIN {
        (2_147_483_647 - (n - 1)) % n
    } else {
        h.unsigned_abs() as usize % n
    }
}

fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let chunks = data.chunks_exact(4);
    let tail = chunks.remainder();
    for c in chunks {
        let k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]).wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h = (h ^ k).rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let mut k = 0u32;
    for (i, b) in tail.iter().enumerate() {
        k |= u32::from(*b) << (8 * i);
    }
    if !tail.is_empty() {
        h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

fn f16_to_f32(h: u16) -> f32 {
    let sign = u32::from(h >> 15) << 31;
    let exp = u32::from((h >> 10) & 0x1f);
    let frac = u32::from(h & 0x3ff);
    let bits = match (exp, frac) {
        (0, 0) => sign,
        (0, f) => {
            // subnormal: renormalize
            let shift = f.leading_zeros() - 21;
            sign | ((113 - shift) << 23) | ((f << (shift + 1)) & 0x3ff) << 13
        }
        (31, 0) => sign | 0x7f80_0000,
        (31, f) => sign | 0x7f80_0000 | (f << 13),
        (e, f) => sign | ((e + 112) << 23) | (f << 13),
    };
    f32::from_bits(bits)
}

/// Files whose prose is meant for an agent: skills, rules, agent instructions, MCP tool JSON.
/// READMEs and code are skipped; the n-gram model has no signal there and YARA covers code.
pub fn is_prompt_file(path: &std::path::Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if matches!(name.as_str(), "skill.md" | "claude.md" | "agents.md" | "gemini.md" | ".cursorrules" | ".windsurfrules")
        || name.ends_with(".mdc")
        || name.ends_with(".json")
    {
        return true;
    }
    name.ends_with(".md")
        && path.components().any(|c| matches!(c.as_os_str().to_str(), Some("skills" | "commands" | "agents" | "prompts" | "rules")))
}

const JSON_KEYS: &[&str] = &["description", "instructions", "prompt", "system_prompt", "systemPrompt"];

/// (1-based line, text) pieces to score. Mirrored by `segments_md` in ml/train.py: change both together.
pub fn segments(path: &std::path::Path, text: &str) -> Vec<(usize, String)> {
    if path.extension().is_some_and(|e| e == "json") {
        let mut out = Vec::new();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            json_strings(&v, &mut |s| {
                // locate the value in the raw file for a line number; escapes may hide it, then line 1
                let needle = serde_json::to_string(&s.chars().take(30).collect::<String>()).unwrap_or_default();
                let needle = needle.trim_matches('"');
                let line = text.find(needle).map_or(1, |i| text[..i].matches('\n').count() + 1);
                out.push((line, s.to_string()));
            });
        }
        return out;
    }
    segments_md(text)
}

fn json_strings(v: &serde_json::Value, f: &mut impl FnMut(&str)) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m {
                match child.as_str() {
                    Some(s) if JSON_KEYS.contains(&k.as_str()) && s.len() >= 20 => f(s),
                    _ => json_strings(child, f),
                }
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|c| json_strings(c, f)),
        _ => {}
    }
}

/// Paragraphs outside code fences, headings on their own, plus the frontmatter `description`.
pub fn segments_md(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let (mut para, mut start) = (Vec::<&str>::new(), 0);
    let flush = |para: &mut Vec<&str>, start: usize, out: &mut Vec<(usize, String)>| {
        let joined = para.join(" ");
        if joined.chars().count() >= 20 {
            out.push((start, joined));
        }
        para.clear();
    };
    let (mut in_front, mut in_fence) = (false, false);
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if i == 0 && t == "---" {
            in_front = true;
            continue;
        }
        if in_front {
            if t == "---" {
                in_front = false;
            } else if let Some(d) = t.strip_prefix("description:") {
                let d = d.trim().trim_matches(|c| c == '"' || c == '\'');
                if d.chars().count() >= 20 {
                    out.push((i + 1, d.to_string()));
                }
            }
            continue;
        }
        if t.starts_with("```") {
            flush(&mut para, start, &mut out);
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            flush(&mut para, start, &mut out);
            if t.starts_with('#') {
                para.push(t);
                start = i + 1;
                flush(&mut para, start, &mut out);
            }
            continue;
        }
        if para.is_empty() {
            start = i + 1;
        }
        para.push(t);
    }
    flush(&mut para, start, &mut out);
    out
}
