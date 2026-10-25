//! Corpus loading, signed feed, and the scan engine shared by the `antidote` CLI and `antidote-ops`.

pub mod classify;
pub mod corpus;
pub mod feed;
pub mod mcp;
pub mod probe;
pub mod review;
pub mod scan;

use serde::Serialize;

#[derive(Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub id: String,
    pub summary: String,
    pub path: String,
    pub line: Option<usize>,
    /// e.g. which MCP server in a config file
    pub context: Option<String>,
    pub evidence: Option<String>,
    /// filled only by opt-in LLM review
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// 0 = critical … 3 = low; lower is worse.
pub fn rank(sev: &str) -> u8 {
    match sev {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    }
}
