//! Talk to an MCP server over stdio just long enough to read its tool list.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

/// Start `cmd`, do `initialize` + `tools/list`, return the tools array. Kills the server afterwards.
pub fn probe(cmd: &[String], env: &[(String, String)], timeout: Duration) -> Result<Value> {
    let (prog, args) = cmd.split_first().context("empty server command")?;
    let mut child = Command::new(prog).args(args).envs(env.iter().cloned()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + timeout;
    let mut send = |v: Value| -> Result<()> { Ok(writeln!(stdin, "{v}")?) };
    let wait_for = |id: u64| -> Result<Value> {
        loop {
            let left = deadline.checked_duration_since(Instant::now()).context("MCP server timed out")?;
            let line = rx.recv_timeout(left).context("MCP server closed or timed out")?;
            // servers may log to stdout; skip anything that isn't our response
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if v["id"] == id {
                    return Ok(v);
                }
            }
        }
    };
    let result = (|| {
        send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "antidote-probe", "version": "0.1"}}}))?;
        wait_for(1)?;
        send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))?;
        let r = wait_for(2)?;
        if let Some(e) = r.get("error") {
            bail!("tools/list error: {e}");
        }
        Ok(r["result"]["tools"].clone())
    })();
    child.kill().ok();
    child.wait().ok();
    result
}
