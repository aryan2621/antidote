use std::path::PathBuf;

/// Default targets for a bare `antidote scan`: (folders to scan fully, MCP config files).
/// Paths that don't exist are dropped.
pub fn targets() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = dirs::home_dir().unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();
    let trees = [
        home.join(".claude/skills"),
        home.join(".claude/plugins"),
        home.join(".claude/commands"),
        home.join(".openclaw/skills"),
        home.join(".openclaw/workspace/skills"),
        home.join(".cursor/rules"),
        cwd.join(".claude/skills"),
        cwd.join(".claude/commands"),
        cwd.join(".cursor/rules"),
        cwd.join("skills"),
    ];
    let configs = [
        home.join(".claude.json"),
        home.join(".cursor/mcp.json"),
        home.join(".openclaw/openclaw.json"),
        // ~/Library/Application Support, ~/.config or %APPDATA%
        dirs::config_dir().unwrap_or_default().join("Claude/claude_desktop_config.json"),
        cwd.join(".mcp.json"),
        cwd.join(".cursor/mcp.json"),
    ];
    let keep = |v: &[PathBuf]| v.iter().filter(|p| p.exists()).cloned().collect();
    (keep(&trees), keep(&configs))
}
