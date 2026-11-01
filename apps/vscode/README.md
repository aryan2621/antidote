# Antidote for VS Code

Checks your MCP configs, agent skills and prompts against the [Antidote](https://aryan2621.github.io/antidote/) database of malicious and vulnerable AI agent artifacts. Findings show in the Problems panel, with the same signal words as the website: DANGER, WARNING, CAUTION.

- Scans the workspace on open and when an MCP config, `SKILL.md`, `CLAUDE.md`, `AGENTS.md` or Cursor rule is saved.
- **Antidote: Scan my agent setup** checks the configs your agents already use (Claude Code, Cursor, Gemini CLI, Windsurf…).
- Everything runs locally. On first use it downloads the `antidote` scanner from the GitHub release and checks its SHA-256. Set `antidote.path` to use your own build.
- "Nothing found" is never a safety verdict; it only means nothing in the database matched.
