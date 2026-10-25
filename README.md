# Antidote

An open database of malicious and vulnerable AI agent artifacts (skills, MCP servers, tool descriptions, prompts, packages), plus an offline scanner. Like ClamAV / OSV, but for AI agents.

> Working name. Status: phase 0+1 MVP.

## Scanner

```bash
cargo install --path crates/antidote-cli

antidote scan                          # auto-discover Claude Code / Cursor / OpenClaw / Claude Desktop config
antidote scan ./skills/my-skill        # scan a folder or file
antidote scan --mcp ~/.cursor/mcp.json # check the packages an MCP config launches
antidote check npm:mcp-remote@0.1.15   # look up one package
antidote scan --format json
```

Exit codes: `0` = no high/critical findings, `1` = high/critical found, `2` = error.

Works fully offline. The corpus is built into the binary. Nothing is uploaded.

What it checks:

| Layer | What |
|---|---|
| Hash | SHA-256 of every file vs `indicators.sha256` in the corpus |
| Signatures | [YARA-X](https://github.com/VirusTotal/yara-x) rules in `corpus/rules/`: hidden Unicode, instruction overrides, concealment, `<IMPORTANT>` blocks aimed at secrets, credential exfiltration, `curl \| sh`, encoded exec, reverse shells, Gatekeeper bypass |
| Packages | `npx`/`uvx`/`bunx`/`pnpm dlx` servers in any `mcpServers` block, matched against `affected` versions and OSV ranges |

The scanner gives deterministic verdicts only. No LLM decides whether something is safe.

## Corpus

- `schema/entry.schema.json`: an OSV extension. Artifact entries are `AGT-YYYY-NNNN`. Behavioral incidents are `AGT-INC-YYYY-NNNN`.
- `corpus/entries/`: one JSON file per entry. Each entry is sourced from public reports and links them in `references`.
- `corpus/rules/*.yar`: each rule has `meta: id, severity, description` and a sample in `crates/antidote-cli/tests/fixtures/bad/<id>.*`.

`cargo test` validates every entry against the schema. It checks that every rule fires on its sample and that nothing fires on `tests/fixtures/good/`.

## Not yet built

`antidote update` (signed feed), SARIF, GitHub Action, live MCP inspection and rug-pull diffing, `report` / `incident new`, tree-sitter code rules, typosquat detection, crawlers, sandbox detonation, classifier, website. See `../product-specs/antidote.md`.

## License

Code: Apache-2.0 (`LICENSE`). Data in `corpus/` and `schema/`: CC-BY-4.0 (`LICENSE-DATA`).
