# Antidote

An open database of malicious and vulnerable AI agent artifacts (skills, MCP servers, tool descriptions, prompts, packages), plus an offline scanner. Like ClamAV / OSV, but for AI agents.

> Working name. Status: phase 2 (scanner, signed feed, GitHub Action, website). Not yet published; `antidote-db/antidote` is a placeholder.

## Scanner

```bash
cargo install --path crates/antidote-cli

antidote scan                          # auto-discover Claude Code / Cursor / OpenClaw / Claude Desktop config
antidote scan ./skills/my-skill        # scan a folder or file
antidote scan --mcp ~/.cursor/mcp.json # check the packages an MCP config launches
antidote check npm:mcp-remote@0.1.15   # look up one package
antidote update                        # fetch the latest signed corpus feed
antidote scan --format json|sarif
antidote scan --fail-on medium         # critical|high (default)|medium|low|never
```

Exit codes: `0` = nothing at or above `--fail-on`, `1` = findings at or above it, `2` = error.

Scanning is fully offline. It uses the corpus built into the binary, or a newer one fetched by `antidote update`. `update` is the only command that touches the network. It accepts a feed only if the minisign signature checks out and the version is newer, so an old feed can't be replayed. The cache is re-verified on every run, and a tampered cache falls back to the built-in corpus. Nothing is ever uploaded.

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: antidote-db/antidote@v0
    with:
      paths: .claude .cursor skills   # default "."
      fail-on: high
```

Findings show up in the repo's Security → Code scanning tab.

### pre-commit

```yaml
- repo: https://github.com/antidote-db/antidote
  rev: v0.1.0
  hooks: [{ id: antidote }]   # needs `antidote` on PATH
```

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

## Website

`web/` is an Astro site with a search page, one page per entry, and an "is X safe?" page per package. It is built from `corpus/entries` and deployed with the signed feed to GitHub Pages by `.github/workflows/pages.yml`. To run it locally: `cd web && npm install && npm run dev`.

## Releasing (maintainers)

1. Generate the feed key once: `minisign -G -W -p antidote.pub -s antidote.key`. Store the second line of `antidote.pub` as the repo variable `ANTIDOTE_FEED_PUBKEY`. Store the contents of `antidote.key` as the secret `MINISIGN_SECRET_KEY`, then delete the local copy or keep it offline.
2. Pushing to `master` publishes the site and the signed feed.
3. Tag `vX.Y.Z` to build release binaries (`release.yml`). They embed the public key and the corpus version.

## Not yet built

Live MCP inspection and rug-pull diffing, `report` / `incident new`, tree-sitter code rules, typosquat detection, crawlers, sandbox detonation, classifier, website. See `../product-specs/antidote.md`.

## License

Code: Apache-2.0 (`LICENSE`). Data in `corpus/` and `schema/`: CC-BY-4.0 (`LICENSE-DATA`).
