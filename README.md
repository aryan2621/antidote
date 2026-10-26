# Antidote

An open database of malicious and vulnerable AI agent artifacts (skills, MCP servers, tool descriptions, prompts, packages), plus an offline scanner. Like ClamAV / OSV, but for AI agents.

> Working name. Status: phases 0–4 built, plus most of phase 5: corpus, scanner, signed feed, CI integrations, website, crawlers, detonation, classifier, live MCP inspection, API and the Burrow integration. Not yet published; `antidote-db/antidote` is a placeholder.

## Scanner

```bash
cargo install --path crates/antidote-cli

antidote scan                          # auto-discover Claude Code / Cursor / OpenClaw / Claude Desktop config
antidote scan ./skills/my-skill        # scan a folder or file
antidote scan --mcp ~/.cursor/mcp.json # check the packages an MCP config launches
antidote check npm:mcp-remote@0.1.15   # look up one package (also flags likely typosquats)
antidote inspect --mcp ~/.cursor/mcp.json  # start each server in a container, scan its live tools, diff vs last time
antidote report ./suspicious-skill     # print a prefilled GitHub issue link (hashes + rule hits only)
antidote incident new                  # write up an agent incident (AGT-INC) and get a submission link
antidote update                        # fetch the latest signed corpus feed
antidote stats on --url <api>/v1/stats # opt in to anonymous rule-hit counts (off by default)
antidote scan --format json|sarif|codequality
antidote scan --fail-on medium         # critical|high (default)|medium|low|never
```

Exit codes: `0` = nothing at or above `--fail-on`, `1` = findings at or above it, `2` = error.

Scanning is fully offline. It uses the corpus built into the binary, or a newer one fetched by `antidote update`. `update` is the only command that touches the network. It accepts a feed only if the minisign signature checks out and the version is newer, so an old feed can't be replayed. The cache is re-verified on every run, and a tampered cache falls back to the built-in corpus. Nothing is ever uploaded. `report` only prints a link; you open it and submit the issue yourself.

`check` and `scan --mcp` flag a package that is one character off (two for names of 10+ characters) a popular one in `corpus/popular/npm.txt`, as `AGT-F-TYPOSQUAT` (medium). That list is a snapshot of the top 500 npm packages with the `mcp` keyword; the crawler refreshes its own copy daily.

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

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/antidote-db/antidote/main/ci/gitlab/antidote.gitlab-ci.yml
```

Findings show up in the merge request's Code Quality widget (`--format codequality`). To change the defaults, override `ANTIDOTE_PATHS`, `ANTIDOTE_FAIL_ON` or `ANTIDOTE_VERSION`.

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
| Code rules | [tree-sitter](https://tree-sitter.github.io/) queries (`corpus/rules/*.scm`, `AGT-T-*`) on JS/TS/Python and shell scripts: shell commands built from dynamic strings, reads of SSH/cloud/keychain/browser credentials, the whole environment sent over the network, eval of runtime-decoded code; in `.sh`/`.bash`/`.zsh`, code downloaded and run (`curl … \| bash`, `bash <(curl …)`, `eval "$(curl …)"`) and base64 blobs piped into a shell |
| Packages | `npx`/`uvx`/`bunx`/`pnpm dlx` servers in any `mcpServers` block, matched against `affected` versions and OSV ranges |

Each finding comes with a suggested fix, e.g. "Upgrade to 0.1.16 or later", "Remove it" or "Restrict or disable tool `x`". The scanner gives deterministic verdicts only. No LLM decides whether something is safe.

### Classifier and LLM explanations

Text meant for an agent is also scored by a small offline classifier for prompt-injection phrasing. That covers skill files, `CLAUDE.md` / `AGENTS.md`, `*.mdc`, and `description` / `prompt` fields in JSON. Hits are reported as `AGT-C-0001`. The model is a hashed character n-gram logistic regression trained in `ml/` (see `ml/MODEL_CARD.md`). It ships inside the signed feed and runs in pure Rust. `--no-classifier` turns it off.

```bash
antidote scan --llm ollama:qwen3                        # explain each finding with a local model
antidote scan --llm http://127.0.0.1:8080/v1 --llm-model m  # any OpenAI-compatible server
```

The LLM only sees excerpts around existing findings. It can add an explanation or raise a finding to high, but it can never lower or remove one. Non-local servers are refused unless you pass `--llm-allow-remote`, which sends file excerpts to that server, with the key taken from `ANTIDOTE_LLM_API_KEY`.

### Guard: MCP gateway with rug-pull detection

Put `antidote guard` in front of any stdio MCP server in your client config:

```json
{ "mcpServers": { "github": { "command": "antidote", "args": ["guard", "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"] } } }
```

Every message passes through untouched, except the `tools/list` answers, which are filtered:
- Each tool's description and input schema is scanned. Tools with a high or critical finding are hidden, and calls to them get an error.
- The first time a tool is seen, its definition is pinned (`<config dir>/antidote/pins/<name>.json`). If the definition later changes, the tool is blocked as a possible rug pull. Review the change, then run `antidote guard --name github --reset` to re-pin it.
- Reasons are written to stderr, which shows up in your client's MCP log.
- `--warn-only` logs problems without hiding anything.

### Inspect: live MCP tools

`antidote inspect` reads your MCP configs (or `--mcp <file>`), then starts each stdio server and asks it for its tools. Each tool's description goes through the same checks as `guard`, using the same pin files. So a tool that changed since you last ran `inspect` or `guard` is reported as `AGT-F-RUGPULL`.

- By default, servers run in Docker or Podman: `--cap-drop ALL`, a read-only root, no host mounts, and secrets passed by name so they stay out of the process list.
- `npx`, `uvx` and `bunx` servers are supported. A local binary is skipped unless you pass `--no-sandbox`, which runs servers directly on your machine.
- `--timeout` (default 180s) covers the first package download.

### Incidents

`antidote incident new --summary … --date 2026-09 --trigger "prompt injection" --impact "data leak" --ref https://…` checks the fields against the schema, then prints the AGT-INC JSON and a prefilled issue link. In a terminal, it asks for any required field you left out. Maintainers can pass `--write corpus` to write the file with the next free id instead.

### Using antidote from other tools

`antidote check <pkg> --format json` and `antidote scan <path> --format json` print a JSON array of findings: `{severity, id, summary, path, line, context, evidence, fix, explanation}`. Exit codes are as listed above. Burrow runs `check` on every stdio MCP server you add. It refuses critical and high findings and shows medium and low ones as warnings.

### Opt-in stats

Off by default. `antidote stats on --url https://<api host>/v1/stats` turns it on. After that, each `scan` sends `{"corpus_version": N, "counts": {"AGT-R-0101": 2, …}}`: which rules fired and how often. It sends nothing else: no paths, file contents, package names or hostnames. The request has a 3-second timeout, and errors are ignored. `antidote stats off` turns it off, and `antidote stats status` shows the current setting. There is no hosted endpoint yet, so `--url` is required.

## Corpus

- `schema/entry.schema.json`: an OSV extension. Artifact entries are `AGT-YYYY-NNNN`. Behavioral incidents are `AGT-INC-YYYY-NNNN`.
- `corpus/entries/`: one JSON file per entry. Each entry is sourced from public reports and links them in `references`.
- `corpus/techniques.json`: maps each `techniques` tag to OWASP Top 10 for Agentic Applications (ASI01–ASI10) and MITRE ATLAS IDs. Entry pages link them.
- `corpus/rules/*.yar`: each rule has `meta: id, severity, description`.
- `corpus/rules/<id>.<js|py>.scm`: tree-sitter queries with `; id:`, `; severity:` and `; description:` header lines. The reported node is captured as `@hit`. `.js` rules also run on TypeScript.

Governance, triage targets, disputes and disclosure: [GOVERNANCE.md](GOVERNANCE.md).

## Website

`web/` is an Astro site with a search page, one page per entry, an "is X safe?" page per package, and a submit form that builds a prefilled GitHub issue in the browser. A stats page shows entry counts, the share verified, and the mix by classification, month and technique. A reporters page ranks reporters by accepted entries, and withdrawn entries are struck through and marked with their withdrawal date. Entry and package pages show README badge Markdown once `PUBLIC_API_URL` (the repo variable `ANTIDOTE_API_URL`) points at a deployed API. It is built from `corpus/entries` and deployed with the signed feed to GitHub Pages by `.github/workflows/pages.yml`. To run it locally: `cd web && npm install && npm run dev`.

## Desktop app

`apps/desktop` is a Tauri app with one page: it lists the agent configs it finds on this machine, scans them, checks a single package and updates the feed. It uses the same core as the CLI. To run it: `cd apps/desktop && pnpm install && pnpm tauri dev`. Tagged releases also build installers for macOS, Linux and Windows (the `desktop` job in `release.yml`); they're unsigned until the Apple secrets are set.

## API

`crates/api` builds `antidote-api` (axum), which serves:
- `GET /v1/feed.json` and `/v1/feed.json.minisig`;
- `GET /v1/entries/{id}`;
- `GET /v1/check/{npm|pypi}/{name}?version=`, which returns the same JSON as `antidote check`;
- `GET /badge/{npm|pypi}/{name}.svg`, a README badge for the latest release, or for `?version=`;
- `POST /v1/stats` and `GET /v1/stats`, opt-in rule-hit counts stored in SQLite. Only `AGT-*` ids are accepted, at most 500 keys, in a 16 KB body.

There is no hosted instance. Anyone who wants the API runs it themselves from the image that each tagged release publishes:

```bash
docker run -p 8080:8080 -v antidote:/data ghcr.io/antidote-db/antidote-api   # built-in corpus
curl localhost:8080/v1/check/npm/mcp-remote?version=0.1.15
```

```bash
cargo run -p antidote-api -- --listen 127.0.0.1:8080            # built-in corpus
antidote-api --feed feed.json --db stats.sqlite                  # signed feed; feed.json.minisig next to it
docker build -f crates/api/Dockerfile -t antidote-api .
```

With `--feed`, the signature is checked at start. The file is re-checked every minute, and a newer verified feed is swapped in without a restart.

## Releasing (maintainers)

1. Generate the feed key once: `minisign -G -W -p antidote.pub -s antidote.key`. Store the second line of `antidote.pub` as the repo variable `ANTIDOTE_FEED_PUBKEY`. Store the contents of `antidote.key` as the secret `MINISIGN_SECRET_KEY`, then delete the local copy or keep it offline.
2. Pushing to `master` publishes the site and the signed feed. Next to `feed.json` it publishes `all.zip`, one JSON file per entry in OSV's `all.zip` layout so OSV tooling can import the corpus, signed as `all.zip.minisig`.
3. Tag `vX.Y.Z` to build release binaries and desktop installers (`release.yml`). They embed the public key and the corpus version.

## Crawling and triage (maintainers)

`crates/ops` builds `antidote-ops`, which runs only in CI and is not shipped to users.

- **`crawl.yml` (hourly)** watches six sources for new and changed artifacts: the official MCP registry, ClawHub (owner/slug), npm (the replication feed, filtered to names containing "mcp"), PyPI (the updates RSS feed plus every package listed in the MCP registry), GitHub (recently pushed repos tagged `mcp-server`, `claude-skills` or `agent-skills`, pinned to their head commit) and Smithery (new servers: the stdio bundle plus every tool description, skipped unless the `SMITHERY_API_KEY` secret is set). For each new version it:
  1. downloads the archive and checks its registry digest where the registry publishes one (npm, PyPI);
  2. extracts it safely (path escapes abort, links are skipped, size is capped);
  3. scans it with the YARA and tree-sitter rules (and listed tool descriptions with the YARA rules and classifier), and checks install scripts, new domains, typosquat names and package age (`AGT-F-NEW-PACKAGE`, first published under 7 days ago).

  Anything at `high` or above opens an issue labelled `triage`. Crawl state and reports live on the `crawl-state` branch.
- **`triage.yml`** acts on comments from repo owners, members and collaborators:
  - `/confirm malicious|vulnerable|suspicious <summary>` opens a PR with a drafted `corpus/entries/AGT-*.json`;
  - `/reject <reason>` opens a PR that adds the report's hits to `corpus/allowlist.json`;
  - `/detonate` starts a detonation.

  PRs opened with `GITHUB_TOKEN` don't trigger CI. Close and reopen the PR, or swap the token for a GitHub App token.
- **`detonate.yml`** installs the package inside gVisor. The container has no route out except a proxy that forwards only registry traffic and sinkholes everything else. The run then starts the package as an MCP server and lists its tools. It reports blocked egress, DNS lookups, writes to sensitive paths, poisoned live tool descriptions, and tool changes since the last detonation (rug-pulls). Auto-detonating high or critical crawler findings is off unless the repo variable `ANTIDOTE_AUTO_DETONATE=true` is set. Running suspected malware on GitHub-hosted runners is a grey area under GitHub's terms, so move this to your own disposable host before using it at volume.

- **`seed.yml` (weekly)** imports new public OSV advisories for MCP packages (`antidote-ops seed-osv`) and opens a PR.

## Not yet built

- Editor extensions and MCP-gateway plugins for other gateways
- A hosted API, so there's no default stats endpoint and no public badges yet
- Reporter sign-in (GitHub OAuth) and gated raw-sample storage
- The CNA application and registry partnerships, which are paperwork rather than code

See `../product-specs/antidote.md`.

## License

Code: Apache-2.0 (`LICENSE`). Data in `corpus/` and `schema/`: CC-BY-4.0 (`LICENSE-DATA`).
