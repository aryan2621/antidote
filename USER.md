# Using Antidote

Antidote answers one question: **is this agent tool safe to install?** It is an open database of malicious and vulnerable AI agent artifacts (MCP servers, skills, tool descriptions, prompts, packages), plus an offline scanner that checks what you have against it.

## What is published

| Piece | Where |
|---|---|
| Website (database, per-package pages, submit form) | <https://aryan2621.github.io/antidote/> |
| CLI `antidote` (and the maintainer tool `antidote-ops`), prebuilt for macOS (Apple silicon, Intel), Linux (x86-64, ARM64), Windows | [GitHub Releases](https://github.com/aryan2621/antidote/releases/latest), each with a `.sha256` file |
| Desktop app | Same release: macOS, Windows (`.msi`, `-setup.exe`), Linux (`.AppImage`, `.deb`, `.rpm`) |
| VS Code extension (also loads in Cursor and Windsurf) | `antidote-<version>.vsix` on the release |
| GitHub Action | `aryan2621/antidote@v0` |
| GitLab CI template, pre-commit hook | `ci/gitlab/antidote.gitlab-ci.yml`, `.pre-commit-hooks.yaml` |
| Signed corpus feed and OSV bundle | `/feed/feed.json`, `/feed/all.zip` on the website, each with a `.minisig` |
| API server image | `ghcr.io/aryan2621/antidote-api` |
| Open data | `corpus/entries/` (CC-BY-4.0), schema in `schema/` |

Pick the way that suits you:

| I want to… | Use |
|---|---|
| Look up one name before I install it | the [website](#1-the-website) or `antidote check` |
| Scan my own agent setup or a folder | `antidote scan` or the [desktop app](#3-the-desktop-app) |
| Block bad changes in a repo | the [GitHub Action, GitLab template or pre-commit hook](#5-in-ci) |
| Protect a live MCP server | [`antidote guard`](#guard-filter-a-live-mcp-server) |
| Report something I found | [`antidote report`](#report-a-suspicious-thing) or the site's Submit page |

## Reading a verdict

Every result uses the same signal system on the website, in the desktop app and in the terminal. Each signal has a **word and a drawn shape**, so it never relies on colour alone.

| Signal | Shape | Meaning | What to do |
|---|---|---|---|
| **DANGER** | ● circle | Malicious, or a critical/high scanner finding | Do not install or run it. If you already did, treat the machine as exposed. |
| **WARNING** | ◆ diamond | Vulnerable: a real bug in otherwise honest software, or a medium finding | Check your version against the affected range, then upgrade or remove it. |
| **CAUTION** | ▲ triangle | Suspicious: looks wrong but is not confirmed, or a low finding | Review it before installing. |
| **NOTICE** | ■ square | An incident: no malicious file, but an agent did something it should not have | Read the report. |

Two rules to remember:

- **"Not in the database" is never a safety verdict.** It only means nobody has reported it yet. Check the name against the real package and run `antidote check` before you install.
- **"Reported" is not "verified".** Entries say which one they are. A reported entry has not been independently confirmed yet.

## 1. The website

Open <https://aryan2621.github.io/antidote/> (or run it locally: `cd web && npm install && npm run dev`).

- **Look something up.** Type a package, skill, CVE id or keyword into the big field. Press `/` anywhere on the page to jump to it, and `Esc` to clear it.
- **Read the result plate.** A matching name shows the worst verdict among the matches, one instruction, and a link to the evidence. A name with no match shows **Not listed** with the "not a safety verdict" wording.
- **Filter.** The four large verdict boxes (Danger, Warning, Caution, Notice) are filters, with the number of live entries in each. Kind and Ecosystem chips narrow further. The search text is kept in the URL, so you can share `?q=name`.
- **Open an entry.** The header shows the signal, the verification status and the id. Below are the description, affected versions, indicators (hashes, defanged domains, patterns), OWASP and MITRE technique links, the scanner rules that detect it, and sources.
- **Package pages** (`/package/<ecosystem>/<name>/`) answer "is X safe?" for one name and list every entry about it.
- **Stats** shows entry counts by verdict, kind, ecosystem, month and technique. **Reporters** credits the people who reported accepted entries.
- **Submit** builds a prefilled GitHub issue in your browser. Nothing is sent until you open and submit that issue yourself.
- **Install** shows copy-paste snippets for the CLI, CI and the signed feed.

## 2. The command line

Download the archive for your system from the [latest release](https://github.com/aryan2621/antidote/releases/latest), check it, and put `antidote` on your PATH:

```bash
t=aarch64-apple-darwin   # or x86_64-apple-darwin, x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-pc-windows-msvc
curl -fsSLO https://github.com/aryan2621/antidote/releases/latest/download/antidote-$t.tar.gz
curl -fsSLO https://github.com/aryan2621/antidote/releases/latest/download/antidote-$t.tar.gz.sha256
shasum -a 256 -c antidote-$t.tar.gz.sha256 && tar xzf antidote-$t.tar.gz
```

Or build from source: `cargo install --path crates/antidote-cli`.

### Scan

```bash
antidote scan                           # auto-discover your agent setup (clients listed below)
antidote scan ./skills/my-skill         # a folder or a single file
antidote scan --mcp ~/.cursor/mcp.json  # check the packages an MCP config launches
```

Text output lists findings worst first:

```
[ ● DANGER  ] critical AGT-2026-0209
  Malicious code in claude-all-config (npm)
  at npm:claude-all-config@3.8.3
  fix:      Remove it
  see:      https://aryan2621.github.io/antidote/entry/AGT-2026-0209/

1 finding(s): 1 critical. Do not install or run this.
```

Colour is used only on a terminal and is switched off by `NO_COLOR`.

What gets checked:

| Layer | What |
|---|---|
| Hash | SHA-256 of every file against known-bad hashes |
| Signatures | YARA-X rules: hidden Unicode, instruction overrides, concealment, credential exfiltration, `curl \| sh`, encoded exec, reverse shells |
| Code rules | tree-sitter queries on JS/TS/Python and shell scripts: dynamic shell commands, reads of SSH/cloud/keychain/browser credentials, whole environment sent over the network, eval of decoded code |
| Packages | `npx`/`uvx`/`bunx`/`pnpm dlx` servers in any `mcpServers` block, matched against affected versions |
| Classifier | A small offline model scores text meant for an agent (skill files, `CLAUDE.md`, `AGENTS.md`, `*.mdc`, `description` fields) for prompt-injection phrasing. `--no-classifier` turns it off. |

Every finding carries a suggested fix. No AI model decides whether something is safe.

A bare `antidote scan` looks for skills, commands and rules for Claude Code, OpenClaw and Cursor, and MCP server configs for Claude Code, Claude Desktop, Cursor, OpenClaw, Gemini CLI, Windsurf and the current project's `.mcp.json`. The MCP parser also understands VS Code's `servers` and Zed's `context_servers` blocks, so pass those files with `--mcp`. Codex's TOML config is not supported yet.

### Options and exit codes

```bash
antidote scan --format json|sarif|codequality   # default is text
antidote scan --fail-on medium                  # critical | high (default) | medium | low | never
```

| Exit code | Meaning |
|---|---|
| `0` | nothing at or above `--fail-on` |
| `1` | findings at or above it |
| `2` | an error |

`--format json` prints an array of `{severity, id, summary, path, line, context, evidence, fix, explanation}`, which is the interface other tools should use.

### Check one package

```bash
antidote check npm:mcp-remote@0.1.15
antidote check pypi:somepackage==1.0
```

It also flags names that are one character off (two for names of 10+ characters) a popular package, as `AGT-F-TYPOSQUAT`.

### Guard: filter a live MCP server

Put `antidote guard` in front of any stdio MCP server in your client config:

```json
{ "mcpServers": { "github": { "command": "antidote", "args": ["guard", "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"] } } }
```

- Each tool's description and input schema is scanned. Tools with a high or critical finding are hidden, and calls to them return an error.
- The first time a tool is seen, its definition is pinned. If it later changes, the tool is blocked as a possible rug pull. After you review the change, run `antidote guard --name github --reset`.
- Reasons are written to stderr, which appears in your client's MCP log.
- `--warn-only` logs problems without hiding anything.

### Inspect: look inside MCP servers

```bash
antidote inspect --mcp ~/.cursor/mcp.json
```

Starts each stdio server, reads its live tool list and runs the same checks as `guard`, sharing its pin files. A tool that changed since last time is reported as `AGT-F-RUGPULL`.

- Servers run in Docker or Podman by default: all capabilities dropped, read-only root, no host mounts. Secrets are passed by name.
- A local binary is skipped unless you pass `--no-sandbox`, which runs servers directly on your machine.
- `--timeout` (default 180 s) covers the first package download.

### Explain findings with a local model (optional)

```bash
antidote scan --llm ollama:qwen3
antidote scan --llm http://127.0.0.1:8080/v1 --llm-model my-model
```

The model sees only excerpts around existing findings. It can add an explanation or raise a finding to high. It can never lower or remove one. Remote servers are refused unless you pass `--llm-allow-remote` (excerpts are then sent to that server; the key comes from `ANTIDOTE_LLM_API_KEY`).

### Keep the corpus current

```bash
antidote update
```

Scanning is fully offline using the corpus built into the binary. `update` is the only command that touches the network. It accepts a feed only if its signature verifies and its version is newer than yours. A tampered cache falls back to the built-in corpus.

### Report a suspicious thing

```bash
antidote report ./suspicious-skill
antidote incident new
```

`report` prints a prefilled GitHub issue link containing file hashes and rule hits, never file contents. `incident new` checks your fields against the schema and prints an `AGT-INC` entry plus a submission link; in a terminal it asks for any required field you left out. You always open and submit the issue yourself.

### Anonymous stats (off by default)

```bash
antidote stats on --url https://<api host>/v1/stats
antidote stats status
antidote stats off
```

When on, each scan sends only which rules fired and how often, with the corpus version. No paths, contents, package names or hostnames. There is no hosted endpoint, so `--url` is required.

## 3. The desktop app

A window with the same checks as the CLI.

```bash
cd apps/desktop
pnpm install
pnpm tauri dev
```

Or install a prebuilt app from the [latest release](https://github.com/aryan2621/antidote/releases/latest): macOS (`.dmg`), Windows (`.msi` or `-setup.exe`), Linux (`.AppImage`, `.deb` or `.rpm`). The installers are not code-signed yet, so your OS may show a warning on first open. A scan of a large home folder takes a few seconds on the release build.

- **Scan my agent setup** finds Claude Code, Cursor, OpenClaw and Claude Desktop configs and scans them.
- **Scan a folder…** scans any folder you pick.
- **Check package** takes a coordinate such as `npm:mcp-remote@0.1.15`. Press `/` to jump to the field.
- **Update feed** downloads the latest verified corpus. The header shows how many entries you have and the database version.
- **Results** show a banner with the worst signal and one instruction, then every finding worst first, with where it matched, the evidence and the fix.

Everything runs on your machine. Nothing is uploaded.

### Wrap: put every MCP server behind guard

```bash
antidote wrap ~/.cursor/mcp.json          # prints the rewritten config
antidote wrap ~/.cursor/mcp.json --write  # edits it in place, keeping mcp.json.bak
```

Rewrites each stdio server in a config (`mcpServers`, VS Code's `servers`, Zed's `context_servers`) to run as `antidote guard --name <server> -- <original command>`. Remote (URL) servers and ones already wrapped are left alone. This suits any gateway or client whose server list uses `command` and `args`. To undo, restore the `.bak` file.

### Intercept: Docker MCP Gateway

Docker's MCP Gateway can run a program before or after every tool call, passing the request or the result as JSON on stdin (see the gateway's [interceptor docs](https://github.com/docker/mcp-gateway/tree/main/examples/interceptors)). `antidote intercept` is that program. It scans every string in the message and, on a high or critical finding such as hidden instructions in a tool result, replaces it with an error result. Clean messages pass untouched.

```bash
docker mcp gateway run \
  --interceptor "before:exec:antidote intercept" \
  --interceptor "after:exec:antidote intercept"
```

Add `--warn-only` to log what would be blocked without blocking. Unreadable input is passed through, never blocked. Tested against the documented stdin and stdout contract, not yet against a live Docker gateway.

## 4. In your editor

Install the `.vsix` from the [latest release](https://github.com/aryan2621/antidote/releases/latest) (VS Code: Extensions → … → Install from VSIX; Cursor and Windsurf accept it too).

- It scans the open folder on startup and when an MCP config, `SKILL.md`, `CLAUDE.md`, `AGENTS.md` or Cursor rule is saved. Findings appear in the Problems panel with DANGER, WARNING or CAUTION, the fix, and a link to the database entry.
- The status bar shows the worst signal and a count. Click it to re-scan.
- **Antidote: Scan my agent setup** checks the configs your agents already use. **Antidote: Update database** fetches the latest signed corpus.
- On first use it downloads the matching `antidote` binary from the release and checks its SHA-256. Set `antidote.path` to use your own.

## 5. In CI

**GitHub Action**

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: aryan2621/antidote@v0
    with:
      paths: .claude .cursor skills   # default "."
      fail-on: high
```

Findings appear under Security → Code scanning.

**GitLab CI**

```yaml
include:
  - remote: https://raw.githubusercontent.com/aryan2621/antidote/master/ci/gitlab/antidote.gitlab-ci.yml
```

Findings appear in the merge request's Code Quality widget. Override `ANTIDOTE_PATHS`, `ANTIDOTE_FAIL_ON` or `ANTIDOTE_VERSION` to change defaults.

**pre-commit** (needs `antidote` on your PATH)

```yaml
- repo: https://github.com/aryan2621/antidote
  rev: v0.1.0
  hooks: [{ id: antidote }]
```

## 6. Using the data

The corpus is open data, OSV-compatible JSON in `corpus/entries/`.

- **Signed feed:** `feed/feed.json` with `feed.json.minisig`, on the website.
- **OSV bundle:** `feed/all.zip` (one JSON file per entry) with `all.zip.minisig`, importable by OSV tooling.
- **Licenses:** data CC-BY-4.0, code Apache-2.0.

**Run the API yourself** (there is no hosted instance):

```bash
docker run -p 8080:8080 -v antidote:/data ghcr.io/aryan2621/antidote-api
curl 'localhost:8080/v1/check/npm/mcp-remote?version=0.1.15'
```

It serves the feed, single entries, package checks (the same JSON as `antidote check`), README badges at `/badge/{npm|pypi}/{name}.svg`, and the opt-in stats.

## 7. How the project runs itself

These GitHub workflows keep the data and releases current. You only need this if you maintain a fork.

| Workflow | When | What it does |
|---|---|---|
| `ci` | every push and pull request | Builds and tests on Linux, macOS and Windows, and builds the website |
| `pages` | every push to `master` | Publishes the website and the signed feed |
| `release` | a `v*` tag | Builds the CLI for 5 targets, the desktop installers, the VS Code extension, and the Docker image |
| `crawl` | hourly | Crawls registries, analyses new versions and opens triage issues (35 minute budget; unfinished work resumes next hour) |
| `seed` | weekly | Imports new OSV advisories for MCP packages and opens a pull request |
| `triage` | issue comments | Maintainer commands `/confirm`, `/reject`, `/detonate` (owners, members and collaborators only) |
| `detonate` | a `detonate` label or `/detonate` | Runs a flagged package in a sandbox with a sinkholing proxy |

Repository settings: the variable `ANTIDOTE_FEED_PUBKEY` and the secret `MINISIGN_SECRET_KEY` sign the feed. Without them the feed is published unsigned and clients reject it. The Apple signing secrets are optional.

To retrain the offline classifier: `cd ml && ./run.sh` (add `bg` to run it detached and log to `train.log`).

## 8. Contributing and reporting

- Found something malicious or vulnerable? Use the website's Submit page, `antidote report`, or open a GitHub issue. Link public evidence, defang domains (`evil[.]example`) and never paste live payloads.
- For a vulnerability in someone's software, tell the author first. Entries are published after a fix or 90 days (30 if it is being exploited).
- Wrong or outdated entry? Open an issue or pull request against its file in `corpus/entries/`.
- Rules for triage, disputes and disclosure are in [GOVERNANCE.md](GOVERNANCE.md).

## Troubleshooting

| Problem | Fix |
|---|---|
| `antidote scan` finds nothing to scan | Pass a path, or `--mcp <file>` for an MCP config. Auto-discovery looks for Claude Code, Cursor, OpenClaw and Claude Desktop. |
| `antidote update` says the feed is rejected | It failed signature or version checks. Your built-in corpus still works. Try again later. |
| `inspect` skips a server | A local binary is skipped unless you pass `--no-sandbox`. Docker or Podman must be running for sandboxed servers. |
| `guard` blocks a tool you trust | Its definition changed since it was pinned. Review the change, then `antidote guard --name <name> --reset`. |
| Too many classifier hits on prompt-like docs | The classifier scores text written for agents, so security documents can score high. Use `--no-classifier` for that run, or `--fail-on high`. |
| Colour codes appear in a log file | Set `NO_COLOR=1`, or use `--format json`. |
| Desktop installer will not open | Release installers are not code-signed. Use your OS's "open anyway" option, or build from source. |
