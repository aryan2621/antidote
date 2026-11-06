# Antidote

Antidote checks AI agent add-ons (skills, MCP servers, prompts, packages) for malware and security bugs before you install them. It is free, open, and runs on your own machine. Think of it as an antivirus for AI agents.

> Working name. Site: [aryan2621.github.io/antidote](https://aryan2621.github.io/antidote).

## Try it

```bash
cargo install --path crates/antidote-cli

antidote scan                          # check your Claude Code, Cursor and other agent setups
antidote scan ./my-skill               # check one folder or file
antidote check npm:mcp-remote@0.1.15   # look up one package before installing it
antidote update                        # get the newest database
```

The scan runs offline. Only `antidote update` uses the network, and nothing you scan is ever uploaded.
If a scan finds a problem, the command exits with `1` (an error gives `2`), so you can use it in scripts.

## Use it in your projects

**GitHub Action**

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: aryan2621/antidote@v0
    with:
      fail-on: high
```

**GitLab CI**: include `ci/gitlab/antidote.gitlab-ci.yml`. **pre-commit**: add the `antidote` hook. Details for both are in [MAINTAINERS.md](MAINTAINERS.md#gitlab-ci).

## Other ways to use it

- **Desktop app** (`apps/desktop`): scan with buttons, no command line. It also has a Trends view.
- **Website**: search entries, see stats, and check whether a package is safe.
- **Guard**: put `antidote guard` in front of an MCP server to hide dangerous tools and catch rug-pulls.

## Learn more

- Every feature in detail: [USER.md](USER.md)
- Found something bad? [CONTRIBUTING.md](CONTRIBUTING.md)
- How entries are decided and disputed: [GOVERNANCE.md](GOVERNANCE.md)
- What the scanner checks, the API, the crawler and releases: [MAINTAINERS.md](MAINTAINERS.md)

License: code Apache-2.0 (`LICENSE`), data in `corpus/` and `schema/` CC-BY-4.0 (`LICENSE-DATA`).
