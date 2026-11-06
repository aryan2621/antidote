# Contributing

## Report a bad package, skill or MCP server

Open an issue or a PR (add `corpus/entries/AGT-YYYY-NNNN.json`, next free number) with:

- **What it is:** where it's published (`clawhub`, `mcp-registry`, `smithery`, `claude-skill`, `cursor-rule`, `npm`, `PyPI`, `GitHub`), its name and the affected versions.
- **Why it's bad:** `malicious` (on purpose), `vulnerable` (a bug) or `suspicious` (unclear).
- **Proof:** links to reports or advisories (CVE/GHSA), or file hashes (sha256).
- **What it does,** in plain words. Never paste live attack code, and write domains like `evil[.]example`.

For plain bugs (not malware), tell the author first and give them 30 to 90 days before it goes public.

## Add a detection rule

1. Add a rule in `corpus/rules/*.yar` with `meta: id = "AGT-R-NNNN"`, a `severity` (`low|medium|high|critical`) and a `description`.
2. Run `antidote scan` on a safe sample that should trigger it, and on normal text that shouldn't.

## If your package was flagged

Our crawler opens a public `[triage]` issue for packages that look risky. It does not notify you, and a triage issue is a machine guess, not a verdict. If yours is a false alarm, comment on the issue or open an issue titled `Dispute: <issue number>`. For anything you'd rather not post publicly, use a private GitHub Security Advisory. A maintainer replies within 3 business days ([GOVERNANCE.md](GOVERNANCE.md#how-a-report-is-handled)) and clears it if you're right.

## For maintainers: triage issues

The crawler opens one issue per package, and new versions are added as comments. If the issue is closed, that package stays quiet. On an issue, comment (owners, members and collaborators only):

| Command | What happens |
|---|---|
| `/confirm malicious\|vulnerable\|suspicious <summary>` | Opens a PR that adds it to the database. |
| `/reject <reason>` | Opens a PR that marks it a false alarm for that exact version, so it isn't raised again. |
| `/detonate` | Runs it in a sandbox and reports back. |

Merging the PR those commands open closes the issue. To dismiss one without a PR, close it as "not planned". The commands use the report in the issue body, which is the first version seen. Later versions are listed in comments.
