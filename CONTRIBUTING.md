# Contributing

## Report a malicious or vulnerable agent artifact

Open a PR that adds `corpus/entries/AGT-YYYY-NNNN.json` (next free number), or open an issue with:

- **What:** ecosystem (`clawhub`, `mcp-registry`, `smithery`, `claude-skill`, `cursor-rule`, `npm`, `PyPI`, `GitHub`), name, affected versions
- **Classification:** `malicious` (intentional), `vulnerable` (bug), or `suspicious`
- **Evidence:** links to public reports, advisories or CVE/GHSA IDs; sha256 of files if you have them
- **Behavior:** what it does, described in plain words. Do **not** paste live payloads. Defang domains (`evil[.]example`).

For *vulnerable* (not malicious) items, notify the author first and allow 30–90 days before the entry goes public.

## Add a detection rule

1. Add a rule to `corpus/rules/*.yar` with `meta: id = "AGT-R-NNNN"`, `severity` (`low|medium|high|critical`), and `description`.
2. Run `antidote scan` on a defanged sample to confirm it fires, and on normal text to confirm it doesn't.

## Triage issues (Antidote maintainers)

The hourly crawler opens one `[triage] <package>` issue per package that scores `high` or `critical`. A later version of that package is added to the same issue as a comment; if the issue is closed, that package stays quiet.

Comment on the issue (owners, members and collaborators only):

| Command | What happens |
|---|---|
| `/confirm malicious\|vulnerable\|suspicious <summary>` | Opens a PR that adds a corpus entry. Merging it closes the issue. |
| `/reject <reason>` | Opens a PR that allowlists the report's hits for that exact version. Merging it closes the issue. |
| `/detonate` | Runs the package in the sandbox and reports back. |

To dismiss an issue without a PR (a false positive you don't want allowlisted), close it by hand as "not planned".

The commands act on the report in the issue body, which is the first version seen. Later versions are listed in comments.

## If your package was flagged

Triage issues are public and name the package, but the crawler does not notify its author. If you own a package that has a `[triage]` issue and you think it is a false positive:

1. Comment on the issue explaining why, or open an issue titled `Dispute: <issue number>`. For anything you'd rather not post publicly, use a private GitHub Security Advisory.
2. A maintainer replies within 3 business days ([GOVERNANCE.md](GOVERNANCE.md#triage)).
3. If it is a false positive, a maintainer runs `/reject` and the reason is recorded in the issue. That version is allowlisted and the crawler won't raise it again.

A triage issue is an unreviewed machine finding, not a verdict, and it is not published in the database. A package is only marked malicious or vulnerable after a maintainer confirms it, and disputes follow [GOVERNANCE.md](GOVERNANCE.md#disputes-and-takedowns).
