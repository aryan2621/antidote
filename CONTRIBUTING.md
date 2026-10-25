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
