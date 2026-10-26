# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
- **Primary:** a developer about to install an MCP server, agent skill, Cursor rule or agent package, asking "is this safe?". They arrive from a search, a README badge or a CLI finding link, look up one package or entry, and leave with a verdict and evidence. Their second job is installing the scanner (CLI, GitHub Action, pre-commit, desktop app).
- **Secondary:** security teams evaluating the feed and CI integration; researchers browsing the dataset and submitting samples.
- **Desktop app users:** developers who prefer a GUI to the CLI: scan their agent setup, scan a folder, check a package, update the feed.

## Product Purpose
Antidote is an open, community-maintained database of malicious and vulnerable AI agent artifacts (skills, MCP servers, tool descriptions, prompts, packages) and behavioral incidents, plus an offline scanner and a signed feed any agent tool can pull. Think ClamAV / OSV for AI agents. It succeeds when a developer can answer "is this agent tool safe to install?" in seconds, with evidence they can check.

## Positioning
- The open sample database in the middle: incident lists aren't machine-readable, scanners are closed and vendor-locked. Antidote's entries are OSV-compatible JSON in a public git repo, data under CC-BY-4.0, code under Apache-2.0.
- Deterministic verdicts: hash, YARA-X, tree-sitter rules, typosquat checks and a small offline classifier. An LLM can explain findings but never decides "safe".
- Offline by default: the scanner never uploads files; reports are prefilled GitHub issues the user chooses to open.

## Operating Context
- Website: static Astro site on GitHub Pages under a base path. Pages: search/database, entry, package lookup, stats, reporters, submit (opens a prefilled GitHub issue), install.
- Desktop: Tauri 2 + React app with five commands (info, targets, scan, check, update).
- Findings link to entry pages; README badges link to package pages.
- Triage happens in GitHub issues; the corpus updates through git.

## Capabilities and Constraints
- Entry kinds: threat entries (classification malicious / vulnerable / suspicious; verification verified / reported / disputed; may be withdrawn) and incidents (trigger, impact, root cause, would-have-prevented).
- Severity scale used by the scanner: critical, high, medium, low.
- "Not in the database" is never a safety verdict; this wording is deliberate and must stay.
- No hosted API or domain yet; badges and stats need `PUBLIC_API_URL`.
- Website has zero runtime dependencies beyond Astro; desktop uses Tailwind v4.

## Brand Commitments
- Name: **Antidote**, committed. The identity may build on the name.
- Voice: plain, evidence-first, technical. No fear-marketing, no hype, no "military-grade".

## Evidence on Hand
- Real corpus: ~240 entries in `corpus/entries/`, technique mappings in `corpus/techniques.json` (OWASP Agentic Top 10, MITRE ATLAS).
- Desktop app icon: `apps/desktop/app-icon.png`.
- **Absent:** user counts, testimonials, partner logos, press. Never fabricate these.

## Product Principles
1. Evidence before verdict: every claim shows what matched and where.
2. Precise wording about certainty: malicious, vulnerable, suspicious, reported, disputed and withdrawn mean different things and are shown differently.
3. Fast lookup: the answer to "is X safe?" is one search away on any screen size.
4. Open and neutral: show the data, its license and how to contribute.

## Accessibility & Inclusion
- WCAG AA contrast in light and dark themes; severity never conveyed by color alone.
- Keyboard-operable search, filters and forms; respect reduced motion.
