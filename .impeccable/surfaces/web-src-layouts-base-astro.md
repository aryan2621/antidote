---
version: 1
slug: "web-src-layouts-base-astro"
primary_target: "web/src/layouts/Base.astro"
related_targets: ["apps/desktop/src/App.tsx"]
---

Scope: the Antidote website (all pages, Read mode) and the desktop app (Operate mode), one shared world.
Audience: a developer about to install an MCP server or skill, asking "is this safe?"; second job: install the scanner.

## Direction contract

THESIS: Antidote is a field guide to the dangerous lookalikes in the agent ecosystem. Every entry is a numbered plate; identification is by field marks (indicators) and a key (filters). Refuses the advisory-table site with a search bar and severity pills.

OWN-WORLD: Guide-cover band in deep moss (#1d2b22) carrying the wordmark and nav; plate-white ground; ink text; field-mark rust for malicious, ochre for vulnerable, lichen for suspicious, slate for incidents, each paired with a drawn mark (disc, diamond, triangle, square) so a verdict reads without colour. Alegreya Sans for reading, Alegreya Sans SC for plate labels and key couplets; mono only for code, hashes and package names. Field marks are called out with hairline leader lines.

STORY: The reader searches the key, finds the plate, sees the verdict mark and the field marks that prove it, and leaves knowing whether to install. Lookalikes (typosquats) are shown beside the real package.

FIRST VIEWPORT: Moss cover band with wordmark and nav. Below, the title "Is this agent tool safe?" and a full-width search as the key's first couplet, with key couplets (classification, ecosystem, artifact) as chips beneath. Then plate rows: plate number, mark, summary, affected packages.

FORM: Field Guide to Lookalikes, #1 on the grounded list (chosen pick). seed:29a655fd43e80e1b

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
