---
version: 1
slug: "web-src-pages-index-astro"
primary_target: "web/src/pages/index.astro"
related_targets: ["apps/desktop/src/App.tsx","web/src/styles/global.css"]
---

# Antidote redesign: web + desktop (Persuade for web home, Operate for desktop and tool pages)

Audience: developer about to install an MCP server, skill or package, asking "is this safe?". Action: look up one name, read the verdict and evidence, then install the scanner. Constraints (PRODUCT.md): keep name, logo mark, the circle/diamond/square verdict shapes, routes, and the "not in the database is never a safety verdict" wording. Absent: user counts, testimonials. Desktop shares the same world.

## Direction contract

THESIS: Every package gets a safety placard: signal word, drawn diamond, one imperative, then the evidence sheet. Refuses the category default of a soft headline-over-search page with a table of equal rows.

OWN-WORLD: ANSI Z535 / NFPA 704 / GHS signage. Ground cool off-white (dark mode near-black), ink black, hard 3px black borders, square 2px corners. Signal fields: DANGER red (malicious), WARNING orange (vulnerable), CAUTION yellow (suspicious), NOTICE blue (incident), each with its drawn shape and its word, never colour alone. Barlow Condensed caps for signal words and headings, Barlow for text, system mono for ids and evidence. Hazard-stripe band only as the header rule and loading state. Data-sheet ruled rows for evidence.

STORY: The visitor sees a placard-sized lookup, types a name or presses /, and gets a verdict plate: signal word, one imperative, matched rule and evidence beside it. They believe it because the evidence is shown. They then filter by verdict or install the scanner.

FIRST VIEWPORT: Black header with brand and caps nav over a stripe rule. Below, left-aligned condensed-caps headline "Is this agent tool safe?" and a very large bordered lookup field with a "/" key hint. Under it four verdict placards (DANGER 31, WARNING 208, CAUTION, NOTICE 8) as live filters. Verdict rows start below the fold line; a typed query shows a result plate above them. Primary action is the lookup field.

FORM: Hazard Placard, the assigned direction (index 3 of the ordered grounded list; raises from Phosphor Terminal: keyboard-first, Kiln Glaze Shelf: risk and evidence beside every verdict, WPA Park Poster: one imperative per verdict plate). seed: b7ba3b2c70c54214

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
