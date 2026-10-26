---
name: Antidote
description: Field guide to dangerous lookalikes in the agent ecosystem — moss cover band, plate rows, verdict marks you can read without colour alone.
colors:
  paper: "#f5f6f1"
  plate: "#ffffff"
  ink: "#17211b"
  ink-muted: "#4a574e"
  rule: "#d3d9cf"
  moss: "#1d2b22"
  moss-ink: "#eef3ea"
  moss-muted: "#b4c4b2"
  fern: "#2c6a3d"
  malicious: "#b23a1e"
  vulnerable: "#95580a"
  suspicious: "#5f6b21"
  incident: "#34557a"
  focus: "#2c6a3d"
typography:
  body:
    fontFamily: "'Alegreya Sans', ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.6
  display:
    fontFamily: "'Alegreya Sans', ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(2rem, 1.4rem + 2.6vw, 3.25rem)"
    fontWeight: 800
    lineHeight: 1.15
    letterSpacing: "-0.015em"
  small-caps:
    fontFamily: "'Alegreya Sans SC', 'Alegreya Sans', ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 500
    lineHeight: 1
    letterSpacing: "0.05em"
  mono:
    fontFamily: "ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "0.86em"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  sm: "4px"
spacing:
  frame-gutter: "16px"
  frame-gutter-wide: "32px"
components:
  button-primary:
    backgroundColor: "{colors.moss}"
    textColor: "{colors.moss-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "0.55rem 1.1rem"
  nav-link:
    typography: "{typography.small-caps}"
    textColor: "{colors.moss-muted}"
    padding: "0 12px"
    height: "44px"
---

## Overview

Antidote’s web UI is a **field guide**, not a generic advisory table. The visitor uses a **key** (search + filter chips), finds a **plate** (entry row or detail), and reads **field marks** (indicators, affected packages, sources). Verdicts use a drawn **mark** (disc, diamond, triangle, square) plus a word so severity is never colour-only.

Mode: **Read** — precision and restraint; patterns developers already know (search, breadcrumbs, definition lists) earn their place. Brand shows up in the moss cover band, plate typography, and mark vocabulary.

## Colors

- **Paper / plate:** page background vs card or inset surfaces.
- **Moss band:** header cover (`--moss`, `--moss-ink`, `--fern` accent rule). Navigation and wordmark live here.
- **Verdict hues:** malicious (rust), vulnerable (ochre), suspicious (lichen), incident (slate). Each pairs with a `--wash-*` tint on plate rows.
- **Focus:** fern green outline; same token in light and dark (`prefers-color-scheme` + optional `data-theme`).

## Typography

- **Alegreya Sans** for reading; **Alegreya Sans SC** for plate labels, section labels (“Verdict”, “Kind”), and nav.
- **Mono** only for IDs, package coordinates, hashes, and code blocks.
- **H1** is the page thesis; **H2** sections use small-caps styling at ~1.05rem.

## Layout

- **Frame:** max-width 1120px; reading column max ~70ch where prose-heavy.
- **Cover bar:** brand + horizontal nav; on narrow viewports nav scrolls horizontally on one row (44px touch targets).
- **Home:** key block (title, lede, search, chip couplets) then numbered plate list.
- **Entry / package:** breadcrumb, plate header (id + mark + verification line), then leaders-style spec rows.

## Elevation & Depth

Flat guide aesthetic: 1px rules (`--rule`), no drop shadows. Depth is separation by plate white on paper, moss band, and optional wash backgrounds on verdict-tinted rows.

## Shapes

- **Marks:** circle (malicious), diamond (vulnerable), triangle (suspicious), square (incident), stroked disc + slash (withdrawn).
- **Radius:** 4px on buttons, inputs, chips.
- **Logo:** magnifying-glass mark in the cover (SVG, not raster).

## Components

- **`Mark`:** verdict shape + label; used in chips and plate headers.
- **Filter chips:** toggle `aria-pressed`; show mark or text + count.
- **Plates:** list rows linking to entry; show id, mark, summary, package links.
- **Leaders:** `dt`/`dd` grid for field marks and metadata.
- **`CodeBlock`:** copy affordance for install/CI snippets.
- **Bars (stats):** inline SVG bars, no chart library.
- **Desktop (`apps/desktop`):** same moss cover, tokens, and `Mark` shapes; findings render as plates with severity mapped to marks (critical/high → disc, medium → diamond, low → triangle). Operate layout: actions + package field, no site nav.

## Do's and Don'ts

- **Do** pair every verdict colour with a mark shape and text label.
- **Do** keep “not in the database” language precise; never imply safety from absence.
- **Do** use `href()` from `entries.ts` for all internal links (GitHub Pages base path).
- **Don't** add runtime JS frameworks; search/filter is vanilla on the home page only.
- **Don't** use severity colour alone in charts or badges without a text or shape counterpart.
- **Don't** fear-market or hype; voice is evidence-first (see `PRODUCT.md`).
