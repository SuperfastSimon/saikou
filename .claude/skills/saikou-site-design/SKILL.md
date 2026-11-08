---
name: saikou-site-design
description: Use when designing, restyling, writing copy for, or reviewing anything visual or public for Saikou - the saikou.tech site (site/), the local app (saikou/web/), the logo, social images, or launch posts. Keeps the work distinctive, accessible, bilingual and inside the project's claim rules.
---

# Saikou site and brand work

Read first, in this order: `docs/brand.md` (positioning, voice, proof, open decisions), then the
`:root` and dark-mode blocks of `site/assets/style.css` (the only source of colour and type
tokens). Do not restate hex values elsewhere.

## Before building

Write a short plan and check it against the brief before any HTML or CSS:

1. **Job of the page** and who reads it (developer merging an AI fix; Dutch SME).
2. **Palette and type** by token name; say what each is for.
3. **Layout** as a rough sketch, with where the verdict / provenance / real output sits.
4. **What is deliberately not there** (decoration that carries no information).

## What makes it Saikou

- The evidence is the hero: real command output, a stamped verdict, a provenance chip. Lead with
  the most characteristic artifact (a blocked fake fix), not a headline number.
- Structure carries meaning: borders mark pass or fail, labels name provenance. No decoration.
- One orchestrated moment of motion at most, and `prefers-reduced-motion` respected.
- Lines of prose stay under about 80 characters. Serif body needs a little more line height.

## Avoid

- Generic "AI site" patterns: tracked-out capital eyebrow labels, `-` prefixes on labels, rows of
  identical rounded cards with the same shadow, a big number over a small label as the default
  hero, gradient accents, arrows tacked onto links. (`.eyebrow` and the uniform card grid exist
  today; they are on the retire-later list in `docs/brand.md`, so do not spread them.)
- Stock imagery, emoji as icons, invented customer logos, quotes, ratings or reviews.
- Any score, percentage of "security", or promise. See the claim rules below.

## Hard constraints

- **No third-party requests**: no CDN, web font, analytics, embed, tracker. System font stacks only.
  If a font file is ever added it is self-hosted and OFL-licensed.
- **Claims**: `BANNED` in `scripts/check_site.py` is the authority; never weaken it to make copy pass.
  A claim about what is caught carries its scope (tools, versions, languages). Numbers come only
  from generated files (`docs/conformance/`, `docs/measurements/`) or CI.
- **Bilingual parity**: every page change goes into `site/` (English) and `site/nl/` (Dutch)
  with the same facts and limits; update `sitemap.xml` and hreflang when pages change.
- **No ratings or reviews in JSON-LD**; `softwareVersion` must equal the engine version.
- **Accessibility**: WCAG 2.1 AA on the dark palette (4.5:1 body text), visible focus, usable at 320 px,
  no horizontal scroll.
- Never publish. Pushing to the Pages repository is a separate step that the maintainer approves
  explicitly, each time.

## Verify before saying it is done

```bash
./.venv/Scripts/python.exe scripts/stage_site.py --mode full    --out <empty dir>
./.venv/Scripts/python.exe scripts/stage_site.py --mode interim --out <empty dir>
cd qa/site && npm ci && SITE_DIR=<staged dir> npx playwright test
```

`stage_site.py` runs `check_site.py` (claims, links, metadata). `qa/site` runs the browser checks
(no off-origin requests, axe WCAG 2.1 A/AA with the system in light and in dark, no overflow at 320/768/1280 px,
no console errors) and writes full-page screenshots. Look at the screenshots; green tests do not
tell you the page is good.

## Related tools (optional installs, not part of this repository)

Anthropic publishes a general `frontend-design` plugin for Claude Code. It is separate from this
skill and its terms are its own; where it conflicts with this file, this file wins for Saikou.
