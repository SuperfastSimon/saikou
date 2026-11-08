# Saikou - brand brief

One page that says what Saikou is, how it sounds and how it looks, so that copy, site, logo and
launch material come out as one thing. Public on purpose. Strategy and competitor notes stay in
`internal/` (git-ignored).

Written 2026-10-22 from the repository itself (README, `site/`, `CLAUDE.md`). Where a choice
belongs to the owner it is listed under "Open decisions" at the end, not decided here.

## Positioning

**Saikou proves that a security fix is real, not just claimed.**

- **For:** developers and security reviewers who merge fixes written by AI coding agents; second,
  small Dutch and EU organisations that need to show their fixes were checked (NIS2 page).
- **The problem:** a fix can look fixed to the scanner and the diff (a new `# nosec`, a sanitised
  value nobody uses, one caller fixed while the shared sink stays raw) and still leave the
  vulnerability in place.
- **The rule it is built around:** *Absence of a finding is never evidence of a fix.*
- **What it does:** compares code before and after a change and blocks transformations that only
  look hardened. Runs on your machine, standard library only, open source (Apache-2.0).
- **What it refuses to do:** give a score, promise security, or imply a check it did not run.
  Every finding says how it was established (`tool`, `parser`, `mechanical`).

The distinctive thing is the refusal. Most security tooling sells confidence; Saikou sells the
exact edge of what was and was not checked. Everything below follows from that.

## Voice

1. **Evidence before explanation.** Show the real command output first (`tests/fixtures/demo/`,
   `saikou selftest`), then say what it means. Never a mock-up that the tool cannot produce.
2. **A claim carries its scope in the same sentence.** Which tools, which versions, which
   languages. Numbers come only from generated files: `docs/conformance/suppression-coverage*.md`,
   `docs/measurements/`, CI. Never from memory, never rounded up.
3. **Say what was not checked.** A limit stated plainly reads as competence, not weakness.
4. **Plain, short, dry.** Concrete nouns (`nosec`, `shell=True`, the line number). No hype, no fear,
   no superlatives, no "revolutionary", no exclamation marks.
5. **Same facts in English and Dutch.** Dutch is written for Dutch readers (informal *je*), not
   translated word for word. Both versions make the same claims and carry the same limits.

The list of phrases the project will never use is `BANNED` in `scripts/check_site.py`. That file
is the only authority (this brief deliberately does not copy it, so the two cannot drift).
`check_site.py` fails the build on a banned phrase, so test copy against it before review.

| Instead of | Write |
|---|---|
| "Catches every fake fix." | "Blocks the fake-fix patterns listed in the coverage statement, for the tools and versions named there." |
| "Secure your AI-written code." | "Check whether the AI-written fix changed the thing that mattered." |
| "Trusted by teams." | Nothing, until there are named users who agreed to be named. |
| "Score 94/100." | Not available. There is no score, ever. |

## Proof

Marketing material may use these and nothing else, quoting scope with them:

- The demo: one vulnerable file, three proposed fixes, real output (`tests/fixtures/demo/`).
- The generated suppression coverage statement (`docs/conformance/suppression-coverage*.md`).
- False-positive measurements on real code (`docs/measurements/`).
- The self-test and the CI matrix, as they stand on the day of writing.

No ratings, reviews, testimonials, customer logos or "as seen in" until they exist. JSON-LD must
not carry them either (`check_site.py` enforces this).

## Visual identity

**Concept: the audit file.** A case file with stamped verdicts and sourced evidence, not a
dashboard and not a hacker terminal. The parts that carry meaning are the brand; everything else
is quiet.

**Decided 2026-10-22: the site is dark in every colour scheme**, with the logo's mint as the brand
accent (links, the main button, labels, a passing verdict), red for fail and amber for warn. Mint
means both "brand" and "passes", so keep it for few things and never use it for a warning.

Keep (each one tells the reader something):
- Verdict stamp and pill (`BLOCKED` / `WARN` / `PASS`) with the pass, fail and warn colours.
- Provenance chip (`tool`, `parser`, `mechanical`) on every finding.
- Terminal blocks with a pass or fail left border for real output.
- Monospace for evidence, condensed capitals for labels, a plain system sans for prose.

Rules:
- **Tokens live in `site/assets/style.css` (`:root` and the dark-mode block).** Do not copy hex values
  into other documents; refer to the token names (`--ground`, `--paper`, `--ink`, `--accent`,
  `--pass`, `--fail`, `--warn`).
- **System fonts only, no third-party requests of any kind.** If a font file is ever added it is
  self-hosted, under the SIL Open Font License, and never loaded from a CDN. The site must keep
  saying "no third-party scripts, fonts or trackers" truthfully.
- The 2026 landing-page mock-ups (acid `#00FFD1` on near-black, Syne and IBM Plex Mono) are a style
  reference at most. Their copy is retired (a guaranteed 10/10, 0% hallucination, SQI scores,
  per-layer percentages, "Non-Hallucination Zone", prices and latencies nobody measured); the claims
  list in `scripts/check_site.py` blocks most of it. They also load Google Fonts, which the site must not do.
- The palette must pass WCAG 2.1 AA (4.5:1 for body text). `qa/site/` checks every page in CI, with the\n  system set to light and to dark (the site looks the same in both).
- Text must work at 320 px wide without horizontal scrolling.

### Logo

The mark chosen by the owner (2026-10-22): a rounded square with a zig-zag line and a diagonal
bar through it, with the word "Saikou" in a squared geometric face, in mint (`#11FAC0`) on black.
It exists as an AI-generated image; the vector files are a trace of it.

Files:
- `site/Saikou.tech-logo-flat-hor.svg`: horizontal logo, tight `viewBox`, transparent. Mint only,
  so it is for dark backgrounds (the whole site is dark).
- `site/Saikou.tech-favicon.svg`: the symbol on a dark rounded square (mint alone vanishes on a
  light browser tab).
- `docs/logo/Saikou.tech-logo-stacked.svg`: symbol above the wordmark, for square and social uses.
  Not used on the site yet.

Known limits of these files:
- They are a bitmap **trace**: at large sizes the edges of the frame are slightly wavy. Fine in the
  header, not for print or a large banner. Redraw as clean geometry before large use.
- One colour variant only; there is no ink version for light backgrounds yet.
- The symbol's thin strokes are weak at 16 px (acceptable at 32 px and up).
- The mark can read as a "chart trending up" (analytics or finance) rather than "verified fix".
  Whether that matters is the owner's call.

Requirements for any new or redrawn mark:

- Real vector (hand-built or cleanly redrawn), not a bitmap trace.
- Legible at 16 px (favicon), in one colour, on light and on dark.
- Wordmark and symbol usable separately.
- AI image tools may be used for exploration. The final mark is drawn as vector by a person or by
  Claude, then checked for distinctiveness and registrability (EUIPO TMview, BOIP) before anyone
  relies on it. No generator can promise a mark is unique.

## Design review of the current site (2026-10-22)

Findings below are from the first `qa/site` run (Playwright + axe-core, Edge, WCAG 2.1 A/AA) on both
staged builds, before the fix. The other browser checks passed: no request to another origin, no console errors, no horizontal
overflow at 320, 768 and 1280 px. **Screenshots were not reviewed by a person yet.**

- **Light mode, contrast:** `--ink-faint` (#6b7165) is 4.31:1 on `--ground` and 3.83:1 on `--chip`;
  `--warn` on `--warn-soft` is 4.06:1. The minimum is 4.5:1. Affected: footer, `.meta`, table
  headers, form labels, `.chip`, `.prov`, `.pill.warn`. **The interim page's footer is affected.**
- **Dark mode, header unreadable (interim and full):** `.site-head` uses `background: var(--ink)`,
  which turns light in dark mode, while the nav link colours are fixed light greys (`#c9cfc5`,
  `#fff`). Contrast is 1.21 to 1.31:1. A visitor whose system is in dark mode barely sees the nav.
- **Full site, keyboard:** scrollable `pre.term` blocks and `.tablewrap` cannot take keyboard focus
  (`scrollable-region-focusable`); they need `tabindex="0"`.
- **Fixed the same day (the four findings above):** `--ink-faint` is now `#5f6459` and `--warn`
  `#7f621b` (4.6:1 or better on every background they sit on); the header and tool bar use their
  own dark-band tokens (`--band`, `--band-ink`, `--band-soft`, `--band-line`) in both schemes;
  scrollable code blocks and tables have `tabindex="0"` and a visible focus ring. `qa/site` now
  passes on both staged builds (interim 20 of 20, full 74 of 74), light and dark.
- **Retire later, decorative:** the tracked-out capital `.eyebrow` with the em-dash prefix above
  most headings, and the uniform `.card` grid (gone from the home pages since 2026-10-30; still on
  the interim, services, NIS2 and checker pages). They are the most common "AI site" tells and carry
  no information.
- **Decided 2026-10-22: dark.** The paper-and-serif look was cohesive but common; the distinctive part
  of the site is the verdict and provenance system, which the dark palette lets stand out. Acid green
  on near-black is itself a common pattern, so the structure (real output, stamp, provenance) has to
  carry the identity, not the colour.

## Open decisions (owner)

1. Logo: who draws the vector mark, and which direction (wordmark-led or symbol-led)?
2. (Done) Dark, with mint as the brand accent.
3. (Done) The accessibility fix above is applied; both builds were restaged from it.
4. A tagline. The README line is the working one; no second line is invented here.
