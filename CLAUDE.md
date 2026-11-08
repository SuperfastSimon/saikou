# Saikou - working notes for Claude

These are the working rules for anyone (or any agent) changing this repository. The maintainer
keeps machine-specific notes in `CLAUDE.local.md` and `internal/`; both are git-ignored and not
part of the published tree.

## What this is

Saikou checks whether a security fix is real rather than just claimed. It compares code before
and after a change and hard-fails transformations that only *look* hardened (new analyser
suppressions, weakened analyser config, unwired guards, partial shared-sink fixes, elision,
comment-only edits, API breaks). No score, ever: every finding carries a provenance
(`tool` / `parser` / `mechanical`) and every report states its verification tier and limits.

## Layout

| Path | What |
|---|---|
| `saikou/engine.py` | Detectors, `scan_transformation`, ledger, self-test. **Standard library only.** |
| `saikou/verify.py` | Per-file verification, config-weakening checks, git change collection |
| `saikou/catalog.py` | Bilingual (en/nl) description of every check; must match what the engine emits |
| `saikou/service.py` | Request logic shared by the hosted API and the local app (dicts in, dicts out) |
| `saikou/cli.py` | `saikou verify / diff / harden / selftest / ui` |
| `saikou/llm.py` | Bring-your-own-key model calls; providers `openai`, `ollama` (cloud), `local` |
| `saikou/api.py` | Hosted FastAPI service (`saikou[api]`): `/v1/verify`, `/v1/verify/batch`, `/v1/checks`, playground on `/`. Never touches files or git |
| `saikou/server.py` | Local app behind `saikou ui`: stdlib server on 127.0.0.1, session key, Host/Origin checks |
| `saikou/webassets.py` | Serves the packaged `saikou/web/` files to the local app and the hosted playground |
| `saikou/web/` | The web app: vanilla JS + CSS, no build, no third-party requests. `sample.json` is the "Load an example" fake fix |
| `saikou/sarif.py` | SARIF 2.1.0 output |
| `site/` | saikou.tech source (English + Dutch), no third-party requests |
| `site/sitemap.xml`, `site/robots.txt` | Search metadata; `scripts/check_site.py` checks them against the pages |
| `site/assets/og-*.png`, `site/404.html` | Social preview images (rendered by `qa/site/og-image.js`, never drawn by hand); bilingual not-found page (root-relative links, noindex) |
| `docs/brand.md` | Brand brief: positioning, voice, proof, visual rules, open decisions. Read before any site, logo or launch copy work |
| `docs/logo/` | Logo variants not used on the site yet (stacked). The header logo and favicon are `site/Saikou.tech-logo-flat-hor.svg` and `site/Saikou.tech-favicon.svg` (traced from an AI image; redraw before large use) |
| `.claude/skills/saikou-site-design/` | Project skill for site, logo and launch-material work; points at `docs/brand.md` and `style.css` tokens |
| `qa/site/` | Browser checks (Playwright, axe, Lighthouse report) on the staged site; Node dev tooling, not in the package. `.github/workflows/site.yml` |
| `docs/business/` | Public service descriptions and scope-agreement templates (en + nl) |
| `docs/measurements/` | False-positive measurements on real code |
| `scripts/` | `fp_corpus.py`, `render_site_demo.py`, `render_site_data.py`, `stage_site.py`, `check_site.py`, `suppression_oracle.py`, `suppression_oracle_js.py` |
| `plugins/`, `.claude-plugin/` | Claude Code plugin + marketplace; `action.yml` = GitHub Action |
| `saikou_harden.py` | Compatibility shim for the old single-file engine |
| `Dockerfile`, `.dockerignore` | Image for the hosted API (non-root; no `.env`, `internal/` or `.git` in it) |

## Commands (run from the repo root)

```bash
py -3.11 -m venv .venv && ./.venv/Scripts/python.exe -m pip install -e ".[dev]"   # once
./.venv/Scripts/python.exe -m pytest -q          # all tests
./.venv/Scripts/saikou.exe selftest              # engine self-test (no network)
./.venv/Scripts/saikou.exe ui --no-browser       # local app; prints the link with its session key
docker build -t saikou-api .                     # hosted API image
./.venv/Scripts/python.exe scripts/render_site_demo.py                      # refresh site demo output
./.venv/Scripts/python.exe scripts/render_site_data.py                      # refresh site numbers, explorer and chart data
./.venv/Scripts/python.exe scripts/stage_site.py --mode full --out <empty dir>   # build + check site
cd qa/site && npm ci --ignore-scripts && SITE_DIR=<staged dir> npx playwright test   # browser checks on a staged site
cd qa/site && node og-image.js                   # social preview PNGs from the home pages (after an h1 or hero change)
./.venv/Scripts/python.exe scripts/fp_corpus.py <dir> --nested              # false-positive measurement
```

All tests and the self-test must pass before any commit.

## Rules

- **Engine stays stdlib-only.** Optional dependencies live behind extras (`[api]`, `[analyser]`, `[dev]`).
- **No score, no guarantees, no unsupported claims** - in code, docs, site and marketing.
  `scripts/check_site.py` blocks known false claims; keep its banned list current.
- **A new hard-fail rule needs a false-positive measurement** on real code (`fp_corpus.py`)
  and a regression test for every false positive found. Update `catalog.py`; `tests/test_catalog.py`
  fails if the catalogue and the engine disagree.
- **Changing an existing check: compare old and new engine.** `fp_corpus.py` only appends a
  harmless probe, so it cannot show what a change does to existing text. Run the old (HEAD) and the
  new engine over the same large corpus, in gating, new-file and verify mode, and read every
  difference. Gating must stay 0 -> 0.
- **New or changed regexes must stay linear** on very long lines: an earlier marker pattern took
  90 s on one 4.6 MB minified line. Time every new or changed pattern on such a line.
- **Suppression markers in Python are read from comment tokens** (as bandit 1.7.3+, Sonar and
  CodeQL do); flake8 `noqa`, `nosemgrep` and `usedforsecurity=False` stay on the raw line because
  those tools match it. `bandit>=1.7.3` is the minimum: 1.7.0-1.7.2 honour `# nosec` inside strings.
- **Changing how suppressions are counted: use `scripts/suppression_oracle.py`.** It runs the real
  bandit, ruff and semgrep and compares Saikou with what they honour (`all --work <dir> --bandit
  <exe> --ruff <exe> --semgrep <exe>`, then `engine` under 3.12 and 3.14; steps and refresh order
  are in the script's docstring). Never decide what a tool honours from reading its source alone:
  "a glued word skips nothing" for bandit and "semgrep matches comments only" were both wrong
  and only running the tools showed so.
- **The published suppression coverage is generated**, not written: `tests/test_suppression_oracle.py`
  and `tests/test_suppression_oracle_js.py` hold Saikou to the verdicts frozen in
  `tests/fixtures/suppression_oracle_golden.json` and `..._js_golden.json` (Python, and JavaScript and
  TypeScript with ESLint, tsc and semgrep), and `docs/conformance/suppression-coverage*.md` come from
  those files (`... conformance`). After an
  intended change: look at what moved, `freeze`, `conformance`, run the tests. Quote the numbers
  from that file together with its scope, never rounded up or without the reference tool versions.
- **Never write a suppression or elision marker literally in a real comment in `saikou/` or
  `tests/`** (describe it instead): the engine counts it, and `saikou diff` blocks the file.
- **Example fake fixes are data, never code.** Keep them in `saikou/web/sample.json` or
  `tests/fixtures/`, not as string literals in `saikou/`: the `dogfood` CI job runs Saikou on
  `saikou/`, and a fake fix written into code would be read as one.
- **Customer-facing material is bilingual:** English and Dutch, both complete.
- **No placeholders** in delivered work unless genuinely blocked; then say so explicitly.
- **Secrets:** keys live in `.env` (git-ignored). Never print, log, copy or commit a key value;
  check presence only. Never put credentials in code, argv or URLs.
- **Outward actions need an explicit yes in chat** each time: pushing, creating repos, publishing
  to PyPI, deploying the site, sending messages, creating accounts.
- **Site and brand work:** read `docs/brand.md` and the `saikou-site-design` skill first. Every number on the
  home pages and all data behind the explorer and charts come from `scripts/render_site_data.py`
  (`<!--data:...-->` slots and `site/assets/site-data.js`); never type a number into a page, and run the script
  after changing the demo, the oracle answers, a measurement or the catalogue (a test fails otherwise). JavaScript
  on the site only shows and draws; all prose stays in the HTML, where `check_site.py` reads it. The site is
  **dark in every colour scheme** (decided 2026-10-22); tokens live only in `site/assets/style.css`,
  mint is the brand accent and also means "passes", so use it sparingly. No third-party request of
  any kind (no Google Fonts, CDN, analytics). Before saying site work is done: stage both builds,
  run `qa/site` on them, and look at the screenshots.
- **Commits:** never change git config.

## Windows pitfalls (learned the hard way)

- Bash heredocs that contain backslashes can corrupt bytes (a `"\x00"` became a real NUL byte and
  broke an import). Write files with the Write/Edit tools; run multi-line Python from a script file.
- Windows Python does not understand Git Bash paths (`/c/Users/...`): pass `C:\...` or use
  `%TEMP%`-style paths inside Python.
- `printf` with Windows paths turns `\U...` into an escape - write such text with the Write tool.
- `subprocess.run(..., text=True)` decodes with the Windows locale codec (cp1252), but the CLI writes
  UTF-8: always pass `encoding="utf-8"`, and `PYTHONIOENCODING=utf-8` when the env is replaced. Without
  it the site showed "Â·" for "·" (fixed 2026-10-31); `check_site.py` now fails on such mojibake.
- Text written on Windows has CRLF line endings; compare content with line endings normalised.
  `.gitattributes` stores everything as LF.
- The Bash tool's working directory can reset between calls - use absolute paths.
- A unicode escape for a line separator (U+2028, U+2029) typed into a Write/Edit parameter lands
  in the file as the real, invisible character. Write such escapes from a script, and scan edited
  files for control and separator characters before committing.
- PowerShell: a function named `H` is shadowed by the `h` alias (Get-History); name helpers
  `Get-Something`. In double-quoted strings a backtick escape eats characters (`` `f `` becomes a
  form feed); write text with backticks in single quotes or with the Write tool.
- Background wait loops (`Start-Sleep`) and measurements started from the tool die when the tool
  connection drops. Run long measurements as detached processes (`Start-Process`) and check their
  result files.
