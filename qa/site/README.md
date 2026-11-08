# qa/site - browser checks for the staged site

Dev tooling only. It is not in the wheel or the sdist, and the engine stays standard-library only.
It tests the **staged** site (what would be published), not `site/` directly.

```bash
# from the repo root
./.venv/Scripts/python.exe scripts/stage_site.py --mode full --out <empty dir>
cd qa/site
npm ci --ignore-scripts                 # exact versions from package-lock.json
SITE_DIR=<that dir> npx playwright test # PowerShell: $env:SITE_DIR = "<that dir>"
```

Locally it drives the installed Edge (`BROWSER_CHANNEL=chrome` for Chrome); no browser download.
CI uses Playwright's chromium (`.github/workflows/site.yml`).

**Hard checks, every page, with the system set to light and to dark (the site is dark in both):** no request to another origin; no console or page
errors; axe finds no WCAG 2.1 A/AA violation; no horizontal overflow at 320, 768 and 1280 px;
the in-browser checker turns the fake-fix example into a blocked verdict.

**Screenshots** go to `test-results/` and the HTML report for a person to look at. They are not
compared with a baseline: the site uses system fonts, so Windows and Linux never match pixel for pixel.

**Social preview images** (`og:image`, 1200x630 PNG) are rendered from the home pages themselves:
the logo, the h1 and the hero's blocked fix, styled by the site's CSS. Run `node og-image.js` after
changing a home page's h1 or hero; it rewrites `site/assets/og-en.png` and `og-nl.png`. Look at
both: `scripts/check_site.py` checks that they exist and have the stated size, not what they show.

**No Lighthouse.** It was a report-only step, and `@lhci/cli` brought in every `npm audit` finding
of this folder, so it was removed (2026-11-08). If it comes back, keep its numbers out of the site
and the docs: the project has no score, and a Lighthouse score would be one.

Pinned versions were each released more than a month before this was written (2026-10-22), so
nothing brand new is pulled in. Update deliberately, together with the lockfile.
