// Browser checks for a staged site (SITE_DIR). Every page, in light and dark:
//   - nothing is requested from another origin (the runtime form of "no third-party requests")
//   - no console errors, page errors or failed local requests
//   - axe: no WCAG 2.1 A/AA violations
//   - no horizontal overflow at 320, 768 and 1280 px
// plus the in-browser checker on the pages that have one. Screenshots are attached for a person to
// look at; they are never compared against a baseline (system fonts differ per OS).
const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const fs = require('fs');
const path = require('path');

const SITE_DIR = path.resolve(process.env.SITE_DIR);
const WIDTHS = [320, 768, 1280];
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

function htmlFiles(dir, base = '') {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const rel = base ? `${base}/${e.name}` : e.name;
    if (e.isDirectory()) return htmlFiles(path.join(dir, e.name), rel);
    return e.name.endsWith('.html') ? [rel] : [];
  });
}

const pages = htmlFiles(SITE_DIR).sort();
if (pages.length === 0) throw new Error(`No .html files in ${SITE_DIR}`);

for (const rel of pages) {
  test.describe(rel, () => {
    test('loads from this origin only, without errors', async ({ page, baseURL }) => {
      const origin = new URL(baseURL).origin;
      const foreign = [];
      const problems = [];
      page.on('request', (r) => {
        const u = new URL(r.url());
        if (!['data:', 'blob:', 'about:'].includes(u.protocol) && u.origin !== origin) foreign.push(r.url());
      });
      page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
      await page.goto(`/${rel}`, { waitUntil: 'networkidle' });
      expect(foreign, 'requests to another origin').toEqual([]);
      expect(problems).toEqual([]);
    });

    test('axe: no WCAG 2.1 A/AA violations', async ({ page }) => {
      await page.goto(`/${rel}`, { waitUntil: 'networkidle' });
      const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
      expect(
        violations.map((v) => ({
          rule: v.id,
          impact: v.impact,
          help: v.help,
          where: v.nodes.slice(0, 5).map((n) => n.target.join(' ')),
        })),
      ).toEqual([]);
    });

    for (const width of WIDTHS) {
      test(`no horizontal overflow at ${width}px`, async ({ page }, testInfo) => {
        await page.setViewportSize({ width, height: 900 });
        await page.goto(`/${rel}`, { waitUntil: 'networkidle' });
        const shot = testInfo.outputPath(`${rel.replace(/[\\/]/g, '_')}-${width}.png`);
        await page.screenshot({ path: shot, fullPage: true });
        await testInfo.attach(`${rel} @ ${width}px`, { path: shot, contentType: 'image/png' });
        // The page itself must not scroll sideways. Wide tables and code blocks that scroll inside
        // their own container (overflow auto/scroll/hidden) are fine; they are left out of the culprits.
        const wide = await page.evaluate(() => {
          const limit = document.documentElement.clientWidth;
          const clipped = (el) => {
            for (let a = el.parentElement; a && a !== document.documentElement; a = a.parentElement) {
              if (['auto', 'scroll', 'hidden'].includes(getComputedStyle(a).overflowX)) return true;
            }
            return false;
          };
          const out = [];
          for (const el of document.body.querySelectorAll('*')) {
            const r = el.getBoundingClientRect();
            if (r.width > 0 && r.right > limit + 1 && !clipped(el)) out.push(`${el.tagName.toLowerCase()}.${el.className || ''} right=${Math.round(r.right)}`);
          }
          return { overflow: document.documentElement.scrollWidth - limit, culprits: out.slice(0, 5) };
        });
        expect(wide.overflow, `page scrolls sideways at ${width}px; wide elements: ${wide.culprits.join(', ')}`).toBeLessThanOrEqual(0);
      });
    }
  });
}

// The home pages' interactive parts: every tab, finding, switch and filter, then axe again, because
// a check at page load does not see what the clicks reveal.
const homePages = pages.filter((p) => fs.readFileSync(path.join(SITE_DIR, p), 'utf8').includes('data-explorer'));
for (const rel of homePages) {
  test(`${rel}: explorer, charts and filters work and stay accessible`, async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(`/${rel}`, { waitUntil: 'networkidle' });
    const data = await page.evaluate(() => window.SAIKOU_DATA);
    const tabs = page.getByRole('tab');
    await expect(tabs).toHaveCount(data.demo.length);
    for (let i = 0; i < data.demo.length; i++) {
      const c = data.demo[i];
      await tabs.nth(i).click();
      await expect(tabs.nth(i)).toHaveAttribute('aria-selected', 'true');
      await expect(tabs.nth(i).locator('.tab-mark')).toHaveClass(c.blocked ? /fail/ : /pass/);
      const panel = page.locator(`#case-${c.id}`);
      await expect(panel).toBeVisible();
      const buttons = panel.locator('.findings button');
      await expect(buttons).toHaveCount(c.findings.length);
      for (let j = 0; j < c.findings.length; j++) {
        await buttons.nth(j).click();
        await expect(panel.locator('.dl.focus')).toHaveCount(c.findings[j].line ? 1 : 0);
      }
    }
    await tabs.first().focus();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.nth(1)).toBeFocused();

    await page.locator('[data-switch] [data-show="js"]').click();
    await expect(page.locator('[data-cov="js"]')).toBeVisible();
    await expect(page.locator('[data-cov="python"]')).toBeHidden();
    await expect(page.locator('.bar-row')).toHaveCount(data.coverage.js.tools.length);

    await page.locator('[data-waffle-switch] [data-show="new"]').click();
    const blockedAsNew = data.measured.reduce((s, m) => s + m.as_new_blocked, 0);
    await expect(page.locator('.waffles .w-new')).toHaveCount(blockedAsNew);
    await expect(page.locator('.waffles rect')).toHaveCount(data.measured.reduce((s, m) => s + m.files, 0));

    await page.locator('[data-catalogue] > summary').click();
    await page.locator('[data-filters] [data-prov="tool"]').click();
    const toolRows = await page.locator('.cat-table tbody tr[data-prov="tool"]').count();
    await expect(page.locator('.cat-table tbody tr:visible')).toHaveCount(toolRows);

    const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
    expect(violations.map((v) => ({ rule: v.id, where: v.nodes.slice(0, 5).map((n) => n.target.join(' ')) }))).toEqual([]);
    expect(errors).toEqual([]);
  });
}

// The language hint: shown only when the browser prefers the other language, gone after closing.
const hintCases = [['index.html', 'nl-NL', true], ['index.html', 'en-GB', false],
  ['nl/index.html', 'en-GB', true], ['nl/index.html', 'nl-NL', false]].filter(([p]) => homePages.includes(p));
for (const [rel, locale, shown] of hintCases) {
  test(`${rel} with browser language ${locale}: language hint ${shown ? 'shown' : 'hidden'}`, async ({ browser, baseURL }) => {
    const ctx = await browser.newContext({ locale, baseURL });
    const page = await ctx.newPage();
    await page.goto(`/${rel}`, { waitUntil: 'networkidle' });
    const hint = page.locator('[data-lang-hint]');
    if (shown) {
      await expect(hint).toBeVisible();
      const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
      expect(violations.map((v) => v.id)).toEqual([]);
      await hint.getByRole('button').click();
      await expect(hint).toBeHidden();
    } else {
      await expect(hint).toBeHidden();
    }
    await ctx.close();
  });
}

// GitHub Pages serves 404.html at whatever address was missed, however deep: its styles, logo and
// links must still resolve from there.
if (pages.includes('404.html')) {
  test('404.html works at a deep missing address', async ({ page }) => {
    const failed = [];
    page.on('requestfinished', async (r) => {
      if (r.url() !== page.url() && (await r.response())?.status() >= 400) failed.push(r.url());
    });
    page.on('requestfailed', (r) => failed.push(r.url()));
    const res = await page.goto('/no/such/page.html', { waitUntil: 'networkidle' });
    expect(res.status()).toBe(404);
    await expect(page.locator('h1')).toBeVisible();
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).not.toBe('rgba(0, 0, 0, 0)');
    expect(await page.locator('.brand img').evaluate((img) => img.naturalWidth)).toBeGreaterThan(0);
    for (const href of await page.locator('main a').evaluateAll((as) => as.map((a) => a.getAttribute('href')))) {
      expect((await page.request.get(href)).status(), href).toBe(200);
    }
    expect(failed).toEqual([]);
  });
}

// The in-browser checker must still turn the "fake fix" example into a blocked verdict.
for (const rel of ['tools/checker.html', 'nl/werkbank.html'].filter((p) => pages.includes(p))) {
  test(`${rel}: the fake-fix example is blocked`, async ({ page }) => {
    await page.goto(`/${rel}`, { waitUntil: 'networkidle' });
    await page.click('button[data-preset="fake"]');
    await page.click('#run');
    await expect(page.locator('#stamp')).toHaveText(/^\s*(blocked|geblokkeerd)\s*$/i);
  });
}
