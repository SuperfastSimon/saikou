// Renders the social preview images (og:image, 1200x630 PNG) from the home pages themselves: the
// logo, the h1 and the hero's blocked fix, styled by the site's own CSS. No text is typed here, so
// the image says what the page says.
//   cd qa/site && node og-image.js      (writes site/assets/og-en.png and og-nl.png)
// Run it after changing a home page's h1 or hero, then look at both images. Locally the installed
// Edge is used, as in the browser checks.
const { chromium } = require('@playwright/test');
const path = require('path');
const { pathToFileURL } = require('url');

const SITE = path.resolve(__dirname, '..', '..', 'site');
const CARDS = [['index.html', 'og-en.png'], ['nl/index.html', 'og-nl.png']];

// Layout only; every colour comes from the tokens in site/assets/style.css.
const CARD_CSS = `
  html, body { margin: 0; width: 1200px; height: 630px; overflow: hidden; background: var(--ground); }
  .og { width: 1200px; height: 630px; padding: 56px 72px 60px; display: flex; flex-direction: column; gap: 28px; }
  .og-top { display: flex; align-items: center; justify-content: space-between; }
  .og-top img { height: 44px; width: auto; }
  .og-top span { font-family: var(--mono); font-size: 22px; color: var(--ink-soft); }
  .og h1 { font-size: 60px; max-width: none; margin: 0; }
  .og .proof { margin-top: auto; padding: 22px 26px; }
  .og .proof pre.term { font-size: 21px; white-space: pre; overflow: hidden; }
  .og .pl { display: inline; }
  .og-row { display: flex; align-items: center; gap: 28px; margin-top: 22px; }
  .og-row .proof-verdict { margin: 0; }
  .og .stamp { font-size: 26px; }
  .og .proof-findings { font-size: 20px; gap: 8px 24px; }
  .og .prov { font-size: 15px; }
`;

(async () => {
  const browser = await chromium.launch({ channel: process.env.CI ? undefined : (process.env.BROWSER_CHANNEL || 'msedge') });
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1, colorScheme: 'dark' });
  for (const [rel, out] of CARDS) {
    await page.goto(pathToFileURL(path.join(SITE, rel)).href, { waitUntil: 'load' });
    await page.evaluate((css) => {
      const take = (sel) => {
        const el = document.querySelector(sel);
        if (!el) throw new Error(`og-image: ${sel} not found on ${location.pathname}`);
        return el.cloneNode(true);
      };
      const make = (tag, cls, ...kids) => {
        const el = document.createElement(tag);
        if (cls) el.className = cls;
        el.append(...kids);
        return el;
      };
      const top = make('div', 'og-top', take('.site-head .brand img'), make('span', '', 'saikou.tech'));
      const proof = make('figure', 'proof', take('.proof pre.term'),
        make('div', 'og-row', take('.proof .proof-verdict'), take('.proof .proof-findings')));
      const style = document.createElement('style');
      style.textContent = css;
      document.head.append(style);
      document.body.replaceChildren(make('div', 'og', top, take('main h1'), proof));
    }, CARD_CSS);
    await page.evaluate(() => document.fonts.ready);
    const file = path.join(SITE, 'assets', out);
    await page.screenshot({ path: file });
    console.log(`wrote ${path.relative(path.resolve(SITE, '..'), file)}`);
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
