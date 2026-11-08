const { defineConfig } = require('@playwright/test');
const path = require('path');

const siteDir = process.env.SITE_DIR;
if (!siteDir) {
  throw new Error('Set SITE_DIR to a staged site folder (python scripts/stage_site.py --mode full --out <empty dir>).');
}
const port = Number(process.env.SITE_PORT || 4173);

module.exports = defineConfig({
  testDir: './tests',
  outputDir: './test-results',
  reporter: [['list'], ['html', { open: 'never' }]],
  fullyParallel: true,
  retries: 0,
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    // CI installs Playwright's chromium. Locally the installed Edge is used, so no browser download.
    channel: process.env.CI ? undefined : (process.env.BROWSER_CHANNEL || 'msedge'),
  },
  // Light and dark are both held to WCAG 2.1 AA.
  projects: [
    { name: 'light', use: { colorScheme: 'light' } },
    { name: 'dark', use: { colorScheme: 'dark' } },
  ],
  webServer: {
    command: `node serve.js "${path.resolve(siteDir)}" ${port}`,
    url: `http://127.0.0.1:${port}/`,
    reuseExistingServer: false,
    timeout: 15000,
  },
});
