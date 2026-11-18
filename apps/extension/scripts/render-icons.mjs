/**
 * Renders the brand mark to the PNG sizes the browser needs. Run once after
 * changing the mark (needs Playwright with Chromium); the PNGs are committed.
 */
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Playwright is used from the global install rather than as a dependency.
const { chromium } = createRequire(import.meta.url)("playwright");

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "static", "icons");
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <path d="M3 29V5h3v2h2V5h3v6h2v2h2v-2h2v2h2v-2h2V5h3v2h2V5h3v24H3Z" fill="#121726"/>
  <path d="M13 29v-6.5a3 3 0 0 1 6 0V29h-6Z" fill="#f7f4ee"/>
  <path d="m16 14.6 2.6 2.6-2.6 2.6-2.6-2.6 2.6-2.6Z" fill="#d69832"/></svg>`;

const browser = await chromium.launch();
const page = await browser.newPage();
for (const size of [16, 32, 48, 128]) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace("<svg", `<svg width="${size}" height="${size}"`)}</body></html>`);
  await page.screenshot({ path: join(out, `icon-${size}.png`), omitBackground: true });
}
await browser.close();
console.log("Icons written to", out);
