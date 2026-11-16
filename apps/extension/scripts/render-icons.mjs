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
  <path d="M16 2.5 4.5 6.8v8.4c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V6.8L16 2.5Z" fill="#0c1424"/>
  <path d="M16 6.4 8.3 9.3v5.9c0 4.9 3.2 8.7 7.7 10.3 4.5-1.6 7.7-5.4 7.7-10.3V9.3L16 6.4Z" fill="#f5f6f8"/>
  <rect x="6.5" y="14.2" width="19" height="2.6" rx="1.3" fill="#0b9488"/>
  <circle cx="16" cy="15.5" r="2.4" fill="#0c1424"/></svg>`;

const browser = await chromium.launch();
const page = await browser.newPage();
for (const size of [16, 32, 48, 128]) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace("<svg", `<svg width="${size}" height="${size}"`)}</body></html>`);
  await page.screenshot({ path: join(out, `icon-${size}.png`), omitBackground: true });
}
await browser.close();
console.log("Icons written to", out);
