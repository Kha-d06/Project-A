/**
 * Renders the Qalaa citadel mark to the website (PWA) and desktop app icons.
 * Run once after changing the mark (needs Playwright with Chromium); the PNGs
 * are committed. The extension's icons come from apps/extension/scripts/render-icons.mjs.
 */
import { createRequire } from "node:module";
import { copyFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { chromium } = createRequire(import.meta.url)("playwright");
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const icons = join(root, "apps/web/public/icons");

// Night-blue tile with a warm radial glow, the citadel in parchment and a brass keystone.
const mark = (size, pad) => `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="${-pad} ${-pad} ${32 + 2 * pad} ${32 + 2 * pad}">
  <defs><radialGradient id="g" cx="50%" cy="78%" r="70%"><stop offset="0" stop-color="#3a2a12"/><stop offset="1" stop-color="#070b16"/></radialGradient></defs>
  <rect x="${-pad}" y="${-pad}" width="${32 + 2 * pad}" height="${32 + 2 * pad}" fill="url(#g)"/>
  <path d="M3 29V5h3v2h2V5h3v6h2v2h2v-2h2v2h2v-2h2V5h3v2h2V5h3v24H3Z" fill="#eee9df"/>
  <path d="M13 29v-6.5a3 3 0 0 1 6 0V29h-6Z" fill="#070b16"/>
  <path d="m16 14.6 2.6 2.6-2.6 2.6-2.6-2.6 2.6-2.6Z" fill="#e9b453"/></svg>`;

const browser = await chromium.launch();
const page = await browser.newPage();
// "maskable" icons need a safe zone, so they get more padding.
for (const [name, size, pad] of [["icon-192.png", 192, 6], ["icon-512.png", 512, 6], ["maskable-512.png", 512, 11], ["apple-touch-icon.png", 180, 6]]) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0">${mark(size, pad)}</body></html>`);
  await page.screenshot({ path: join(icons, name) });
}
await browser.close();
// The desktop app and its installers use the 512px icon.
await copyFile(join(icons, "icon-512.png"), join(root, "apps/desktop/build/icon.png"));
await copyFile(join(icons, "icon-512.png"), join(root, "apps/desktop/src/renderer/icon.png"));
console.log("App icons written.");
