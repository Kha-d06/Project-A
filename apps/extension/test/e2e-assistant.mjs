/**
 * End-to-end check of pre-load blocking and the on-screen assistant in Chromium,
 * against a mock SENTINEL API (test/mock-server.mjs). Runs without the real stack:
 *
 *   SENTINEL_TEST_BUILD=1 SENTINEL_SERVER=http://localhost:8787 npm run build
 *   node test/e2e-assistant.mjs [screenshot-dir]
 */
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startMockServer } from "./mock-server.mjs";

const { chromium } = createRequire(import.meta.url)("playwright");
const extensionPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "chrome");
const shots = process.argv[2];
const step = (text) => console.log(`✓ ${text}`);

const { server, seen } = await startMockServer(8787, {
  verdicts: { "paypa1-login.example.com": "suspicious" },
  blocklist: ["preload-evil.example"],
});

const context = await chromium.launchPersistentContext(await mkdtemp(join(tmpdir(), "sentinel-e2e-")), {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
});
const shot = async (page, name) => shots && page.screenshot({ path: join(shots, `${name}.png`), fullPage: false });

const PHISH = `<!doctype html><html><head><title>Sign in</title>
<script src="https://www.google-analytics.com/analytics.js"></script>
<script src="https://connect.facebook.net/en_US/fbevents.js"></script></head>
<body style="font-family:sans-serif;padding:40px"><h1>PayPal sign in</h1>
<form><input name="email" placeholder="Email"><br><br><input type="password" id="pw" placeholder="Password"></form>
<script>document.cookie = "sid=SECRET-SESSION-VALUE; path=/"; document.cookie = "_ga=GA1.2.3; max-age=31536000; path=/";</script>
</body></html>`;
await context.route(/^https?:\/\/paypa1-login\.example\.com\//, (route) => route.fulfill({ contentType: "text/html", body: PHISH }));
await context.route(/google-analytics\.com|facebook\.net/, (route) => route.fulfill({ contentType: "text/javascript", body: "/* tracker stand-in */" }));

let [worker] = context.serviceWorkers();
worker ??= await context.waitForEvent("serviceworker");
const extensionId = new URL(worker.url()).host;

// Wait for enrollment and the blocklist download.
for (let i = 0; i < 50; i++) {
  const stored = await worker.evaluate(() => chrome.storage.local.get("blocklist"));
  if (stored.blocklist) break;
  await new Promise((r) => setTimeout(r, 200));
}
const rules = await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
assert.deepEqual(rules.find((r) => r.id === 1)?.condition.requestDomains, ["preload-evil.example"]);
step("blocklist downloaded and installed as a declarativeNetRequest rule");

// 1. A listed domain is stopped inside the browser, before any request leaves it.
const page = await context.newPage();
await page.goto("http://preload-evil.example/login").catch(() => undefined);
for (let i = 0; i < 50 && !page.url().includes("warning.html"); i++) await new Promise((r) => setTimeout(r, 200));
assert.ok(page.url().includes("warning.html"), `warning page shown (at ${page.url()})`);
await page.waitForSelector("text=On SENTINEL's list of known malicious domains");
await shot(page, "ext-preload-warning");
step("listed domain blocked before loading; warning page explains why");

await context.route(/^http:\/\/preload-evil\.example\//, (route) => route.fulfill({ contentType: "text/html", body: "<title>Listed</title><h1>Listed page</h1>" }));
await page.click("summary");
await page.click("text=Continue to preload-evil.example");
await page.waitForSelector("text=Listed page", { timeout: 10000 });
step("'Continue anyway' lets that one domain through for the session");

// 2. Turn on the assistant (and Arabic later) through the options page.
const options = await context.newPage();
await options.goto(`chrome-extension://${extensionId}/options.html`);
await options.evaluate(() => chrome.runtime.sendMessage({ type: "settings", changes: { assistant: true, warnOnSuspicious: false } }));
await options.close();

// 3. On a suspicious page the assistant warns, lists cookies and trackers, and answers.
const shop = await context.newPage();
await shop.goto("https://paypa1-login.example.com/");
const bubble = shop.locator("#sentinel-assistant-root .bubble");
await bubble.waitFor({ timeout: 10000 });
assert.match(await bubble.innerText(), /Suspicious/);
await shot(shop, "ext-assistant-warning");
step("assistant shows a warning bubble on a suspicious page");

await shop.locator("#sentinel-assistant-root .bubble button", { hasText: "Dismiss" }).click();
await shop.click("#pw");
await shop.locator("#sentinel-assistant-root .bubble", { hasText: "Stop before typing your password" }).waitFor();
await shot(shop, "ext-assistant-password");
step("focusing a password field on a suspicious page shows a warning");

await shop.locator("#sentinel-assistant-root .fab").click();
const card = shop.locator("#sentinel-assistant-root .card");
await card.waitFor();
await card.locator("text=Meta Pixel").waitFor();
const cardText = await card.innerText();
assert.match(cardText, /Google Analytics/);
assert.match(cardText, /_ga/);
assert.match(cardText, /sid/);
assert.ok(!cardText.includes("SECRET-SESSION-VALUE"), "cookie values are never shown");
step("assistant lists cookie names and trackers, never cookie values");

await card.locator("button.chip").first().click();
await card.locator(".answer", { hasText: "Built-in answer" }).waitFor();
assert.match(await card.locator(".answer").innerText(), /Do not enter passwords/);
await shot(shop, "ext-assistant-card");
const sent = JSON.stringify(seen.assistantContexts);
assert.ok(seen.assistantContexts.length === 1 && !sent.includes("SECRET-SESSION-VALUE"), "server got a summary without cookie values");
assert.equal(seen.assistantContexts[0].context.host, "paypa1-login.example.com");
step("questions go to the server with a summary only, and fall back to built-in answers");

// 4. Arabic.
const options2 = await context.newPage();
await options2.goto(`chrome-extension://${extensionId}/options.html`);
await options2.evaluate(() => chrome.runtime.sendMessage({ type: "settings", changes: { language: "ar" } }));
await options2.reload();
assert.equal(await options2.evaluate(() => document.documentElement.dir), "rtl");
await options2.locator("text=المساعد على الشاشة").waitFor();
await shot(options2, "ext-options-ar");
await shop.reload();
await shop.locator("#sentinel-assistant-root .bubble", { hasText: "مشبوه" }).waitFor({ timeout: 10000 });
await shot(shop, "ext-assistant-ar");
step("options page and assistant switch to Arabic, right to left");

await context.close();
server.close();
console.log("All extension assistant checks passed.");
