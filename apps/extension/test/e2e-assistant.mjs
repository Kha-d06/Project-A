/**
 * End-to-end check of pre-load blocking and the on-screen assistant in Chromium,
 * against a mock Qalaa API (test/mock-server.mjs). Runs without the real stack:
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
  family: { domains: ["casino.example"], groups: ["Home"] },
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
await page.waitForSelector("text=On Qalaa's list of known malicious domains");
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
// On a slow machine the page can load before the new setting reaches it: reload once.
await bubble.waitFor({ timeout: 20000 }).catch(async (error) => {
  console.error("No assistant bubble. Hosts the mock server was asked about:", seen.checks);
  throw error;
});
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

// 4. A family group's block list, applied by the linked account holder.
const familyPage = await context.newPage();
await familyPage.goto(`chrome-extension://${extensionId}/options.html`);
await familyPage.evaluate(() => chrome.runtime.sendMessage({ type: "refresh-account" }));
await familyPage.goto("https://www.casino.example/").catch(() => undefined);
for (let i = 0; i < 50 && !familyPage.url().includes("warning.html"); i++) await new Promise((r) => setTimeout(r, 200));
await familyPage.waitForSelector("text=Home blocks this site");
assert.equal(await familyPage.locator("summary").count(), 0, "no way to proceed past a family block");
await shot(familyPage, "ext-family-block");
step("family block list applied: warning names the group, no proceed option");

// 5. Tracker blocking and search-result badges.
let trackerLoads = 0;
await context.route(/google-analytics\.com/, (route) => {
  trackerLoads += 1;
  return route.fulfill({ contentType: "text/javascript", body: "" });
});
await context.route(/^https:\/\/www\.bing\.com\//, (route) =>
  route.fulfill({
    contentType: "text/html",
    body: `<html><body><ol id="b_results">
      <li><h2><a href="https://paypa1-login.example.com/">PayPal login</a></h2></li>
      <li><h2><a href="https://news.example.org/">News</a></h2></li></ol></body></html>`,
  }),
);
const settingsPage = await context.newPage();
await settingsPage.goto(`chrome-extension://${extensionId}/options.html`);
await settingsPage.evaluate(() => chrome.runtime.sendMessage({ type: "settings", changes: { blockTrackers: true, searchBadges: true } }));
const search = await context.newPage();
await search.goto("https://www.bing.com/search?q=paypal");
const flagged = search.locator("#b_results li", { hasText: "PayPal login" });
await search.waitForFunction(() => document.querySelectorAll("[data-sentinel-checked]").length === 2, null, { timeout: 10000 });
await search.waitForTimeout(500);
const badgeText = await search.evaluate(() => document.querySelectorAll("#b_results li")[0].querySelector("span") !== null);
assert.ok(badgeText, "a badge was added to the suspicious result");
assert.equal(await search.evaluate(() => document.querySelectorAll("#b_results li")[1].querySelector("span")), null, "clean results are left alone");
await shot(search, "ext-search-badges");
step("search results with warning signs are labelled; others untouched");
const before = trackerLoads;
const article = await context.newPage();
await context.route(/^https:\/\/news\.example\.org\//, (route) =>
  route.fulfill({ contentType: "text/html", body: `<html><body>News<script src="https://www.google-analytics.com/analytics.js"></script></body></html>` }),
);
await article.goto("https://news.example.org/");
await article.waitForTimeout(800);
assert.equal(trackerLoads, before, "the tracker request never left the browser");
step("third-party tracker blocked when tracker blocking is on");

// 6. Appearance: dark and light chosen in Options, on the extension's pages and the assistant.
const themePage = await context.newPage();
await themePage.goto(`chrome-extension://${extensionId}/options.html`);
const pageCanvas = () => themePage.evaluate(() => getComputedStyle(document.body).backgroundColor);
await themePage.selectOption("#theme", "dark");
await themePage.waitForFunction(() => document.documentElement.dataset.theme === "dark");
assert.equal(await pageCanvas(), "rgb(7, 11, 22)");
await shot(themePage, "ext-options-dark");
await shop.reload();
await shop.waitForFunction(() => document.getElementById("sentinel-assistant-root")?.shadowRoot?.querySelector(".wrap.dark") != null, null, { timeout: 10000 });
await themePage.selectOption("#theme", "light");
await themePage.waitForFunction(() => document.documentElement.dataset.theme === "light");
assert.equal(await pageCanvas(), "rgb(247, 244, 238)");
await themePage.selectOption("#theme", "system");
await themePage.close();
step("appearance: dark and light themes on the extension's pages and the assistant");

// 7. Arabic.
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
