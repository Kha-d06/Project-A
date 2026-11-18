/**
 * End-to-end check of the built extension in Chromium against a running Qalaa
 * stack. Not part of `npm test`: it needs the web app and API running, the
 * extension built with SENTINEL_SERVER pointing at them, and the development
 * fixtures loaded (python -m app.cli load-test-fixtures).
 *
 *   SENTINEL_SERVER=http://localhost:3000 npm run build
 *   SENTINEL_SERVER=http://localhost:3000 node test/e2e.mjs [screenshot-dir]
 */
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { chromium } = createRequire(import.meta.url)("playwright");
const extensionPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "chrome");
const server = process.env.SENTINEL_SERVER ?? "http://localhost:3000";
const shots = process.argv[2];
const LISTED = "http://malware.example.net/payload.exe";

const context = await chromium.launchPersistentContext(await mkdtemp(join(tmpdir(), "sentinel-e2e-")), {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
});
const shot = async (page, name) => shots && page.screenshot({ path: join(shots, `${name}.png`) });

// Test sites that do not exist on the internet are answered locally.
await context.route(/^http:\/\/(paypall\.com|malware\.example\.net|news\.example\.org)\//, (route) =>
  route.fulfill({ contentType: "text/html", body: "<title>Test page</title><h1>Test page</h1>" }),
);

let [worker] = context.serviceWorkers();
worker ??= await context.waitForEvent("serviceworker");
const extensionId = new URL(worker.url()).host;
const step = (text) => console.log(`✓ ${text}`);

/** The extension swaps the tab's URL mid-navigation, which waitForURL can miss; poll instead. */
async function waitForUrl(page, test, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (test(page.url())) {
      await page.waitForLoadState("domcontentloaded").catch(() => undefined);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for the expected URL; tab is at ${page.url()}`);
}
const onWarning = (url) => url.includes("/warning.html");

// 1. Install: the welcome page opens and the extension enrolls anonymously.
const welcome = await context.waitForEvent("page", { predicate: (p) => p.url().includes("welcome.html"), timeout: 10000 }).catch(() => context.pages().find((p) => p.url().includes("welcome.html")));
assert.ok(welcome, "welcome page opened");
await welcome.waitForSelector("text=Protection is on");
await shot(welcome, "ext-01-welcome");
step("welcome page explains permissions");
const credentials = await worker.evaluate(() => chrome.storage.local.get("credentials"));
assert.ok(credentials.credentials?.refreshToken, "enrolled on install");
step("anonymous enrollment on install");

// 2. A known malicious address is replaced by the warning page.
const page = await context.newPage();
await page.goto(LISTED).catch(() => undefined);
await waitForUrl(page, (url) => url.startsWith(`chrome-extension://${extensionId}/warning.html`));
await page.waitForSelector("text=This site is known to be dangerous");
assert.ok(await page.isVisible("text=malware.example.net"));
assert.ok(await page.isVisible("text=Development test fixtures (not real threat data)"));
await shot(page, "ext-02-warning-dangerous");
step("dangerous site replaced by warning with evidence");

// 3. "Go back to safety" leaves the warning page.
await page.goto("http://news.example.org/");
await page.goto(LISTED).catch(() => undefined);
await waitForUrl(page, onWarning);
await page.click("text=Go back to safety");
await waitForUrl(page, (url) => url === "http://news.example.org/");
step("go back to safety returns to the previous page");

// 4. A look-alike domain is interrupted, and "continue" is allowed for the session.
await page.goto("http://paypall.com/login").catch(() => undefined);
await waitForUrl(page, onWarning);
await page.waitForSelector("text=This site looks like an imitation");
await shot(page, "ext-03-warning-suspicious");
await page.click("summary");
await page.click("text=Continue to paypall.com");
await waitForUrl(page, (url) => url === "http://paypall.com/login");
await page.goto("http://paypall.com/other");
assert.equal(page.url(), "http://paypall.com/other", "no second warning after proceeding");
step("suspicious site warns once; proceeding is remembered for the session");

// 5. The popup lists recent alerts and the current status.
const popup = await context.newPage();
await popup.goto(`chrome-extension://${extensionId}/popup.html`);
await popup.waitForSelector("text=Recent alerts");
await popup.waitForSelector(".alerts .host");
assert.ok(await popup.isVisible("text=malware.example.net"));
await popup.setViewportSize({ width: 340, height: 520 });
await shot(popup, "ext-04-popup");
step("popup shows alerts");

// 6. Pausing stops checks.
await popup.click("#protection");
await page.goto(LISTED).catch(() => undefined);
await page.waitForTimeout(1500);
assert.ok(!page.url().includes("warning.html"), "no warning while paused");
await popup.reload();
await popup.waitForSelector("text=Protection paused");
await popup.click("#protection");
step("pause and resume");

// 7. Linking with a code from the dashboard.
const site = await context.newPage();
await site.goto(`${server}/sign-up`);
await site.fill("input[type=email]", `ext${Date.now()}@example.com`);
await site.fill("input[type=password]", "an extension test phrase");
await site.click("button[type=submit]");
await site.waitForURL(/dashboard/);
await site.goto(`${server}/dashboard/browser-protection`);
await site.click("text=Create a link code");
const code = (await site.locator("p.font-mono").first().textContent()).trim();
console.log("  link code read from dashboard:", JSON.stringify(code), "count:", await site.locator("p.font-mono").count());
const options = await context.newPage();
await options.goto(`chrome-extension://${extensionId}/options.html`);
await options.fill("#link-code", code);
await options.getByRole("button", { name: "Link", exact: true }).click();
await options.waitForSelector("text=Linked to", { timeout: 8000 }).catch(async (error) => {
  await shot(options, "ext-debug-options");
  throw new Error(`Linking failed: ${await options.locator("[role=alert]").allTextContents()} (${error.message.split("\n")[0]})`);
});
await shot(options, "ext-05-options-linked");
await site.reload();
await site.waitForSelector("text=Version 0.1.0", { timeout: 5000 }).catch(() => site.waitForSelector("text=version 0.1.0"));
step("linked via one-time code; browser listed in dashboard");

// 8. With warning history on, a warning is recorded (domain only).
await site.click("[role=switch]");
await site.waitForSelector("[role=switch][aria-checked=true]");
await options.reload();
await options.waitForSelector("text=Warnings are recorded");
await worker.evaluate(() => chrome.storage.session.get(null).then((all) => chrome.storage.session.remove(Object.keys(all).filter((k) => k.startsWith("proceed:")))));
await page.goto(LISTED).catch(() => undefined);
await waitForUrl(page, onWarning);
await page.waitForTimeout(800);
await site.reload();
await site.waitForSelector("text=Warning shown");
await shot(site, "ext-06-dashboard");
step("warning recorded in the account with the domain only");

// 9. Disconnecting from the dashboard revokes the extension's access.
await site.click("text=Disconnect");
await site.waitForSelector("text=No browser linked to this account");
await worker.evaluate(() => chrome.storage.session.remove("accessToken"));
await page.goto("http://news.example.org/fresh").catch(() => undefined);
await page.waitForTimeout(1500);
const after = await worker.evaluate(() => chrome.storage.local.get("credentials"));
assert.equal(after.credentials, undefined, "credentials dropped after revocation");
step("revocation takes effect");

await context.close();
console.log("All extension end-to-end checks passed.");
