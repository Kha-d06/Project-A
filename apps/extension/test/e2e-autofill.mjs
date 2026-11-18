/**
 * End-to-end test of password autofill: a real Chromium with the extension, the
 * Qalaa website and API, a vault created on the site, and a local login page.
 *   SENTINEL_TEST_BUILD=1 SENTINEL_SERVER=http://localhost:3000 node scripts/build.mjs
 *   node test/e2e-autofill.mjs [screenshot-dir]
 */
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const extensionPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "chrome");
const site = process.env.SENTINEL_SERVER ?? "http://localhost:3000";
const shots = process.argv[2];
const step = (text) => console.log(`✓ ${text}`);
const shot = async (page, name) => shots && page.screenshot({ path: join(shots, `${name}.png`), fullPage: true });

// A login page on this machine (http://localhost is allowed for filling; other http is not).
const loginPage = createServer((_, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end(`<title>Shop sign in</title><form><input type="hidden" name="csrf" value="t">
    <label>Email <input type="email" id="email" name="email"></label>
    <label>Password <input type="password" id="pw" name="password"></label>
    <input type="password" id="trap" style="display:none"><button>Sign in</button></form>`);
}).listen(8790);

const context = await chromium.launchPersistentContext(await mkdtemp(join(tmpdir(), "sentinel-autofill-")), {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
});
let [worker] = context.serviceWorkers();
worker ??= await context.waitForEvent("serviceworker");
const extensionId = new URL(worker.url()).host;
await context.route(/^http:\/\/news\.example\.org\//, (route) => route.fulfill({ contentType: "text/html", body: "<input type=password>" }));

// 1. An account with a vault holding a login for the local shop.
const page = await context.newPage();
await page.goto(`${site}/sign-up`);
await page.fill("input[type=email]", `autofill${Date.now()}@example.com`);
await page.fill("input[type=password]", "a-strong-password-123");
await page.click("button[type=submit]");
await page.waitForURL(/dashboard/);
const master = "orbit candle maple jungle";
await page.goto(`${site}/dashboard/passwords`);
await page.getByLabel("Master password", { exact: true }).fill(master);
await page.getByLabel("Type it again").fill(master);
await page.getByRole("checkbox").check();
await page.getByRole("button", { name: "Create vault" }).click();
await page.waitForSelector("text=Your vault is empty");
async function addLogin(title, url, user, password) {
  await page.getByRole("button", { name: "Add login" }).click();
  const dialog = page.locator("dialog[open]");
  await dialog.getByLabel("Name", { exact: true }).fill(title);
  await dialog.getByLabel("Website address").fill(url);
  await dialog.getByLabel("Username or email").fill(user);
  await dialog.getByLabel("Password", { exact: true }).fill(password);
  await dialog.getByRole("button", { name: "Save" }).click();
  await page.locator("#vault-items", { hasText: title }).waitFor();
}
await addLogin("Local shop", "http://localhost:8790", "sara@example.com", "Shop-Pass-2026!");
await addLogin("News", "http://news.example.org", "sara", "News-Pass-1");
step("vault created on the website with two logins");

// 2. Link the extension with a code from Devices → Add a device.
await page.goto(`${site}/dashboard/devices`);
await page.getByRole("button", { name: "Add a device" }).click();
const code = (await page.locator("#device-link-code").innerText()).trim();
const options = await context.newPage();
await options.goto(`chrome-extension://${extensionId}/options.html`);
const linked = await options.evaluate((c) => chrome.runtime.sendMessage({ type: "link", code: c }), code);
assert.equal(linked.ok, true, JSON.stringify(linked));
step("extension linked to the account");

// 3. Open the shop, then the popup for that tab.
const shop = await context.newPage();
await shop.goto("http://localhost:8790/login");
const [tab] = await options.evaluate(() => chrome.tabs.query({ url: "http://localhost:8790/*" }));
const popup = await context.newPage();
await popup.goto(`chrome-extension://${extensionId}/popup.html?tab=${tab.id}`);
await popup.waitForSelector("#vault-master");
await popup.fill("#vault-master", "wrong master password!");
await popup.click("#vault-unlock");
await popup.waitForSelector("text=does not open your vault");
await popup.fill("#vault-master", master);
await popup.click("#vault-unlock");
await popup.waitForSelector("#vault-logins >> text=Local shop");
assert.equal(await popup.locator("#vault-logins >> text=News").count(), 0, "only this site's logins are offered");
await shot(popup, "autofill-popup");
step("wrong master password refused; unlocked vault offers only this site's login");

await popup.click('[data-fill]');
await popup.waitForSelector("text=Filled.");
assert.equal(await shop.inputValue("#email"), "sara@example.com");
assert.equal(await shop.inputValue("#pw"), "Shop-Pass-2026!");
assert.equal(await shop.inputValue("#trap"), "", "hidden password field left empty");
await shot(shop, "autofill-filled");
step("Fill put the username and password into the visible fields only");

// 4. Refusals.
const news = await context.newPage();
await news.goto("http://news.example.org/login");
const [newsTab] = await options.evaluate(() => chrome.tabs.query({ url: "http://news.example.org/*" }));
const newsItems = await popup.evaluate((url) => chrome.runtime.sendMessage({ type: "vault-status", url }), "http://news.example.org/login");
assert.equal(newsItems.data.refusal, "not_https");
const plain = await popup.evaluate(({ id, url }) => chrome.runtime.sendMessage({ type: "vault-fill", tabId: id, url, itemId: "x" }), { id: newsTab.id, url: "http://news.example.org/login" });
assert.equal(plain.ok, false);
step("plain-http site refused");

const fromOtherPage = await options.evaluate(({ url }) => chrome.runtime.sendMessage({ type: "vault-secret", url, itemId: "any" }), { url: "http://localhost:8790/login" });
assert.equal(fromOtherPage.ok, false);
assert.match(fromOtherPage.error, /Not allowed/);
step("only the popup can read a password");

const locked = await popup.evaluate(() => chrome.runtime.sendMessage({ type: "vault-lock" }));
assert.equal(locked.ok, true);
const after = await popup.evaluate((url) => chrome.runtime.sendMessage({ type: "vault-status", url }), "http://localhost:8790/login");
assert.equal(after.data.unlocked, false);
step("lock forgets the decrypted vault");

await context.close();
loginPage.close();
console.log("Autofill end to end: all checks passed");
