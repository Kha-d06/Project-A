/**
 * End-to-end check of the compiled EasyList / EasyPrivacy rulesets in Chromium:
 * Chrome accepts both, they're off by default, "Block ads and trackers" turns
 * them on, a request matching a compiled rule never reaches the server while an
 * ordinary one does, and the person's allow list exempts their site.
 *
 *   FILTER_LIST_DIR=... SENTINEL_TEST_BUILD=1 SENTINEL_SERVER=http://localhost:8787 npm run build
 *   node test/e2e-adblock.mjs
 */
import assert from "node:assert/strict";
import { readFile, mkdtemp } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startMockServer } from "./mock-server.mjs";

const { chromium } = createRequire(import.meta.url)("playwright");
const extensionPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "chrome");
const step = (text) => console.log(`✓ ${text}`);

// A whole-host EasyList rule with no other conditions; Chromium resolves every name to this test server.
const rules = JSON.parse(await readFile(join(extensionPath, "rules", "easylist.json"), "utf8"));
const generic = rules.find((r) => r.action.type === "block" && /^\|\|[a-z0-9.-]+\^$/.test(r.condition.urlFilter) && Object.keys(r.condition).length === 1);
assert.ok(generic, "a whole-host rule exists in the compiled list");
const blockedHost = generic.condition.urlFilter.slice(2, -1);

const seen = [];
const site = createServer((req, res) => {
  seen.push(`${req.headers.host?.split(":")[0]}${req.url}`);
  if (req.url === "/") {
    res.setHeader("Content-Type", "text/html");
    res.end(`<!doctype html><title>ads</title><script>
      const port = location.port;
      window.results = Promise.all([fetch(\`http://${blockedHost}:\${port}/ad.js\`, { mode: "no-cors" }).then(() => "loaded", () => "blocked"), fetch("/ordinary.js").then(() => "loaded", () => "blocked")]);
    </script>`);
  } else res.end("ok");
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const origin = `http://news.test:${site.address().port}`;

const { server } = await startMockServer(8787);
const context = await chromium.launchPersistentContext(await mkdtemp(join(tmpdir(), "qalaa-ads-")), {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`, "--host-resolver-rules=MAP * 127.0.0.1"],
});
let [worker] = context.serviceWorkers();
worker ??= await context.waitForEvent("serviceworker");
const extensionId = new URL(worker.url()).host;
const settings = async (changes) => {
  const options = await context.newPage();
  await options.goto(`chrome-extension://${extensionId}/options.html`);
  await options.evaluate((c) => chrome.runtime.sendMessage({ type: "settings", changes: c }), changes);
  await options.close();
};
const visit = async () => {
  const page = await context.newPage();
  await page.goto(`${origin}/`);
  const results = await page.evaluate(() => window.results);
  await page.close();
  return results;
};

try {
  assert.deepEqual(await worker.evaluate(() => chrome.declarativeNetRequest.getEnabledRulesets()), [], "off by default");
  assert.deepEqual(await visit(), ["loaded", "loaded"]);
  step("rulesets are off by default; nothing is blocked");

  await settings({ blockAds: true });
  const enabled = await worker.evaluate(() => chrome.declarativeNetRequest.getEnabledRulesets());
  assert.deepEqual([...enabled].sort(), ["easylist", "easyprivacy"]);
  seen.length = 0;
  assert.deepEqual(await visit(), ["blocked", "loaded"]);
  assert.ok(!seen.includes(`${blockedHost}/ad.js`) && seen.includes("news.test/ordinary.js"), "the blocked request never reached the server");
  step(`Chrome accepted both rulesets; a request to ${blockedHost} (rule ${generic.condition.urlFilter}) was blocked, an ordinary one loaded`);

  await settings({ allowlist: ["news.test"] });
  assert.deepEqual(await visit(), ["loaded", "loaded"]);
  step("a site on the allow list is left alone");

  await settings({ allowlist: [], blockAds: false });
  assert.deepEqual(await worker.evaluate(() => chrome.declarativeNetRequest.getEnabledRulesets()), []);
  step("turning it off disables the rulesets again");
} finally {
  await context.close();
  server.close();
  site.close();
}
