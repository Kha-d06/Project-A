/**
 * End-to-end test of the built desktop app in Electron, against a stand-in
 * SENTINEL server. Run under a display (xvfb-run on Linux CI):
 *   npm run build && xvfb-run -a node test/e2e.mjs [screenshot-dir]
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { _electron: electron } = require("playwright");
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const shots = process.argv[2];
const step = (text) => console.log(`✓ ${text}`);
const shot = async (page, name) => shots && page.screenshot({ path: join(shots, `${name}.png`) });

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const SAMPLE = Buffer.from("this stands in for a sample listed on MalwareBazaar");
const sampleHash = createHash("sha256").update(SAMPLE).digest("hex");

// Stand-in for the account side: queues a full scan and a quarantine once the
// person allows remote scans, and records what the app reports back.
const device = { linked: false, heartbeats: [], queued: [], results: {}, started: [] };
const readBody = (request) =>
  new Promise((resolve) => {
    let data = "";
    request.on("data", (chunk) => (data += chunk));
    request.on("end", () => resolve(data ? JSON.parse(data) : null));
  });
const json = (response, status, body) => {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
};

const server = createServer(async (request, response) => {
  const url = request.url ?? "";
  if (url.startsWith("/api/v1/devices/")) {
    const body = await readBody(request);
    if (url === "/api/v1/devices/register") {
      if (body.link_code !== "ABCD2345") return json(response, 400, { error: { message: "That code is not valid." } });
      device.linked = true;
      return json(response, 201, { device_id: "dev-1", token: "sdv_e2e", account_email: "owner@example.com" });
    }
    if (request.headers.authorization !== "Bearer sdv_e2e") return json(response, 401, { error: { message: "Unknown device" } });
    if (url === "/api/v1/devices/heartbeat") {
      device.heartbeats.push(body);
      if (body.allow_remote && !device.queuedOnce) {
        device.queuedOnce = true;
        device.queued.push({ id: "cmd-scan", kind: "full_scan", args: {} }, { id: "cmd-q", kind: "quarantine", args: { sha256: [sampleHash] } });
      }
      return json(response, 200, { pending_commands: device.queued.length });
    }
    if (url === "/api/v1/devices/commands") return json(response, 200, device.queued.splice(0));
    const started = url.match(/^\/api\/v1\/devices\/commands\/([\w-]+)\/started$/);
    if (started) {
      device.started.push(started[1]);
      return response.writeHead(204).end();
    }
    const result = url.match(/^\/api\/v1\/devices\/commands\/([\w-]+)\/result$/);
    if (result) {
      device.results[result[1]] = body;
      return response.writeHead(204).end();
    }
    if (url === "/api/v1/devices/self") {
      device.linked = false;
      return response.writeHead(204).end();
    }
  }
  if (url === "/api/v1/intelligence/hash-list") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ version: "1-test", generated_at: new Date().toISOString(), sources: ["MalwareBazaar (test)"], sha256: [sampleHash] }));
    return;
  }
  response.writeHead(404).end();
});
await new Promise((resolve) => server.listen(8799, "127.0.0.1", resolve));

const work = await mkdtemp(join(tmpdir(), "sentinel-desktop-e2e-"));
const profile = join(work, "profile");
const downloads = join(work, "Downloads");
const files = join(work, "files");
const documents = join(work, "Documents");
await Promise.all([mkdir(profile), mkdir(downloads), mkdir(files), mkdir(documents)]);
await writeFile(
  join(profile, "settings.json"),
  JSON.stringify({ serverUrl: "http://localhost:8799", watchFolders: [downloads], watchEnabled: true, autoQuarantine: true, useClamav: true, cloudLookup: false, language: "en", ransomwareWatch: true, protectedFolders: [documents] }),
);
await writeFile(join(files, "eicar.com"), EICAR);
await writeFile(join(files, "sample.bin"), SAMPLE);
await writeFile(join(files, "notes.txt"), "Shopping list: milk, bread, eggs");
await writeFile(join(files, "invoice.pdf"), Buffer.concat([Buffer.from("MZ"), Buffer.alloc(300)]));

const app = await electron.launch({
  executablePath: require("electron"),
  args: [join(root, "dist", "main.js"), "--no-sandbox"],
  env: { ...process.env, SENTINEL_DESKTOP_PROFILE: profile, SENTINEL_DESKTOP_HOME: files },
});
const page = await app.firstWindow();
await page.waitForSelector("nav button");

// Isolation: the page has no Node.js and only the bridge.
assert.equal(await page.evaluate(() => typeof require), "undefined");
assert.equal(await page.evaluate(() => typeof window.sentinel.scan), "function");
step("window is isolated: no Node.js in the page, only the SENTINEL bridge");

await page.click('[data-tab="protection"]');
await page.waitForSelector("text=1 known-malware fingerprints", { timeout: 15000 });
await shot(page, "desktop-protection");
step("fingerprint list downloaded from the server");

await page.click('[data-tab="scan"]');
const totals = await page.evaluate((dir) => window.sentinel.scan([dir]), files);
assert.deepEqual({ ...totals, current: undefined }, { scanned: 4, malicious: 2, suspicious: 1, current: undefined });
await page.waitForSelector('#results li[data-verdict="malicious"]');
const verdicts = await page.$$eval("#results > li", (items) => items.map((li) => `${li.querySelector(".name").textContent}:${li.dataset.verdict}`).sort());
assert.deepEqual(verdicts, ["eicar.com:malicious", "invoice.pdf:suspicious", "notes.txt:no_known_threat", "sample.bin:malicious"]);
await shot(page, "desktop-scan");
step("folder scan: EICAR and known sample malicious, disguised program suspicious, text file no known threat");

await page.locator("#results > li", { hasText: "invoice.pdf" }).locator("button.danger").click();
await page.waitForSelector("text=In quarantine");
await assert.rejects(stat(join(files, "invoice.pdf")));
step("manual quarantine removes the file from its folder");

await writeFile(join(downloads, "free-game.exe.crdownload"), "partial download");
await writeFile(join(downloads, "eicar-download.com"), EICAR);
for (let i = 0; i < 50 && (await readdir(downloads)).includes("eicar-download.com"); i++) await new Promise((r) => setTimeout(r, 200));
assert.deepEqual((await readdir(downloads)).sort(), ["free-game.exe.crdownload"]);
step("new download detected by the watcher and quarantined automatically; partial download ignored");

await page.click('[data-tab="quarantine"]');
await page.waitForSelector("#quarantine li");
assert.equal(await page.locator("#quarantine > li").count(), 2);
await shot(page, "desktop-quarantine");
await page.locator("#quarantine > li", { hasText: "invoice.pdf" }).locator("button.secondary").click();
for (let i = 0; i < 25; i++) {
  if (await stat(join(files, "invoice.pdf")).then(() => true, () => false)) break;
  await new Promise((r) => setTimeout(r, 200));
}
await stat(join(files, "invoice.pdf"));
step("restore puts the file back where it was");

// Ransomware watch: many files renamed with a ransomware extension raise an alert.
for (let i = 0; i < 9; i++) await writeFile(join(documents, `invoice-${i}.docx.lockbit`), Buffer.alloc(2048, i));
await page.waitForSelector("text=Possible ransomware activity", { timeout: 10000 });
await page.waitForSelector("#wifi-status");
await shot(page, "desktop-ransomware");
step("ransomware watch alerts on mass renames with a ransomware extension");

// Account link and a scan started from the website.
await page.click('[data-tab="settings"]');
await page.fill("#link-code", "WRONG123");
await page.click("#link-button");
await page.waitForSelector("text=That code is not valid.");
await page.fill("#link-code", "ABCD2345");
await page.click("#link-button");
await page.waitForSelector("#linked-as");
assert.ok(device.linked);
await page.waitForFunction(() => document.querySelector("#allow-remote") && !document.querySelector("#allow-remote").checked);
assert.ok(device.heartbeats.length >= 1 && device.heartbeats.every((beat) => beat.allow_remote === false));
assert.ok(!JSON.stringify(device.heartbeats).includes(work), "heartbeats must not contain folder paths");
step("linked to an account with a code; remote scans stay off until allowed; no paths sent");

await page.check("#allow-remote");
const deadline = Date.now() + 20000;
while (!device.results["cmd-q"] && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 200));
const scanReport = device.results["cmd-scan"];
assert.ok(scanReport?.ok, `full scan report: ${JSON.stringify(scanReport)}`);
assert.ok(scanReport.scanned >= 2);
assert.ok(scanReport.detections.some((d) => d.name === "sample.bin" && d.sha256 === sampleHash && d.verdict === "malicious"));
assert.ok(!JSON.stringify(scanReport).includes(work), "results must not contain paths");
assert.deepEqual(device.started, ["cmd-scan", "cmd-q"]);
assert.equal(device.results["cmd-q"].quarantined, 1);
await assert.rejects(stat(join(files, "sample.bin")));
await shot(page, "desktop-account");
step("scan started from the account ran here, reported detections, then quarantined the file it found");

page.once("dialog", (dialog) => dialog.accept());
await page.click("#unlink-button");
await page.waitForSelector("#link-code");
assert.equal(device.linked, false);
step("removing the computer from the account unlinks it on the server");

await page.selectOption("#language", "ar");
await page.waitForSelector("text=الحماية");
assert.equal(await page.evaluate(() => document.documentElement.dir), "rtl");
await page.click('[data-tab="scan"]');
await shot(page, "desktop-arabic");
step("interface switches to Arabic, right to left");

await app.close();
server.close();
console.log("All desktop checks passed.");
