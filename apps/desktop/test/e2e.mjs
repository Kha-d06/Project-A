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

const server = createServer((request, response) => {
  if (request.url === "/api/v1/intelligence/hash-list") {
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
  env: { ...process.env, SENTINEL_DESKTOP_PROFILE: profile },
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

await page.click('[data-tab="settings"]');
await page.selectOption("#language", "ar");
await page.waitForSelector("text=الحماية");
assert.equal(await page.evaluate(() => document.documentElement.dir), "rtl");
await page.click('[data-tab="scan"]');
await shot(page, "desktop-arabic");
step("interface switches to Arabic, right to left");

await app.close();
server.close();
console.log("All desktop checks passed.");
