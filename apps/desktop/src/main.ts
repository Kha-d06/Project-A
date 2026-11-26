/**
 * Qalaa Desktop main process.
 *
 * The window shows only the app's own local page, with context isolation, the
 * Chromium sandbox, no Node.js in the page, no navigation, no new windows and
 * no permission grants. The page talks to this process through a fixed set of
 * IPC calls (see preload.ts), and every argument is validated here.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, readdir, rm, stat, unlink, writeFile } from "node:fs/promises";
import { homedir, hostname, userInfo } from "node:os";
import { basename, join } from "node:path";

import { BrowserWindow, Menu, Notification, Tray, app, clipboard as electronClipboard, dialog, ipcMain, nativeImage, nativeTheme, safeStorage, session, shell } from "electron";

import { type LinkedAccount, loadAccount, register, saveAccount, unlinkSelf } from "./engine/account";
import { BackupError, MIN_PASSWORD_LENGTH, createBackup, pruneBackups, readBackup } from "./engine/backup";
import { findClam } from "./engine/clamav";
import { findSevenZip } from "./engine/formats";
import { type RansomwareAlert, RansomwareMonitor } from "./engine/ransomware";
import { isDue, nextSlot } from "./engine/schedule";
import { verifyDownloadedUpdate } from "./engine/release-verify";
import { type UpdateState, feedUrl, installKind, isNewer, versionFromManifest } from "./engine/updates";
import {
  type DeviceUse,
  type FirewallStatus,
  type ListeningPort,
  type StartupItem,
  cameraAndMicrophoneUse,
  firewallStatus,
  listeningPorts,
  newUses,
  startupItems,
} from "./engine/security";
import { pendingUpdates, wifiStatus } from "./engine/system";
import { diskEncryption } from "./engine/encryption";
import { type HistoryReport, checkHistory } from "./engine/history";
import { type ProcessConcern, concernsFor, groupByExecutable, listProcesses } from "./engine/processes";
import * as vpn from "./engine/vpn";
import * as monitor from "./engine/monitor";
import * as explorer from "./engine/explorer";
import { storage } from "./engine/storage";
import * as nettools from "./engine/nettools";
import { newRiskyFindings, scanNetwork } from "./engine/network/scan";
import { checkHttp, checkLineService } from "./engine/network/credentials";
import { type Inventory, annotate, loadInventory, reconcile, saveInventory, setTrusted } from "./engine/network/inventory";
import type { NetworkScan } from "./engine/network/types";
import * as fanotify from "./engine/fanotify";
import * as vpnGuard from "./engine/vpn-guard";
import { RansomwareBurst, underAny } from "./engine/behaviour";
import * as cfa from "./engine/cfa";
import * as privacyBlock from "./engine/privacy-block";
import * as utilities from "./engine/utilities";
import { posture } from "./engine/posture";
import { IntegrityMonitor } from "./engine/integrity";
import { Telemetry } from "./engine/telemetry";
import * as reports from "./engine/reports";
import { buildReport } from "./engine/report-data";
import { Quarantine } from "./engine/quarantine";
import { type Detection, type OfferedFolder, type ScanOutcome, RemoteAgent, quarantineCandidates } from "./engine/remote";
import { type ScanContext, scanFile } from "./engine/scanner";
import { fetchSignatures, lookupHash, uploadForFullScan } from "./engine/server";
import { type DesktopSettings, defaultSettings, loadSettings, sanitizeChanges, saveSettings } from "./engine/settings";
import { SignatureStore } from "./engine/signatures";
import type { ScanResult } from "./engine/types";
import { isDirectory, walk } from "./engine/walk";
import { type DecoyRecord, DropWatcher, RemovableWatcher, executableDropFolders, isExcluded, isSilent, looksRunnable, persistenceFolders, plantDecoys, removableMounts, silentUntilFrom, tamperedDecoys } from "./engine/protection";
import { parseDesktopEntry, parseLaunchPlist, startupWarnings } from "./engine/security";
import * as tools from "./engine/tools";
import * as mail from "./engine/mail";
import { type CoreHost, type Emit, createHandlers } from "./core/handlers";
import { ClipboardService, POLL_MS } from "./core/clipboard-service";
import { CredentialGuardService, pollMs as credentialPollMs } from "./core/credential-guard-service";
import { SafePayService } from "./core/safepay-service";
import { AliasService } from "./core/alias-service";
import { BrokerService } from "./core/broker-service";
import { parseSafePayLink } from "./engine/safepay";
import { KeyboardService } from "./core/keyboard-service";
import { ListenerService } from "./core/listener-service";
import { SafeDnsService } from "./core/safe-dns-service";
import { listKeyboards, pollMs } from "./engine/hid";
import { ipcPaths } from "./core/paths";
import { type IpcServer, startIpcServer } from "./core/server";
import { disableTerminal, enableTerminal, terminalStatus } from "./engine/shell-init";
import { FolderWatcher } from "./engine/watcher";

const SIGNATURE_REFRESH_MS = 6 * 60 * 60 * 1000;
const HISTORY_LIMIT = 300;

// Tests and portable setups can point the app at a separate profile folder.
if (process.env.SENTINEL_DESKTOP_PROFILE) app.setPath("userData", process.env.SENTINEL_DESKTOP_PROFILE);

const dataDir = () => app.getPath("userData");
let settings: DesktopSettings;
let signatures: SignatureStore;
let quarantine: Quarantine;
let clamBinary: string | null = null;
let sevenZip: string | null = null;
let window: BrowserWindow | null = null;
let tray: Tray | null = null;
let history: ScanResult[] = [];
let watcher: FolderWatcher;
let lastSignatureError: string | null = null;
let ransomware: RansomwareMonitor;
let lastRansomwareAlert: (RansomwareAlert & { at: string }) | null = null;
let account: LinkedAccount | null = null;
let remote: RemoteAgent;
let personalFolders: string[] = [];
const accountFile = () => join(dataDir(), "account.json");
const backupKeyFile = () => join(dataDir(), "backup-key.bin");
const mailFile = () => join(dataDir(), "mail.json");
const mailKeyFile = () => join(dataDir(), "mail-key.bin");
interface MailConfig {
  account: mail.MailAccount | null;
  watch: boolean;
  state: mail.MailState;
}
let mailConfig: MailConfig = { account: null, watch: false, state: { ...mail.EMPTY_STATE } };
/** Used only when the system keychain is unavailable; lost when the app quits. */
let sessionMailPassword: string | null = null;
let mailChecking = false;
let scanning = false;
let backingUp = false;
/** Used only when the system keychain is unavailable; lost when the app quits. */
let sessionBackupPassword: string | null = null;
let lastFirewall: FirewallStatus | null = null;
let lastPorts: ListeningPort[] | null = null;
let lastStartup: StartupItem[] = [];
let deviceUses: DeviceUse[] = [];
const deviceUseLog: { at: string; device: DeviceUse["device"]; app: string }[] = [];
let privacyTimer: NodeJS.Timeout | null = null;
let updateState: UpdateState = { state: "idle" };
/** The version whose download passed the signed-manifest check, if any. */
let verifiedUpdate: string | null = null;
const UPDATE_CHECK_MS = 6 * 60 * 60 * 1000;
// Executable scan results, reused while the file is unchanged (path → size+mtime).
const programCache = new Map<string, { stamp: string; verdict: ScanResult["verdict"]; title: string | null }>();
let lastHistoryReport: HistoryReport | null = null;
// System monitor: sampled only while its screen is open.
const MONITOR_MS = 2000;
const MONITOR_HISTORY = 90;
let monitorSampler: monitor.Sampler | null = null;
let monitorTimer: NodeJS.Timeout | null = null;
let monitorHistory: monitor.Snapshot[] = [];
let stopJournal: (() => void) | null = null;
let monitorTicks = 0;
let telemetry: Telemetry | null = null;
let integrity: IntegrityMonitor;
let lastPosture: Awaited<ReturnType<typeof posture>> | null = null;
let removable: RemovableWatcher | null = null;
let dropWatcher: DropWatcher | null = null;
let persistenceWatcher: DropWatcher | null = null;
let decoys: DecoyRecord = {};
let decoyKey = "";
let disabledStartup: tools.DisabledStartup[] = [];
/** Paths the person picked in a system dialog for shredding or firewall blocking, this session only. */
const pickedPaths = new Set<string>();
const decoyFile = () => join(dataDir(), "decoys.json");
const networkInventoryFile = () => join(dataDir(), "network-devices.json");
let lastNetworkScan: NetworkScan | null = null;
let networkScanning = false;
let onAccess: fanotify.OnAccessServer | null = null;
let ransomwareBurst: RansomwareBurst | null = null;
/** Processes frozen for ransomware behaviour, awaiting a resume/kill decision. */
const haltedPids = new Map<number, { reason: string; files: number; at: string }>();
const onAccessSocket = () => join(dataDir(), "onaccess.sock");
const onAccessHelper = () => join(__dirname, "onaccessd.py");
const disabledStartupFile = () => join(dataDir(), "startup-disabled.json");
const excluded = (path: string) => isExcluded(path, settings.exclusions);
const silent = () => isSilent(settings.silentUntil);

/** Writes to the local security event log (best effort). */
function logEvent(kind: string, level: "info" | "warning" | "alert", message: string) {
  try {
    telemetry?.log(kind, level, message);
  } catch {
    // the log must never break the action it records
  }
}

/** One reading a minute into the local history, independent of the Monitor screen. */
function startTelemetry() {
  const sampler = new monitor.Sampler();
  const tick = async () => {
    const s = await sampler.sample(false).catch(() => null);
    if (!s || !telemetry) return;
    try {
      telemetry.record({
        cpu: s.cpu.total,
        memory: s.memory.total ? (s.memory.used / s.memory.total) * 100 : 0,
        rx: s.network?.rxPerSec ?? 0,
        tx: s.network?.txPerSec ?? 0,
        read: s.disk?.readPerSec ?? 0,
        write: s.disk?.writePerSec ?? 0,
      });
    } catch {
      // disk full or database busy: skip this minute
    }
  };
  void tick();
  setInterval(() => void tick(), 60_000).unref();
  setInterval(() => telemetry?.prune(), 6 * 3600_000).unref();
}

async function postureCheck() {
  const [firewall, encryption, updates, ports, startup] = await Promise.all([
    firewallStatus(),
    diskEncryption(),
    pendingUpdates().catch(() => null),
    listeningPorts(),
    startupItems().catch(() => []),
  ]);
  lastPosture = await posture({
    firewall: firewall.state,
    encryption: encryption.state,
    pendingUpdates: updates ? updates.updates.length : null,
    riskyPorts: ports ? ports.filter((p) => p.exposed && p.risk).length : null,
    suspiciousStartup: startup.filter((item) => item.warnings.length).length,
  });
  logEvent("posture", lastPosture.score !== null && lastPosture.score < 60 ? "warning" : "info", `Security posture checked: ${lastPosture.score ?? "?"}/100`);
  return lastPosture;
}

/** Saves text, or a PDF printed from HTML, where the person chooses. */
async function saveExport(defaultName: string, format: "json" | "csv" | "html" | "pdf", content: string): Promise<string | null> {
  const filters = { json: [{ name: "JSON", extensions: ["json"] }], csv: [{ name: "CSV", extensions: ["csv"] }], html: [{ name: "Web page", extensions: ["html"] }], pdf: [{ name: "PDF", extensions: ["pdf"] }] }[format];
  const target = process.env.QALAA_EXPORT_DIR
    ? join(process.env.QALAA_EXPORT_DIR, `${defaultName}.${format}`)
    : (await dialog.showSaveDialog(window!, { defaultPath: `${defaultName}.${format}`, filters })).filePath;
  if (!target) return null;
  if (format === "pdf") {
    const printer = new BrowserWindow({ show: false, webPreferences: { javascript: false, sandbox: true } });
    try {
      await printer.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(content)}`);
      await writeFile(target, await printer.webContents.printToPDF({ printBackground: true, pageSize: "A4" }));
    } finally {
      printer.destroy();
    }
  } else {
    await writeFile(target, content, { mode: 0o600 });
  }
  return target;
}

function startMonitor() {
  if (monitorTimer) return monitorHistory;
  monitorSampler ??= new monitor.Sampler();
  const tick = async () => {
    // GPU tools are slower to ask; every other sample is enough.
    const snapshot = await monitorSampler!.sample(monitorTicks++ % 2 === 0).catch(() => null);
    if (!snapshot) return;
    if (!snapshot.gpus.length && monitorHistory.length) snapshot.gpus = monitorHistory[monitorHistory.length - 1]!.gpus;
    monitorHistory = [...monitorHistory, snapshot].slice(-MONITOR_HISTORY);
    send("monitor-sample", snapshot);
  };
  void tick();
  monitorTimer = setInterval(() => void tick(), MONITOR_MS);
  stopJournal = monitor.followJournal((event) => send("monitor-event", event));
  return monitorHistory;
}

function stopMonitor() {
  if (monitorTimer) clearInterval(monitorTimer);
  monitorTimer = null;
  stopJournal?.();
  stopJournal = null;
}
const vpnFile = () => join(dataDir(), `${vpn.CONNECTION_NAME}.conf`);

function send(channel: string, payload: unknown) {
  window?.webContents.send(channel, payload);
}

function context(): ScanContext {
  return {
    signatures,
    clamBinary: settings.useClamav ? clamBinary : null,
    sevenZip,
    cloudLookup: settings.cloudLookup ? (sha) => lookupHash(settings.serverUrl, sha) : undefined,
  };
}

async function persistHistory() {
  await writeFile(join(dataDir(), "history.json"), JSON.stringify(history.slice(0, HISTORY_LIMIT)));
}

async function record(result: ScanResult, automatic: boolean): Promise<ScanResult & { quarantined?: string }> {
  let quarantined: string | undefined;
  if (automatic && settings.autoQuarantine && result.verdict === "malicious") {
    try {
      const item = await quarantine.add(result.path, {
        sha256: result.sha256,
        verdict: result.verdict,
        reason: result.findings[0]?.title ?? "",
      });
      quarantined = item.id;
    } catch {
      // left in place; the interface still shows the detection
    }
  }
  history = [result, ...history].slice(0, HISTORY_LIMIT);
  void persistHistory();
  if (automatic && (result.verdict === "malicious" || result.verdict === "suspicious")) coreIpc?.broadcast(quarantined ? "threat.blocked" : "alert", { name: result.name });
  const entry = { ...result, quarantined };
  send("scan-result", entry);
  // Silent mode: still quarantined and listed, just no pop-up.
  if (automatic && !silent() && result.verdict !== "no_known_threat" && result.verdict !== "not_scanned" && Notification.isSupported()) {
    new Notification({
      title: result.verdict === "malicious" ? `Threat found: ${result.name}` : `Suspicious file: ${result.name}`,
      body: (quarantined ? "Moved to quarantine. " : "") + (result.findings[0]?.title ?? ""),
    }).show();
  }
  return entry;
}

async function scanLabelled(
  targets: { path: string; label: string | null }[],
  onProgress?: (progress: { scanned: number; found: number; folder: string | null }) => void,
): Promise<ScanOutcome> {
  const totals = { scanned: 0, malicious: 0, suspicious: 0, quarantined: 0 };
  const detections: Detection[] = [];
  const scanOne = async (path: string, label: string | null) => {
    if (excluded(path)) return;
    const result = await scanFile(path, context());
    await record(result, false);
    totals.scanned += 1;
    if (result.verdict === "malicious") totals.malicious += 1;
    if (result.verdict === "suspicious") totals.suspicious += 1;
    if (result.verdict === "malicious" || result.verdict === "suspicious") {
      detections.push({
        name: result.name,
        folder: label,
        verdict: result.verdict,
        title: result.findings[0]?.title ?? "",
        sha256: result.sha256,
        quarantined: false,
      });
    }
    send("scan-progress", { ...totals, current: path });
    onProgress?.({ scanned: totals.scanned, found: totals.malicious + totals.suspicious, folder: label });
  };
  for (const { path, label } of targets) {
    if (await isDirectory(path)) {
      for await (const file of walk(path, 50_000, excluded)) await scanOne(file, label);
    } else {
      await scanOne(path, label);
    }
  }
  return { ...totals, detections };
}

async function scanPaths(paths: string[]): Promise<{ scanned: number; malicious: number; suspicious: number }> {
  const { scanned, malicious, suspicious } = await scanLabelled(paths.map((path) => ({ path, label: null })));
  return { scanned, malicious, suspicious };
}

/** Runs one scan at a time; a scheduled scan waits for the next minute if another is running. */
async function exclusive<T>(work: () => Promise<T>): Promise<T> {
  scanning = true;
  try {
    return await work();
  } finally {
    scanning = false;
  }
}

function notify(title: string, body: string) {
  if (silent()) return;
  if (Notification.isSupported()) new Notification({ title, body }).show();
}

/** Start answering the on-access helper's verdict requests (Linux only). */
/** Every open is seen only while the fanotify helper is actually running and answering us. */
function syncCredentialMode() {
  if (!credentialService) return;
  if (!onAccess) return credentialService.configure({ everyOpen: false });
  void fanotify
    .onAccessStatus()
    .then((status) => credentialService?.configure({ everyOpen: onAccess !== null && status.state === "active" }))
    .catch(() => credentialService?.configure({ everyOpen: false }));
}

async function startOnAccessServer(): Promise<void> {
  if (onAccess || !fanotify.onAccessSupported()) return;
  // Behavioural ransomware blocking watches opens inside the protected folders.
  const roots = () => settings.protectedFolders;
  ransomwareBurst = new RansomwareBurst();
  onAccess = new fanotify.OnAccessServer({
    socketPath: onAccessSocket(),
    scan: (path) => scanFile(path, context()),
    isExcluded: (path) => excluded(path),
    onBlocked: (path, result) => {
      logEvent("on-access", "alert", `Blocked opening ${basename(path)}: ${result.findings[0]?.title ?? "known malware"}`);
      notify("Dangerous file blocked", `Qalaa stopped a program from opening ${basename(path)}.`);
      void record(result, true);
    },
    onOpen: (pid, path) => void credentialService?.observe(pid, path).catch(() => undefined),
    behaviour: {
      feed: (pid, path) => (underAny(path, roots()) ? ransomwareBurst!.feed({ pid, path, at: Date.now() }) : null),
    },
    onHalt: (pid, reason, files) => {
      haltedPids.set(pid, { reason, files, at: new Date().toISOString() });
      logEvent("ransomware", "alert", `Froze process ${pid}: ${reason}`);
      notify("Ransomware stopped", `Qalaa froze a program that was changing your files (${reason}). Open Qalaa to remove or release it.`);
      send("ransomware-halt", { pid, reason, files, at: new Date().toISOString() });
    },
  });
  await onAccess.start().catch((error) => {
    logEvent("on-access", "warning", `Could not start the on-access responder: ${String(error)}`);
    onAccess = null;
  });
  syncCredentialMode();
}

async function stopOnAccessServer(): Promise<void> {
  await onAccess?.stop().catch(() => {});
  onAccess = null;
  credentialService?.configure({ everyOpen: false });
}

/** Gather {path,size} for every file under a folder the person picks. */
async function gatherFiles(): Promise<{ root: string; files: utilities.FileEntry[] } | null> {
  const picked = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  if (picked.canceled || !picked.filePaths[0]) return null;
  const root = picked.filePaths[0];
  const files: utilities.FileEntry[] = [];
  for await (const path of walk(root, 200_000, (p) => excluded(p))) {
    try {
      files.push({ path, size: (await stat(path)).size });
    } catch {
      // skip unreadable files
    }
  }
  return { root, files };
}

async function scanSpace() {
  const gathered = await gatherFiles();
  if (!gathered) return null;
  return {
    root: gathered.root,
    largest: utilities.largestFiles(gathered.files, 50),
    folders: utilities.folderBreakdown(gathered.files, gathered.root),
  };
}

/** A sha256 of the first `bytes` of a file, or the whole file when bytes is 0. */
function hashFile(path: string, bytes: number): Promise<string | null> {
  return new Promise((resolve) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path, bytes > 0 ? { end: bytes - 1 } : {});
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", () => resolve(null));
  });
}

async function findDuplicateFiles() {
  const gathered = await gatherFiles();
  if (!gathered) return null;
  return { root: gathered.root, groups: await utilities.findDuplicates(gathered.files, hashFile) };
}

async function installedApps(): Promise<utilities.InstalledApp[]> {
  try {
    if (process.platform === "linux") {
      const out = await new Promise<string>((resolve) =>
        execFile("dpkg-query", ["-W", "-f=${Package}\\t${Version}\\n"], { timeout: 20_000, maxBuffer: 8 * 1024 * 1024 }, (_e, stdout) => resolve(String(stdout))),
      );
      return utilities.parseDpkg(out);
    }
    if (process.platform === "win32") {
      const out = await new Promise<string>((resolve) =>
        execFile("powershell.exe", ["-NoProfile", "-Command", "Get-Package | Select-Object Name,Version | ConvertTo-Json -Compress"], { timeout: 30_000, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (_e, stdout) => resolve(String(stdout))),
      );
      return utilities.parseWindowsPackages(out);
    }
    const out = await new Promise<string>((resolve) => execFile("ls", ["/Applications"], { timeout: 10_000 }, (_e, stdout) => resolve(String(stdout))));
    return utilities.parseMacApps(out);
  } catch {
    return [];
  }
}

/** Camera / microphone block state and controls. */
async function privacyBlockStatus() {
  const supported = privacyBlock.privacyBlockSupported();
  if (!supported) return { supported: false, camera: "unsupported" as const, microphone: "unsupported" as const };
  if (process.platform === "win32") {
    const read = (device: privacyBlock.Device) =>
      new Promise<privacyBlock.BlockState>((resolve) => {
        execFile("reg.exe", privacyBlock.windowsRegQueryArgs(device), { windowsHide: true, timeout: 10_000 }, (_e, out) => resolve(privacyBlock.parseWindowsConsent(String(out))));
      });
    return { supported: true, camera: await read("camera"), microphone: await read("microphone") };
  }
  return {
    supported: true,
    camera: await privacyBlock.linuxState(await privacyBlock.cameraNodes()),
    microphone: await privacyBlock.linuxState(await privacyBlock.micNodes()),
  };
}

async function setPrivacyBlock(device: privacyBlock.Device, block: boolean) {
  if (!privacyBlock.privacyBlockSupported()) return { error: "Blocking the camera and microphone isn't available on this system." };
  try {
    if (process.platform === "win32") {
      await new Promise<void>((resolve, reject) =>
        execFile("reg.exe", privacyBlock.windowsRegSetArgs(device, !block), { windowsHide: true, timeout: 10_000 }, (e) => (e ? reject(e) : resolve())),
      );
    } else {
      const nodes = device === "camera" ? await privacyBlock.cameraNodes() : await privacyBlock.micNodes();
      if (!nodes.length) return { error: "No camera or microphone device was found." };
      await pkexec(privacyBlock.linuxBlockScript(nodes, block));
    }
    logEvent("privacy", "info", `${device} ${block ? "blocked" : "allowed"}`);
    return await privacyBlockStatus();
  } catch (error) {
    return { error: String(error instanceof Error ? error.message : error) };
  }
}

/** Release (SIGCONT) or remove (SIGKILL) a process frozen for ransomware behaviour. */
async function resolveHaltedProcess(pid: number, action: "resume" | "kill") {
  if (!haltedPids.has(pid)) return { error: "That process is no longer frozen." };
  try {
    // The root helper froze it, so changing its state needs root too.
    await pkexec(`kill -${action === "kill" ? "KILL" : "CONT"} ${pid}`);
    haltedPids.delete(pid);
    ransomwareBurst?.clear(pid);
    logEvent("ransomware", "info", `${action === "kill" ? "Removed" : "Released"} frozen process ${pid}`);
    return { ok: true };
  } catch (error) {
    return { error: String(error instanceof Error ? error.message : error) };
  }
}

async function onAccessStatus() {
  const status = await fanotify.onAccessStatus();
  return { ...status, enabled: settings.onAccessScan };
}

async function setOnAccess(on: boolean) {
  if (!fanotify.onAccessSupported()) return { error: "On-access scanning is available on Linux only." };
  try {
    if (on) {
      await startOnAccessServer();
      await fanotify.enableOnAccess({ bundledHelper: onAccessHelper(), socketPath: onAccessSocket(), markRoots: [homedir()], user: userInfo().username });
    } else {
      await fanotify.disableOnAccess();
      await stopOnAccessServer();
    }
    settings = { ...settings, onAccessScan: on };
    await saveSettings(join(dataDir(), "settings.json"), settings);
    logEvent("on-access", "info", on ? "On-access scanning enabled" : "On-access scanning disabled");
    return await onAccessStatus();
  } catch (error) {
    return { error: String(error instanceof Error ? error.message : error) };
  }
}

/** Scan the home network, fold the result into the saved inventory, alert on new devices. */
async function runNetworkScan(): Promise<NetworkScan> {
  if (networkScanning && lastNetworkScan) return lastNetworkScan;
  networkScanning = true;
  try {
    const inventory: Inventory = await loadInventory(networkInventoryFile());
    // Test hook: scan an explicit host list instead of the live network.
    const forceHosts = process.env.QALAA_TEST_NETWORK_HOST?.split(",").map((h) => h.trim()).filter(Boolean);
    const scan = await scanNetwork({ forceHosts: forceHosts?.length ? forceHosts : undefined, onProgress: (done, total, phase) => send("network-progress", { done, total, phase }) });
    const { inventory: updated, newKeys } = reconcile(inventory, scan.devices);
    await saveInventory(networkInventoryFile(), updated);
    scan.devices = annotate(scan.devices, updated);
    scan.newDevices = newKeys;
    // New high/critical issues since the last scan, for the scheduled-watch alert.
    const freshRisky = newRiskyFindings(lastNetworkScan, scan);
    const hadPrevious = lastNetworkScan !== null;
    lastNetworkScan = scan;
    if (hadPrevious && freshRisky.length) notify("New risk on your network", freshRisky[0]!.title);
    logEvent("network-scan", scan.findings.some((f) => f.severity === "critical" || f.severity === "high") ? "alert" : "info", `${scan.devices.length} devices, ${scan.findings.length} findings on ${scan.cidr ?? "network"}`);
    // Only alert about genuinely new, untrusted devices — and never while the inventory was empty (first run).
    const freshDevices = newKeys.length && Object.keys(inventory).length > 0;
    if (freshDevices) notify("New device on your network", `${newKeys.length} device(s) joined ${scan.wifi?.ssid ?? "your network"}. Open Qalaa to review them.`);
    send("network-scanned", scan);
    return scan;
  } finally {
    networkScanning = false;
  }
}

/**
 * The opt-in, per-device default-password check. Requires explicit consent each
 * time. Tries HTTP admin first, then Telnet/FTP if those ports are open. Results
 * are returned, never stored.
 */
async function networkCredentialCheck(ip: string, consent: boolean) {
  if (!consent) return { refused: "Consent is required for the default-password check." };
  const device = lastNetworkScan?.devices.find((d) => d.ip === ip);
  if (!device) return { refused: "Run a network scan first, then check a device from the list." };
  const results = [];
  if (device.services.some((s) => s.port === 80 || s.port === 8080)) {
    results.push(await checkHttp(ip, device.services.some((s) => s.port === 80) ? 80 : 8080));
  }
  if (device.services.some((s) => s.port === 23 || s.port === 2323)) {
    results.push(await checkLineService(ip, device.services.some((s) => s.port === 23) ? 23 : 2323, "telnet"));
  }
  if (device.services.some((s) => s.port === 21)) {
    results.push(await checkLineService(ip, 21, "ftp"));
  }
  if (!results.length) return { refused: "This device has no login service (HTTP, Telnet or FTP) to check." };
  return { results };
}

async function loadJson<T>(file: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return fallback;
  }
}

async function saveJson(file: string, value: unknown) {
  await writeFile(file, JSON.stringify(value), { mode: 0o600 });
}

/** Plants (or removes) ransomware decoys to match the settings; only when something changed. */
async function applyDecoys(force = false) {
  const wanted = settings.ransomwareWatch && settings.ransomwareDecoys ? settings.protectedFolders : [];
  const key = JSON.stringify(wanted);
  if (!force && key === decoyKey) return;
  decoyKey = key;
  ransomware.setDecoys({});
  for (const path of Object.keys(decoys)) await unlink(path).catch(() => undefined);
  decoys = wanted.length ? await plantDecoys(wanted) : {};
  await saveJson(decoyFile(), decoys);
  // Events from writing the decoys arrive shortly; by then the new fingerprints are known.
  ransomware.setDecoys(decoys);
}

/** A program appeared in a temp or bin folder: scan it; a known threat is quarantined. */
async function onDroppedFile(path: string) {
  if (excluded(path) || !(await looksRunnable(path))) return;
  const result = await scanFile(path, context());
  if (result.verdict === "no_known_threat" || result.verdict === "not_scanned") return; // clean drops are not listed
  logEvent("system-watch", result.verdict === "malicious" ? "alert" : "warning", `${result.verdict}: ${path}`);
  await record(result, true);
}

/** Something registered itself to start automatically. */
async function onPersistenceFile(path: string) {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return; // removed
  }
  if (text.includes("Switched off by Qalaa Desktop") || /^Hidden=true$/m.test(text)) return; // Qalaa's own change
  const location = basename(join(path, ".."));
  let item: { name: string; command: string } | null = null;
  if (path.endsWith(".desktop")) item = parseDesktopEntry(text, path, location);
  else if (path.endsWith(".plist")) item = parseLaunchPlist(text, path, location);
  else if (/\.(service|timer)$/.test(path)) {
    const command = /^ExecStart=(.*)$/m.exec(text)?.[1];
    if (command) item = { name: basename(path), command };
  }
  if (!item) return;
  const warnings = startupWarnings(item.command);
  logEvent("startup", warnings.length ? "alert" : "warning", `New startup entry: ${item.name} (${item.command.slice(0, 200)})`);
  notify(warnings.length ? `Suspicious startup entry: ${item.name}` : `New startup entry: ${item.name}`, warnings.length ? `${warnings[0]}. Review it in Qalaa Desktop → Tools → Startup manager.` : `It will start with the computer: ${item.command.slice(0, 120)}`);
  send("startup-added", { name: item.name, command: item.command, warnings });
  void securityCheck().catch(() => undefined);
}

function applySystemWatch() {
  const on = settings.watchSystemChanges && process.platform !== "win32";
  dropWatcher?.set(on ? executableDropFolders() : []);
  persistenceWatcher?.set(on ? persistenceFolders() : []);
}

async function onRemovable(mount: string) {
  logEvent("removable", "info", `Drive connected: ${mount}`);
  send("removable-connected", mount);
  if (!settings.scanRemovable || excluded(mount)) return;
  notify("Drive connected", `Scanning ${mount} for threats.`);
  const outcome = await exclusive(() => scanLabelled([{ path: mount, label: basename(mount) || mount }]));
  const threats = outcome.malicious + outcome.suspicious;
  if (threats) logEvent("removable", "warning", `${threats} threat(s) on ${mount}`);
  notify(threats ? "Threats found on the drive" : "Drive checked", threats ? `${threats} file(s) on ${mount} need your attention.` : `${outcome.scanned} files checked. No known threats found.`);
  send("removable-scanned", { mount, outcome });
}

async function persistSettings() {
  await saveSettings(join(dataDir(), "settings.json"), settings);
}

// --- Security centre -------------------------------------------------------------

async function securityCheck() {
  const [firewall, ports, startup, use, encryption] = await Promise.all([firewallStatus(), listeningPorts(), startupItems(), cameraAndMicrophoneUse(), diskEncryption()]);
  lastFirewall = firewall;
  lastPorts = ports;
  lastStartup = startup;
  // The first check sets the baseline; later checks point out what is new since.
  const firstCheck = settings.knownStartup.length === 0;
  if (firstCheck) {
    settings = { ...settings, knownStartup: startup.map((item) => item.id).slice(0, 2000) };
    await persistSettings();
  }
  const known = new Set(settings.knownStartup);
  return {
    firewall,
    ports,
    startup: startup.map((item) => ({ ...item, isNew: !known.has(item.id) })),
    deviceUse: { ...use, log: deviceUseLog },
    encryption,
    checkedAt: new Date().toISOString(),
  };
}

/** Every running program's executable, scanned (cached while unchanged) and
 * checked for unusual locations. Read-only: nothing is stopped. */
async function processCheck() {
  const processes = await listProcesses();
  if (!processes) return { supported: false, checkedAt: new Date().toISOString(), programs: [], unreadable: 0 };
  const programs: { name: string; path: string; pids: number[]; concerns: ProcessConcern[]; verdict: ScanResult["verdict"] | null; title: string | null }[] = [];
  for (const group of groupByExecutable(processes)) {
    const concerns = concernsFor({ pid: group.pids[0]!, name: group.name, path: group.path, deleted: group.deleted });
    let verdict: ScanResult["verdict"] | null = null;
    let title: string | null = null;
    try {
      const info = await stat(group.path);
      const stamp = `${info.size}:${info.mtimeMs}`;
      const cached = programCache.get(group.path);
      if (cached && cached.stamp === stamp) {
        ({ verdict, title } = cached);
      } else {
        const result = await scanFile(group.path, context());
        verdict = result.verdict;
        title = result.findings[0]?.title ?? null;
        programCache.set(group.path, { stamp, verdict, title });
      }
    } catch {
      // Deleted or unreadable executable: the location rules still apply.
    }
    programs.push({ name: group.name, path: group.path, pids: group.pids.slice(0, 20), concerns, verdict, title });
  }
  const rank = (p: (typeof programs)[number]) => (p.verdict === "malicious" ? 0 : p.verdict === "suspicious" ? 1 : p.concerns.length ? 2 : 3);
  programs.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
  return { supported: true, checkedAt: new Date().toISOString(), programs, unreadable: processes.filter((p) => !p.path).length };
}

/** Downloads the threat list from the linked server and compares it with recent
 * browser history on this computer. No history is sent. */
async function historyCheck(days: number) {
  if (!account) throw new Error("Link this computer to your Qalaa account first (Settings), so it can download the list of dangerous sites.");
  const response = await fetch(`${account.server.replace(/\/$/, "")}/api/v1/devices/blocklist`, {
    headers: { Accept: "application/json", Authorization: `Bearer ${account.token}` },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`Could not download the list of dangerous sites (the server answered ${response.status}).`);
  const list = (await response.json()) as { hosts: string[]; urls?: string[] };
  lastHistoryReport = await checkHistory({ hosts: list.hosts ?? [], urls: list.urls ?? [] }, days);
  return lastHistoryReport;
}

/** Read the Endpoint host from the saved tunnel, for the kill switch. */
async function vpnEndpointHost(): Promise<string | null> {
  try {
    const text = await readFile(vpnFile(), "utf8");
    const host = /^Endpoint\s*=\s*([^\s:]+)/m.exec(text)?.[1];
    return host ?? null;
  } catch {
    return null;
  }
}

function vpnGuardView() {
  return {
    capable: vpnGuard.killSwitchCapable(),
    killSwitch: settings.vpnKillSwitch,
    allowLan: settings.vpnKillSwitchAllowLan,
    splitMode: settings.vpnSplitMode,
    splitCidrs: settings.vpnSplitCidrs,
    autoConnect: settings.vpnAutoConnect,
    trusted: settings.vpnTrustedNetworks,
  };
}

async function vpnStatus() {
  let saved = false;
  try {
    await stat(vpnFile());
    saved = true;
  } catch {
    saved = false;
  }
  return { linked: Boolean(account), saved, state: await vpn.tunnelState(), platform: process.platform, guard: vpnGuardView() };
}

async function vpnSetup() {
  if (!account) throw new Error("Link this computer to your Qalaa account first (Settings).");
  const keys = vpn.generateKeyPair();
  const config = await vpn.requestPeer(account, keys.publicKey);
  // Apply the chosen split-tunnel routing before the tunnel is saved and imported.
  const text = vpnGuard.applySplitTunnel(vpn.buildConfig(config, keys.privateKey), settings.vpnSplitMode, settings.vpnSplitCidrs);
  const file = await vpn.saveTunnel(dataDir(), text);
  if ((await vpn.tunnelState()) !== "unsupported") await vpn.importTunnel(file);
  // If split-tunnel settings changed while the kill switch is on, refresh its LAN rule too.
  if (settings.vpnKillSwitch) await applyKillSwitch().catch(() => {});
  return vpnStatus();
}

const pkexec = (script: string) =>
  new Promise<void>((resolve, reject) => {
    execFile("pkexec", ["sh", "-c", script], { timeout: 120_000 }, (error, _stdout, stderr) => (error ? reject(new Error(String(stderr || error.message).slice(0, 300))) : resolve()));
  });

async function applyKillSwitch(): Promise<void> {
  const host = (await vpnEndpointHost()) ?? "0.0.0.0";
  const rules = vpnGuard.killSwitchRules(vpn.CONNECTION_NAME, host, settings.vpnKillSwitchAllowLan);
  await pkexec(vpnGuard.killSwitchScript(rules));
}

async function setKillSwitch(on: boolean) {
  if (!vpnGuard.killSwitchCapable()) return { error: "The kill switch needs nftables and is available on Linux only." };
  try {
    if (on) await applyKillSwitch();
    else await pkexec(vpnGuard.removeKillSwitchScript());
    settings = { ...settings, vpnKillSwitch: on };
    await saveSettings(join(dataDir(), "settings.json"), settings);
    logEvent("vpn-killswitch", "info", on ? "VPN kill switch enabled" : "VPN kill switch disabled");
    return vpnGuardView();
  } catch (error) {
    return { error: String(error instanceof Error ? error.message : error) };
  }
}

/** Save split-tunnel / auto-connect settings; re-import the tunnel if routing changed. */
async function setVpnGuard(changes: Partial<ReturnType<typeof vpnGuardView>>) {
  const before = { mode: settings.vpnSplitMode, cidrs: settings.vpnSplitCidrs.join(",") };
  if (changes.splitMode === "full" || changes.splitMode === "exclude" || changes.splitMode === "only") settings = { ...settings, vpnSplitMode: changes.splitMode };
  if (Array.isArray(changes.splitCidrs)) settings = { ...settings, vpnSplitCidrs: changes.splitCidrs.filter((c): c is string => typeof c === "string").slice(0, 40) };
  if (typeof changes.allowLan === "boolean") settings = { ...settings, vpnKillSwitchAllowLan: changes.allowLan };
  if (typeof changes.autoConnect === "boolean") settings = { ...settings, vpnAutoConnect: changes.autoConnect };
  if (Array.isArray(changes.trusted)) settings = { ...settings, vpnTrustedNetworks: changes.trusted.filter((c): c is string => typeof c === "string").slice(0, 40) };
  await saveSettings(join(dataDir(), "settings.json"), settings);
  // If routing changed and a tunnel exists, rebuild it so the new AllowedIPs take effect.
  const routingChanged = before.mode !== settings.vpnSplitMode || before.cidrs !== settings.vpnSplitCidrs.join(",");
  if (routingChanged) {
    try {
      const text = await readFile(vpnFile(), "utf8");
      const next = vpnGuard.applySplitTunnel(text, settings.vpnSplitMode, settings.vpnSplitCidrs);
      await vpn.saveTunnel(dataDir(), next);
      if ((await vpn.tunnelState()) !== "unsupported") await vpn.importTunnel(vpnFile());
    } catch {
      // no tunnel saved yet; the new routing applies next time one is set up
    }
  }
  applyVpnAutoConnect();
  return vpnGuardView();
}

let vpnAutoTimer: NodeJS.Timeout | null = null;
let vpnAutoActed = false;

/** Poll the current Wi-Fi and bring the VPN up on untrusted networks. */
function applyVpnAutoConnect() {
  if (vpnAutoTimer) { clearInterval(vpnAutoTimer); vpnAutoTimer = null; }
  if (!settings.vpnAutoConnect || !vpnGuard.killSwitchCapable()) return;
  const tick = async () => {
    try {
      if ((await vpn.tunnelState()) === "unsupported") return;
      const wifi = await wifiStatus();
      const want = vpnGuard.shouldAutoConnect(wifi, { enabled: settings.vpnAutoConnect, trusted: settings.vpnTrustedNetworks });
      const state = await vpn.tunnelState();
      if (want && state === "disconnected" && !vpnAutoActed) {
        vpnAutoActed = true;
        await vpn.connectTunnel().catch(() => {});
        notify("VPN connected", `Qalaa turned on the VPN on ${wifi.ssid ?? "this network"} to protect your traffic.`);
      } else if (!want) {
        vpnAutoActed = false; // back on a trusted network; allow acting again later
      }
    } catch {
      // ignore a single poll failure
    }
  };
  vpnAutoTimer = setInterval(() => void tick(), 20_000);
  vpnAutoTimer.unref();
  void tick();
}

async function watchDeviceUse() {
  const { uses } = await cameraAndMicrophoneUse();
  const started = newUses(deviceUses, uses);
  deviceUses = uses;
  for (const use of started) {
    deviceUseLog.unshift({ at: new Date().toISOString(), device: use.device, app: use.app });
    notify(use.device === "camera" ? "Camera turned on" : "Microphone in use", `${use.app} is using your ${use.device}.`);
  }
  deviceUseLog.splice(50);
  if (started.length) send("device-use", { uses, log: deviceUseLog });
}

function applyPrivacyWatch() {
  if (privacyTimer) clearInterval(privacyTimer);
  privacyTimer = null;
  // macOS shows its own camera and microphone indicators and does not let other apps see who is recording.
  if (!settings.privacyWatch || process.platform === "darwin") return;
  void watchDeviceUse();
  privacyTimer = setInterval(() => void watchDeviceUse(), 5000);
  privacyTimer.unref();
}

// --- Mailbox scanning ------------------------------------------------------------

async function storedMailPassword(): Promise<string | null> {
  if (sessionMailPassword) return sessionMailPassword;
  try {
    if (!safeStorage.isEncryptionAvailable()) return null;
    return safeStorage.decryptString(await readFile(mailKeyFile()));
  } catch {
    return null;
  }
}

/** The interface language: the person's choice, or the system's. */
function uiLanguage(): "en" | "ar" {
  if (settings.language === "en" || settings.language === "ar") return settings.language;
  return app.getLocale().toLowerCase().startsWith("ar") ? "ar" : "en";
}

async function mailStatus() {
  return {
    account: mailConfig.account,
    watch: mailConfig.watch,
    checking: mailChecking,
    hasPassword: Boolean(await storedMailPassword()),
    keychain: safeStorage.isEncryptionAvailable(),
    lastCheck: mailConfig.state.lastCheck,
    lastError: mailConfig.state.lastError,
    results: mailConfig.state.results,
  };
}

async function checkMail(): Promise<Awaited<ReturnType<typeof mailStatus>>> {
  const password = await storedMailPassword();
  if (!mailConfig.account || !password || mailChecking) return mailStatus();
  mailChecking = true;
  try {
    const { state, added } = await mail.scanInbox(mailConfig.account, password, mailConfig.state, settings.serverUrl, { lang: uiLanguage() });
    mailConfig = { ...mailConfig, state };
    await saveJson(mailFile(), mailConfig);
    const worrying = mail.worrying(added);
    const first = worrying[0];
    if (first) {
      notify(
        worrying.length === 1 ? "An email shows warning signs" : `${worrying.length} emails show warning signs`,
        `${first.subject || "(no subject)"} · ${first.findings[0]?.title ?? first.summary}`,
      );
    }
  } finally {
    mailChecking = false;
  }
  return mailStatus();
}

async function connectMail(input: Record<string, unknown>, password: string) {
  try {
    const accountIn = mail.sanitizeAccount(input);
    if (!password) return { error: "Enter the password or app password." };
    if (safeStorage.isEncryptionAvailable()) {
      await writeFile(mailKeyFile(), safeStorage.encryptString(password), { mode: 0o600 });
      sessionMailPassword = null;
    } else {
      sessionMailPassword = password;
    }
    mailConfig = { account: accountIn, watch: mailConfig.watch, state: { ...mail.EMPTY_STATE } };
    await saveJson(mailFile(), mailConfig);
    return await checkMail();
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

async function disconnectMail() {
  sessionMailPassword = null;
  await rm(mailKeyFile(), { force: true });
  mailConfig = { account: null, watch: false, state: { ...mail.EMPTY_STATE } };
  await saveJson(mailFile(), mailConfig);
  return mailStatus();
}

// --- Backups ---------------------------------------------------------------------

async function storedBackupPassword(): Promise<string | null> {
  if (sessionBackupPassword) return sessionBackupPassword;
  try {
    if (!safeStorage.isEncryptionAvailable()) return null;
    return safeStorage.decryptString(await readFile(backupKeyFile()));
  } catch {
    return null;
  }
}

async function setBackupPassword(password: string | null): Promise<"keychain" | "session" | "cleared"> {
  if (password === null) {
    sessionBackupPassword = null;
    await rm(backupKeyFile(), { force: true });
    return "cleared";
  }
  if (password.length < MIN_PASSWORD_LENGTH) throw new BackupError(`Use a password of at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (safeStorage.isEncryptionAvailable()) {
    await writeFile(backupKeyFile(), safeStorage.encryptString(password), { mode: 0o600 });
    sessionBackupPassword = null;
    return "keychain";
  }
  sessionBackupPassword = password;
  return "session";
}

async function runBackup(passwordOverride?: string) {
  if (backingUp) throw new BackupError("A backup is already running.");
  if (!settings.backupDestination) throw new BackupError("Choose where to save backups first.");
  const password = passwordOverride ?? (await storedBackupPassword());
  if (!password) throw new BackupError("Set a backup password first.");
  backingUp = true;
  try {
    const summary = await createBackup(settings.backupFolders, settings.backupDestination, password, (progress) => send("backup-progress", progress));
    await pruneBackups(settings.backupDestination, settings.backupKeep);
    settings = { ...settings, lastBackup: { at: summary.created, file: summary.file, files: summary.files, bytes: summary.bytes }, lastBackupError: null };
    await persistSettings();
    return summary;
  } catch (error) {
    settings = { ...settings, lastBackupError: error instanceof Error ? error.message : String(error) };
    await persistSettings();
    throw error;
  } finally {
    backingUp = false;
    send("backup-progress", null);
  }
}

// --- Updates ---------------------------------------------------------------------

function setUpdateState(next: UpdateState) {
  updateState = next;
  send("update-state", next);
}

async function checkForUpdates(): Promise<UpdateState> {
  const kind = installKind(process.platform, process.env, app.isPackaged);
  if (kind === "development") {
    setUpdateState({ state: "manual", version: app.getVersion(), reason: "development" });
    return updateState;
  }
  setUpdateState({ state: "checking" });
  if (kind === "deb-rpm") {
    // Installed by the system package manager: only report that a newer version exists.
    try {
      const response = await fetch(`${feedUrl(settings.serverUrl)}/latest-linux.yml`, { signal: AbortSignal.timeout(15_000) });
      const version = response.ok ? versionFromManifest(await response.text()) : null;
      if (version && isNewer(version, app.getVersion())) setUpdateState({ state: "manual", version, reason: "package-manager" });
      else setUpdateState({ state: "none", checkedAt: new Date().toISOString() });
    } catch (error) {
      setUpdateState({ state: "error", message: error instanceof Error ? error.message : String(error) });
    }
    return updateState;
  }
  try {
    const { autoUpdater } = await import("electron-updater");
    autoUpdater.setFeedURL({ provider: "generic", url: feedUrl(settings.serverUrl) });
    autoUpdater.autoDownload = settings.autoUpdate;
    // Never install on quit: only an update that passed the signed-manifest check
    // (engine/release-verify.ts) may install, and only when the person chooses to.
    autoUpdater.autoInstallOnAppQuit = false;
    verifiedUpdate = null;
    autoUpdater.removeAllListeners();
    autoUpdater.on("update-available", (info) => setUpdateState({ state: "available", version: info.version }));
    autoUpdater.on("update-not-available", () => setUpdateState({ state: "none", checkedAt: new Date().toISOString() }));
    autoUpdater.on("download-progress", (p) => setUpdateState({ state: "downloading", percent: Math.round(p.percent) }));
    autoUpdater.on("update-downloaded", (info) => {
      void verifyDownloadedUpdate({ feed: feedUrl(settings.serverUrl), downloadedFile: info.downloadedFile, updateVersion: info.version, currentVersion: app.getVersion() }).then((check) => {
        if (check.ok) {
          verifiedUpdate = info.version;
          setUpdateState({ state: "ready", version: info.version });
        } else {
          // Not signed by a pinned release key: offer the download page instead.
          setUpdateState({ state: "manual", version: info.version, reason: check.reason === "no_keys" ? "unsigned-build" : "unverified" });
        }
      });
    });
    autoUpdater.on("error", (error) => setUpdateState({ state: "error", message: error.message.slice(0, 300) }));
    await autoUpdater.checkForUpdates();
  } catch (error) {
    setUpdateState({ state: "error", message: error instanceof Error ? error.message : String(error) });
  }
  return updateState;
}

// --- Schedules -------------------------------------------------------------------

async function checkSchedules() {
  const now = new Date();
  // The schedule starts counting from the first time the app runs, rather than scanning right after installation.
  if (settings.lastScheduledScan === null) {
    settings = { ...settings, lastScheduledScan: now.toISOString() };
    await persistSettings();
  }
  // Silent mode postpones scheduled work; it runs once silent mode ends.
  if (silent()) return;
  if (!scanning && isDue(settings.scanSchedule, settings.lastScheduledScan, now)) {
    // Recorded first, so a crash or quit mid-scan does not repeat it in a loop.
    settings = { ...settings, lastScheduledScan: now.toISOString() };
    await persistSettings();
    const targets = settings.scheduledScanKind === "full" ? [{ path: process.env.SENTINEL_DESKTOP_HOME ?? homedir(), label: "Home" }] : settings.watchFolders.map((path) => ({ path, label: basename(path) }));
    void exclusive(() => scanLabelled(targets)).then((outcome) => {
      const threats = outcome.malicious + outcome.suspicious;
      notify("Scheduled scan finished", threats ? `${threats} file(s) need your attention. Open Qalaa Desktop to review them.` : `${outcome.scanned} files checked. No known threats found.`);
      send("schedule-ran", { kind: "scan", outcome });
    });
  }
  if (!backingUp && settings.backupDestination && settings.backupFolders.length && isDue(settings.backupSchedule, settings.lastBackup?.at ?? null, now)) {
    void runBackup().then(
      (summary) => send("schedule-ran", { kind: "backup", summary }),
      (error: unknown) => notify("Backup did not finish", error instanceof Error ? error.message : String(error)),
    );
  }
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolve(hash.digest("hex")));
  });
}

/** Quarantine files from scan history by hash, checking that each file still has that hash. */
async function quarantineByHash(hashes: string[]): Promise<number> {
  const already = new Set((await quarantine.list()).map((item) => item.originalPath));
  let moved = 0;
  for (const entry of quarantineCandidates(history, hashes, already)) {
    try {
      if ((await sha256File(entry.path)) !== entry.sha256) continue;
      await quarantine.add(entry.path, { sha256: entry.sha256, verdict: entry.verdict, reason: entry.findings[0]?.title ?? "" });
      moved += 1;
    } catch {
      // gone or locked; nothing to move
    }
  }
  return moved;
}

function offeredFolders(): OfferedFolder[] {
  const folders: OfferedFolder[] = settings.watchFolders.map((path, index) => ({ id: `watch-${index}`, label: basename(path) || path, path }));
  const names = ["documents", "desktop", "pictures"] as const;
  personalFolders.forEach((path, index) => {
    if (!settings.watchFolders.includes(path)) folders.push({ id: names[index] ?? `folder-${index}`, label: basename(path) || path, path });
  });
  return folders;
}

function platformName(): "windows" | "macos" | "linux" {
  return process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : "linux";
}

async function updateSignatures(): Promise<void> {
  try {
    await signatures.save(await fetchSignatures(settings.serverUrl));
    lastSignatureError = null;
  } catch (error) {
    lastSignatureError = error instanceof Error ? error.message : String(error);
  }
  // The window may have read its status before the list arrived.
  send("signatures-updated", { count: signatures.size, error: lastSignatureError });
}

function onRansomware(alert: RansomwareAlert) {
  coreIpc?.broadcast("alert", { kind: "ransomware" });
  lastRansomwareAlert = { ...alert, at: new Date().toISOString() };
  send("ransomware-alert", lastRansomwareAlert);
  if (Notification.isSupported()) {
    new Notification({
      title: "Possible ransomware activity",
      body: `${alert.reasons[0]}. Disconnect this computer from the network and check your files.`,
      urgency: "critical",
    }).show();
  }
  window?.show();
}

function applyWatching() {
  watcher.set(settings.watchEnabled ? settings.watchFolders : []);
  ransomware.set(settings.ransomwareWatch ? settings.protectedFolders : []);
  if (decoyKey) void applyDecoys();
  applySystemWatch();
  tray?.setToolTip(settings.watchEnabled ? "Qalaa Desktop: watching for new files" : "Qalaa Desktop: watching paused");
}

async function status() {
  return {
    settings,
    signatures: { count: signatures.size, ...(signatures.meta ?? {}), error: lastSignatureError },
    clamav: { available: Boolean(clamBinary), path: clamBinary },
    watching: watcher.folders,
    ransomwareAlert: lastRansomwareAlert,
    quarantineCount: (await quarantine.list()).length,
    account: account ? { email: account.email, server: account.server } : null,
    remote: { lastContact: remote?.lastContact ?? null, lastError: remote?.lastError ?? null },
    schedule: { nextScan: nextSlot(settings.scanSchedule)?.toISOString() ?? null, nextBackup: nextSlot(settings.backupSchedule)?.toISOString() ?? null },
    backup: { running: backingUp, hasPassword: Boolean(await storedBackupPassword()), keychain: safeStorage.isEncryptionAvailable() },
    privacyWatchSupported: process.platform !== "darwin",
    update: updateState,
    silent: silent(),
    decoys: Object.keys(decoys).length,
    firewallBlock: tools.firewallBlockSupported(),
    installKind: installKind(process.platform, process.env, app.isPackaged),
    platform: process.platform,
    version: app.getVersion(),
    locale: app.getLocale(),
  };
}

// --- qalaa-ipc (native interface) --------------------------------------------------
// While the Electron shell runs it serves the same methods as the headless daemon,
// so the native command centre works with either.

let coreIpc: IpcServer | null = null;
const coreEmit: Emit = (event, payload) => coreIpc?.broadcast(event, payload);
let listenerService: ListenerService | null = null;
let keyboardService: KeyboardService | null = null;
let safeDnsService: SafeDnsService | null = null;
let clipboardService: ClipboardService | null = null;
let credentialService: CredentialGuardService | null = null;
let safePayService: SafePayService | null = null;
let brokerService: BrokerService | null = null;

/** Opens a qalaa://safepay link; false when it isn't one Qalaa accepts. */
function openSafePayLink(link: string): boolean {
  const url = parseSafePayLink(link);
  if (!url) return false;
  if (!safePayService) {
    pendingSafePayLink = link;
    return true;
  }
  void safePayService.launch({ url }).catch((error: unknown) => notify("SafePay couldn't start", error instanceof Error ? error.message : String(error)));
  return true;
}
let pendingSafePayLink: string | null = process.argv.find((a) => a.startsWith("qalaa://")) ?? null;

const electronHost: CoreHost = {
  version: app.getVersion(),
  async homeInput() {
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    return {
      now: new Date(),
      platform: process.platform,
      watchEnabled: settings.watchEnabled,
      onAccessScan: settings.onAccessScan,
      ransomwareWatch: settings.ransomwareWatch,
      networkWatch: settings.networkWatch,
      cloudLookup: settings.cloudLookup,
      signatures: { count: signatures.size, updatedAt: signatures.meta?.updatedAt ?? null, error: lastSignatureError },
      lastScanAt: history[0]?.scannedAt ?? null,
      lastNetworkScanAt: lastNetworkScan?.finishedAt ?? null,
      lastBackupAt: settings.lastBackup?.at ?? null,
      lastBackupError: settings.lastBackupError,
      backupConfigured: settings.backupFolders.length > 0 && Boolean(settings.backupDestination),
      quarantineCount: (await quarantine.list()).length,
      recentThreats: history.filter((r) => (r.verdict === "malicious" || r.verdict === "suspicious") && Date.parse(r.scannedAt) > weekAgo).length,
      ransomwareAlertAt: lastRansomwareAlert?.at ?? null,
      updateAvailable: updateState.state === "available" || updateState.state === "ready" ? updateState.version : null,
      silentUntil: settings.silentUntil,
      newListeners: listenerService?.newCount() ?? 0,
      newKeyboards: keyboardService?.newCount() ?? 0,
      safeDns: safeDnsService ? { on: safeDnsService.isOn(), available: safeDnsService.isSupported() } : undefined,
      clipboardGuard: { on: settings.clipboardGuard, available: true },
      brokersRecheckDue: brokerService?.recheckDueCount() ?? 0,
      credentialGuard: credentialService ? { on: settings.credentialGuard, available: credentialService.isSupported(), pending: credentialService.pendingCount() } : undefined,
    };
  },
  get listeners() {
    return listenerService ?? undefined;
  },
  get keyboards() {
    return keyboardService ?? undefined;
  },
  get safeDns() {
    return safeDnsService ?? undefined;
  },
  get clipboard() {
    return clipboardService ?? undefined;
  },
  get credentials() {
    return credentialService ?? undefined;
  },
  get safePay() {
    return safePayService ?? undefined;
  },
  get brokers() {
    return brokerService ?? undefined;
  },
  aliases: new AliasService(async () => account, async (text) => electronClipboard.writeText(text)),
  async updateToggles(changes) {
    const { onAccessScan, ...rest } = changes;
    settings = { ...settings, ...rest };
    await saveSettings(join(dataDir(), "settings.json"), settings);
    clipboardService?.configure({ enabled: settings.clipboardGuard });
    credentialService?.configure({ enabled: settings.credentialGuard });
    applyWatching();
    if (onAccessScan !== undefined) await setOnAccess(onAccessScan);
  },
  quickScan: () => exclusive(() => scanPaths(settings.watchFolders)),
  updateSignatures,
};

async function startCoreIpc() {
  listenerService = new ListenerService(join(dataDir(), "listeners.json"), process.platform, () => listeningPorts(), (event, payload) => {
    coreEmit(event, payload);
    const p = payload as { kind?: string; port?: number; process?: string | null };
    if (event === "alert" && p.kind === "listener") {
      notify("A program started accepting connections", `${p.process ?? "A program"} is listening on port ${p.port} and can be reached from other machines.`);
      logEvent("security", "warning", `New listener: ${p.process ?? "unknown"} on port ${p.port}`);
    }
  });
  await listenerService.load();
  keyboardService = new KeyboardService(join(dataDir(), "keyboards.json"), () => listKeyboards(), (event, payload) => {
    coreEmit(event, payload);
    const k = payload as { name?: string };
    notify("A new keyboard was connected", `${k.name ?? "A keyboard"}. If you didn't just plug in a keyboard, unplug it: some USB sticks pretend to be keyboards to type commands.`);
    logEvent("security", "warning", `New keyboard: ${k.name ?? "unknown"}`);
  });
  await keyboardService.load();
  safeDnsService = new SafeDnsService(join(dataDir(), "safe-dns.json"), () => settings.serverUrl, { platform: process.platform });
  await safeDnsService.load();
  void safeDnsService.resume();
  // The classic app reads the clipboard through Electron, so no extra tools are needed.
  clipboardService = new ClipboardService(
    {
      read: async () => electronClipboard.readText(),
      clear: async () => electronClipboard.clear(),
      write: async (text) => electronClipboard.writeText(text),
    },
    coreEmit,
  );
  clipboardService.configure({ enabled: settings.clipboardGuard, ttlSeconds: settings.clipboardTtl });
  setInterval(() => void clipboardService?.poll().catch(() => undefined), POLL_MS).unref();
  credentialService = new CredentialGuardService({
    file: join(dataDir(), "credential-guard.json"),
    home: app.getPath("home"),
    platform: process.platform,
    emit: (event, payload) => {
      coreEmit(event, payload);
      const c = payload as { kind?: string; program?: string; file?: string };
      if (event === "alert" && c.kind === "credential") {
        notify("A program opened your credentials", `${c.program ?? "A program"} opened ${c.file ?? "a credential file"}. If you don't recognise it, pause it from Qalaa.`);
        logEvent("security", "alert", `Credential read: ${c.program ?? "unknown"} opened ${c.file ?? "a credential file"}`);
      }
    },
  });
  await credentialService.load();
  credentialService.configure({ enabled: settings.credentialGuard });
  syncCredentialMode();
  if (credentialService.isSupported()) setInterval(() => void credentialService?.poll().catch(() => undefined), credentialPollMs(process.platform)).unref();
  safePayService = new SafePayService({ platform: process.platform, emit: coreEmit, safeDnsOn: () => safeDnsService?.isOn() ?? false });
  await safePayService.cleanup();
  brokerService = new BrokerService(join(dataDir(), "brokers.json"), undefined, undefined, async (text) => electronClipboard.writeText(text));
  await brokerService.load();
  if (pendingSafePayLink) {
    const link = pendingSafePayLink;
    pendingSafePayLink = null;
    openSafePayLink(link);
  }
  const handlers = createHandlers(electronHost, coreEmit);
  coreIpc = await startIpcServer(ipcPaths(process.platform, process.env, dataDir()), handlers, { version: app.getVersion() });
  const check = () => void listenerService?.check().catch(() => undefined);
  check();
  setInterval(check, 60_000).unref();
  const checkKeyboards = () => void keyboardService?.check().catch(() => undefined);
  checkKeyboards();
  setInterval(checkKeyboards, pollMs(process.platform)).unref();
}

function stringArray(value: unknown, max = 1000): string[] {
  if (!Array.isArray(value)) throw new Error("Expected a list of paths.");
  return value.filter((item): item is string => typeof item === "string" && item.length < 4096).slice(0, max);
}

function registerIpc() {
  ipcMain.handle("status", () => status());
  ipcMain.handle("history", () => history);
  ipcMain.handle("choose", async (_event, kind: unknown) => {
    const result = await dialog.showOpenDialog(window!, {
      properties: kind === "folder" ? ["openDirectory"] : ["openFile", "multiSelections"],
    });
    return result.canceled ? [] : result.filePaths;
  });
  ipcMain.handle("scan", (_event, paths: unknown) => exclusive(() => scanPaths(stringArray(paths))));
  ipcMain.handle("quick-scan", () => exclusive(() => scanPaths(settings.watchFolders)));
  ipcMain.handle("quarantine-list", () => quarantine.list());
  ipcMain.handle("quarantine-add", async (_event, path: unknown) => {
    if (typeof path !== "string") throw new Error("Expected a path.");
    const last = history.find((item) => item.path === path);
    const item = await quarantine.add(path, {
      sha256: last?.sha256 ?? null,
      verdict: last?.verdict ?? "suspicious",
      reason: last?.findings[0]?.title ?? "Quarantined by you",
    });
    return item;
  });
  ipcMain.handle("quarantine-restore", (_event, id: unknown) => quarantine.restore(String(id)));
  ipcMain.handle("quarantine-delete", (_event, id: unknown) => quarantine.remove(String(id)));
  ipcMain.handle("update-signatures", async () => {
    await updateSignatures();
    return status();
  });
  ipcMain.handle("full-scan", async (_event, path: unknown) => {
    if (typeof path !== "string") throw new Error("Expected a path.");
    const url = await uploadForFullScan(settings.serverUrl, path);
    await shell.openExternal(url);
    return url;
  });
  ipcMain.handle("settings", async (_event, changes: unknown) => {
    settings = { ...settings, ...sanitizeChanges(changes) };
    await saveSettings(join(dataDir(), "settings.json"), settings);
    nativeTheme.themeSource = settings.theme;
    applyWatching();
    applyPrivacyWatch();
    void remote.tick();
    return status();
  });
  ipcMain.handle("account-link", async (_event, code: unknown) => {
    if (typeof code !== "string" || !/^[A-Za-z0-9-]{4,32}$/.test(code.trim())) throw new Error("Enter the code shown on the website.");
    account = await register(settings.serverUrl, code, settings.deviceName, platformName(), app.getVersion());
    await saveAccount(accountFile(), account);
    remote.start();
    return status();
  });
  ipcMain.handle("account-unlink", async () => {
    if (account) await unlinkSelf(account);
    account = null;
    remote.stop();
    settings = { ...settings, allowRemote: false };
    await saveSettings(join(dataDir(), "settings.json"), settings);
    await saveAccount(accountFile(), null);
    // The VPN tunnel belongs to the account: forget it on this computer too.
    await vpn.forgetTunnel();
    await rm(vpnFile(), { force: true });
    return status();
  });
  ipcMain.handle("update-check", () => checkForUpdates());
  ipcMain.handle("update-install", async () => {
    if (updateState.state !== "ready" || verifiedUpdate !== updateState.version) return;
    const { autoUpdater } = await import("electron-updater");
    autoUpdater.quitAndInstall();
  });
  ipcMain.handle("security-check", () => securityCheck());

  // --- Protection settings that need a system dialog -------------------------------------
  ipcMain.handle("exclusion-add", async (_event, kind: unknown) => {
    const result = await dialog.showOpenDialog(window!, { properties: kind === "folder" ? ["openDirectory"] : ["openFile", "multiSelections"] });
    if (!result.canceled && result.filePaths.length) {
      settings = { ...settings, ...sanitizeChanges({ exclusions: [...settings.exclusions, ...result.filePaths] }) };
      await persistSettings();
      logEvent("settings", "info", `Excluded from scans: ${result.filePaths.join(", ")}`);
    }
    return status();
  });
  ipcMain.handle("silent", async (_event, hours: unknown) => {
    settings = { ...settings, silentUntil: silentUntilFrom(typeof hours === "number" ? hours : 0) };
    await persistSettings();
    return status();
  });

  // --- Tools ------------------------------------------------------------------------------
  // The person's real home: startup entries, browser profiles and caches live there.
  const homeDir = () => homedir();
  ipcMain.handle("startup-list", () => ({
    active: lastStartup.map((item) => ({ ...item, canSwitchOff: tools.canSwitchOff(item, process.platform, homeDir()) })),
    disabled: disabledStartup,
  }));
  ipcMain.handle("startup-off", async (_event, id: unknown) => {
    const item = lastStartup.find((entry) => entry.id === id);
    if (!item) throw new Error("That entry is no longer listed. Check again.");
    const entry = await tools.switchOffStartup(item, process.platform, homeDir());
    disabledStartup = [entry, ...disabledStartup.filter((d) => d.id !== entry.id)];
    await saveJson(disabledStartupFile(), disabledStartup);
    logEvent("startup", "info", `Switched off at startup: ${item.name}`);
    await securityCheck();
    return disabledStartup;
  });
  ipcMain.handle("startup-on", async (_event, id: unknown) => {
    const entry = disabledStartup.find((d) => d.id === id);
    if (!entry) throw new Error("Unknown entry.");
    await tools.switchOnStartup(entry);
    disabledStartup = disabledStartup.filter((d) => d.id !== id);
    await saveJson(disabledStartupFile(), disabledStartup);
    logEvent("startup", "info", `Switched back on at startup: ${entry.name}`);
    await securityCheck();
    return disabledStartup;
  });
  const junk = () => tools.junkCategories(process.platform, homeDir());
  ipcMain.handle("junk-measure", () => tools.measureJunk(junk()));
  ipcMain.handle("junk-clean", async (_event, ids: unknown) => {
    const chosen = stringArray(ids, 10);
    const result = await tools.cleanJunk(junk(), chosen);
    logEvent("cleanup", "info", `Removed ${result.files} junk files (${Math.round(result.bytes / 1e6)} MB)`);
    return result;
  });
  ipcMain.handle("pick-paths", async (_event, kind: unknown) => {
    const result = await dialog.showOpenDialog(window!, { properties: kind === "folder" ? ["openDirectory", "multiSelections"] : ["openFile", "multiSelections"] });
    for (const path of result.filePaths) pickedPaths.add(path);
    return result.canceled ? [] : result.filePaths.map((path) => ({ path, refusal: tools.shredRefusal(path, tools.shredGuard(process.platform, homeDir(), [dataDir()])) }));
  });
  ipcMain.handle("shred", async (_event, paths: unknown, passes: unknown) => {
    const totals = { files: 0, bytes: 0, refused: [] as string[] };
    for (const path of stringArray(paths, 100)) {
      // Only what was picked in the system dialog, and never system folders or Qalaa's data.
      if (!pickedPaths.has(path) || tools.shredRefusal(path, tools.shredGuard(process.platform, homeDir(), [dataDir()]))) {
        totals.refused.push(path);
        continue;
      }
      const done = await tools.shred(path, typeof passes === "number" ? passes : 1);
      pickedPaths.delete(path);
      totals.files += done.files;
      totals.bytes += done.bytes;
    }
    logEvent("shredder", "info", `Shredded ${totals.files} file(s)`);
    return totals;
  });
  ipcMain.handle("extensions", () => tools.browserExtensions(process.platform, homeDir()));

  // Terminal protection (Linux and macOS): the qalaa command and the bash/zsh hooks.
  ipcMain.handle("terminal-status", () => (process.platform === "win32" ? null : terminalStatus()));
  ipcMain.handle("terminal-set", async (_event, on: unknown) => {
    if (process.platform === "win32") throw new Error("Terminal protection is for Linux and macOS.");
    let result;
    if (on === true) {
      // AppImage: its inner path changes on every start, so the launcher calls the AppImage itself.
      const appImage = process.env.APPIMAGE;
      const runtime = appImage ?? process.execPath;
      // cli.js is bundled next to main.js; packaged, it is kept outside the asar archive.
      const script = appImage ? null : app.isPackaged ? join(process.resourcesPath, "app.asar.unpacked", "dist", "cli.js") : join(__dirname, "cli.js");
      result = await enableTerminal(runtime, script, undefined, undefined, dataDir());
    } else {
      result = await disableTerminal();
    }
    // Qalaa's own edit to ~/.bashrc / ~/.zshrc is expected: do not raise a file-integrity alarm for it.
    for (const file of result.changed) if (integrity.state.paths.includes(file)) await integrity.accept(file).catch(() => undefined);
    logEvent("terminal", "info", `Terminal protection ${on === true ? "on" : "off"}${result.changed.length ? ` (${result.changed.join(", ")})` : ""}`);
    return result.setup;
  });
  ipcMain.handle("deep-check", async () => {
    const result = await tools.deepCheck(process.platform, homeDir());
    for (const finding of result.findings) logEvent("deep-check", finding.severity === "high" ? "alert" : "warning", `${finding.area}: ${finding.item}`);
    return { ...result, checkedAt: new Date().toISOString() };
  });
  ipcMain.handle("firewall-blocked", () => tools.blockedPrograms());
  ipcMain.handle("firewall-block", async (_event, path: unknown) => {
    if (typeof path !== "string") throw new Error("Expected a program path.");
    // A program from the process explorer (its path is known) or one picked in a dialog.
    const known = pickedPaths.has(path) || ((await explorer.processDetails()) ?? []).some((p) => p.path === path);
    if (!known) throw new Error("Choose the program first.");
    await tools.blockProgram(path);
    logEvent("firewall", "info", `Blocked network access: ${path}`);
    return tools.blockedPrograms();
  });
  ipcMain.handle("firewall-unblock", async (_event, path: unknown) => {
    if (typeof path !== "string") throw new Error("Expected a program path.");
    await tools.unblockProgram(path);
    logEvent("firewall", "info", `Unblocked network access: ${path}`);
    return tools.blockedPrograms();
  });
  ipcMain.handle("process-check", () => processCheck());
  ipcMain.handle("history-check", (_event, days: unknown) => historyCheck(Math.min(90, Math.max(1, Number(days) || 30))));
  ipcMain.handle("history-last", () => lastHistoryReport);
  // Process explorer
  ipcMain.handle("explorer-list", () => explorer.processDetails());
  ipcMain.handle("explorer-inspect", async (_event, path: unknown) => {
    const file = String(path);
    const [sha256, sig] = await Promise.all([explorer.sha256File(file).catch(() => null), explorer.signature(file)]);
    return { sha256, signature: sig };
  });
  ipcMain.handle("explorer-control", async (_event, pid: unknown, action: unknown, name: unknown) => {
    if (action !== "end" && action !== "suspend" && action !== "resume") throw new Error("Unknown action.");
    await explorer.controlProcess(Number(pid), action);
    logEvent("process", "warning", `${action === "end" ? "Ended" : action === "suspend" ? "Suspended" : "Resumed"} ${String(name).slice(0, 80)} (PID ${Number(pid)})`);
    return true;
  });
  ipcMain.handle("reveal-path", (_event, path: unknown) => shell.showItemInFolder(String(path)));
  // Storage and network tools
  ipcMain.handle("storage", () => storage());
  ipcMain.handle("net-lookup", (_event, query: unknown) => nettools.lookup(String(query).slice(0, 300)));
  ipcMain.handle("net-interfaces", () => nettools.interfaces());
  ipcMain.handle("network-status", () => lastNetworkScan);
  ipcMain.handle("network-scan", () => runNetworkScan());
  ipcMain.handle("network-trust", async (_event, key: unknown, trusted: unknown) => {
    const inventory = await loadInventory(networkInventoryFile());
    const next = setTrusted(inventory, String(key), Boolean(trusted));
    await saveInventory(networkInventoryFile(), next);
    if (lastNetworkScan) lastNetworkScan = { ...lastNetworkScan, devices: annotate(lastNetworkScan.devices, next) };
    return lastNetworkScan;
  });
  ipcMain.handle("network-credential-check", (_event, ip: unknown, consent: unknown) => networkCredentialCheck(String(ip), Boolean(consent)));
  ipcMain.handle("onaccess-status", () => onAccessStatus());
  ipcMain.handle("onaccess-set", (_event, on: unknown) => setOnAccess(Boolean(on)));
  ipcMain.handle("utilities-space", () => scanSpace());
  ipcMain.handle("utilities-duplicates", () => findDuplicateFiles());
  ipcMain.handle("utilities-apps", () => installedApps());
  ipcMain.handle("privacy-block-status", () => privacyBlockStatus());
  ipcMain.handle("mail-status", () => mailStatus());
  ipcMain.handle("mail-connect", (_event, input: unknown, password: unknown) =>
    connectMail(input && typeof input === "object" ? (input as Record<string, unknown>) : {}, typeof password === "string" ? password : ""),
  );
  ipcMain.handle("mail-disconnect", () => disconnectMail());
  ipcMain.handle("mail-check", () => checkMail());
  ipcMain.handle("mail-watch", async (_event, watch: unknown) => {
    mailConfig = { ...mailConfig, watch: Boolean(watch) };
    await saveJson(mailFile(), mailConfig);
    return mailStatus();
  });
  ipcMain.handle("privacy-block-set", (_event, device: unknown, block: unknown) => setPrivacyBlock(device === "microphone" ? "microphone" : "camera", Boolean(block)));
  ipcMain.handle("cfa-status", () => cfa.cfaStatus());
  ipcMain.handle("cfa-apply", async (_event, action: unknown, path: unknown) => {
    try {
      await cfa.cfaApply(action as Parameters<typeof cfa.cfaApplyScript>[0], typeof path === "string" ? path : undefined);
      logEvent("cfa", "info", `Controlled folder access: ${String(action)}`);
      return await cfa.cfaStatus();
    } catch (error) {
      return { error: String(error instanceof Error ? error.message : error) };
    }
  });
  ipcMain.handle("cfa-pick-folder", async () => {
    const result = await dialog.showOpenDialog({ properties: ["openDirectory"] });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  });
  ipcMain.handle("ransomware-halted", () => [...haltedPids.entries()].map(([pid, info]) => ({ pid, ...info })));
  ipcMain.handle("ransomware-resolve", (_event, pid: unknown, action: unknown) => resolveHaltedProcess(Number(pid), action === "kill" ? "kill" : "resume"));
  // Posture, integrity, history, reports
  ipcMain.handle("posture", () => postureCheck());
  ipcMain.handle("integrity-state", () => integrity.state);
  ipcMain.handle("integrity-check", async () => {
    await integrity.check();
    return integrity.state;
  });
  ipcMain.handle("integrity-accept", async (_event, path: unknown) => {
    logEvent("integrity", "info", `Change accepted: ${String(path)}`);
    return integrity.accept(String(path));
  });
  ipcMain.handle("integrity-remove", (_event, path: unknown) => integrity.setPaths(integrity.state.paths.filter((p) => p !== String(path))));
  ipcMain.handle("integrity-add", async () => {
    const result = await dialog.showOpenDialog(window!, { properties: ["openFile", "multiSelections", "showHiddenFiles"] });
    if (result.canceled) return integrity.state;
    return integrity.setPaths([...integrity.state.paths, ...result.filePaths]);
  });
  ipcMain.handle("integrity-reset", () => integrity.rebaseline());
  ipcMain.handle("telemetry-history", (_event, hours: unknown) => telemetry?.history(Math.min(168, Math.max(1, Number(hours) || 24))) ?? []);
  ipcMain.handle("security-log", () => telemetry?.events(300) ?? []);
  ipcMain.handle("report", async (_event, kind: unknown, format: unknown) => {
    if (kind !== "inventory" && kind !== "security" && kind !== "performance") throw new Error("Unknown report.");
    if (format !== "json" && format !== "csv" && format !== "html" && format !== "pdf") throw new Error("Unknown format.");
    const report = await buildReport(kind, {
      posture: lastPosture ?? (await postureCheck()),
      integrity: integrity.state,
      security: await securityCheck(),
      sampler: monitorSampler ?? new monitor.Sampler(),
      history: telemetry?.history(24) ?? [],
      events: telemetry?.events(100) ?? [],
    });
    const content = reports.render(report, format === "pdf" ? "html" : format);
    const saved = await saveExport(`qalaa-${kind}-${new Date().toISOString().slice(0, 10)}`, format, content);
    if (saved) logEvent("report", "info", `${report.title} saved as ${format.toUpperCase()}`);
    return saved;
  });
  ipcMain.handle("monitor-start", () => startMonitor());
  ipcMain.handle("monitor-stop", () => stopMonitor());
  ipcMain.handle("monitor-connections", () => monitor.connections());
  ipcMain.handle("monitor-services", () => monitor.services());
  ipcMain.handle("monitor-events", (_event, minutes: unknown) => monitor.recentEvents(Math.min(24 * 60, Math.max(5, Number(minutes) || 60))));
  ipcMain.handle("monitor-service-details", (_event, name: unknown) => monitor.serviceDetails(String(name)));
  ipcMain.handle("monitor-service-startup", async (_event, name: unknown, enabled: unknown) => {
    await monitor.setServiceStartup(String(name), Boolean(enabled));
    logEvent("service", "warning", `${Boolean(enabled) ? "Enabled" : "Disabled"} service ${String(name)}`);
    return monitor.services();
  });
  ipcMain.handle("monitor-security-events", (_event, minutes: unknown) => monitor.securityEvents(Math.min(7 * 24 * 60, Math.max(5, Number(minutes) || 24 * 60))));
  ipcMain.handle("monitor-events-export", async (_event, events: unknown, format: unknown) => {
    if (format !== "csv" && format !== "json" || !Array.isArray(events)) throw new Error("Unknown format.");
    return saveExport(`qalaa-events-${new Date().toISOString().slice(0, 10)}`, format, monitor.exportEvents((events as monitor.LogEvent[]).slice(0, 10_000), format));
  });
  ipcMain.handle("monitor-service-control", async (_event, name: unknown, action: unknown) => {
    if (action !== "start" && action !== "stop" && action !== "restart") throw new Error("Unknown action.");
    await monitor.controlService(String(name), action);
    return monitor.services();
  });
  ipcMain.handle("vpn-status", () => vpnStatus());
  ipcMain.handle("vpn-setup", () => vpnSetup());
  ipcMain.handle("vpn-connect", async () => {
    await vpn.connectTunnel();
    return vpnStatus();
  });
  ipcMain.handle("vpn-disconnect", async () => {
    await vpn.disconnectTunnel();
    return vpnStatus();
  });
  ipcMain.handle("vpn-show-file", () => shell.showItemInFolder(vpnFile()));
  ipcMain.handle("vpn-guard", () => vpnGuardView());
  ipcMain.handle("vpn-guard-set", (_event, changes: unknown) => setVpnGuard((changes ?? {}) as Partial<ReturnType<typeof vpnGuardView>>));
  ipcMain.handle("vpn-killswitch-set", (_event, on: unknown) => setKillSwitch(Boolean(on)));
  ipcMain.handle("startup-acknowledge", async () => {
    settings = { ...settings, knownStartup: lastStartup.map((item) => item.id).slice(0, 2000) };
    await persistSettings();
    return securityCheck();
  });
  ipcMain.handle("scan-program", async (_event, id: unknown) => {
    // Only programs from the startup list just shown can be scanned this way.
    const item = lastStartup.find((entry) => entry.id === id);
    if (!item?.program) throw new Error("That program could not be found.");
    return exclusive(() => scanPaths([item.program!]));
  });
  ipcMain.handle("backup-add-folder", async () => {
    const result = await dialog.showOpenDialog(window!, { properties: ["openDirectory"] });
    if (!result.canceled && result.filePaths[0]) {
      settings = { ...settings, backupFolders: [...new Set([...settings.backupFolders, result.filePaths[0]])].slice(0, 20) };
      await persistSettings();
    }
    return status();
  });
  ipcMain.handle("backup-remove-folder", async (_event, path: unknown) => {
    settings = { ...settings, backupFolders: settings.backupFolders.filter((folder) => folder !== path) };
    await persistSettings();
    return status();
  });
  ipcMain.handle("backup-destination", async () => {
    const result = await dialog.showOpenDialog(window!, { properties: ["openDirectory", "createDirectory"] });
    if (!result.canceled && result.filePaths[0]) {
      settings = { ...settings, backupDestination: result.filePaths[0] };
      await persistSettings();
    }
    return status();
  });
  ipcMain.handle("backup-password", async (_event, password: unknown) => {
    if (password !== null && typeof password !== "string") throw new Error("Expected a password.");
    return setBackupPassword(password);
  });
  ipcMain.handle("backup-run", () => runBackup());
  ipcMain.handle("backup-open", async (_event, mode: unknown, password: unknown) => {
    if (typeof password !== "string") throw new Error("Enter the backup's password.");
    const picked = await dialog.showOpenDialog(window!, { properties: ["openFile"], filters: [{ name: "Qalaa backup", extensions: ["sbk"] }] });
    if (picked.canceled || !picked.filePaths[0]) return null;
    let target: string | null = null;
    if (mode === "restore") {
      const into = await dialog.showOpenDialog(window!, { title: "Choose an empty folder to restore into", properties: ["openDirectory", "createDirectory"] });
      if (into.canceled || !into.filePaths[0]) return null;
      target = into.filePaths[0];
    }
    const result = await readBackup(picked.filePaths[0], password, target, (progress) => send("backup-progress", progress));
    send("backup-progress", null);
    if (target) void shell.openPath(target);
    return { ...result, file: basename(picked.filePaths[0]), restoredTo: target };
  });
  ipcMain.handle("wifi", () => wifiStatus());
  ipcMain.handle("updates", () => pendingUpdates());
  ipcMain.handle("add-protected-folder", async () => {
    const result = await dialog.showOpenDialog(window!, { properties: ["openDirectory"] });
    if (!result.canceled && result.filePaths[0]) {
      settings = { ...settings, protectedFolders: [...new Set([...settings.protectedFolders, result.filePaths[0]])] };
      await saveSettings(join(dataDir(), "settings.json"), settings);
      applyWatching();
    }
    return status();
  });
  ipcMain.handle("add-watch-folder", async () => {
    const result = await dialog.showOpenDialog(window!, { properties: ["openDirectory"] });
    if (!result.canceled && result.filePaths[0]) {
      settings = { ...settings, watchFolders: [...new Set([...settings.watchFolders, result.filePaths[0]])] };
      await saveSettings(join(dataDir(), "settings.json"), settings);
      applyWatching();
    }
    return status();
  });
}

function createWindow() {
  window = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 760,
    minHeight: 560,
    title: "Qalaa Desktop",
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#070b16" : "#f7f4ee",
    show: false,
    webPreferences: {
      preload: join(__dirname, "preload.js"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
    },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  window.once("ready-to-show", () => window?.show());
  window.on("closed", () => (window = null));
  void window.loadFile(join(__dirname, "renderer", "index.html"));
}

function createTray() {
  try {
    tray = new Tray(nativeImage.createFromPath(join(__dirname, "renderer", "icon.png")));
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: "Open Qalaa Desktop", click: () => (window ? window.show() : createWindow()) },
        { label: "Scan Downloads now", click: () => void scanPaths(settings.watchFolders) },
        { type: "separator" },
        { label: "Quit", click: () => app.quit() },
      ]),
    );
  } catch {
    tray = null; // no system tray (some Linux desktops)
  }
}

async function start() {
  const dir = dataDir();
  const personal = (["documents", "desktop", "pictures"] as const).map((name) => app.getPath(name));
  personalFolders = personal;
  settings = await loadSettings(join(dir, "settings.json"), defaultSettings(app.getPath("downloads"), personal, hostname().slice(0, 80) || "This computer"));
  // The renderer's styles follow prefers-color-scheme, which this sets for the app.
  nativeTheme.themeSource = settings.theme;
  if (process.env.SENTINEL_SERVER) settings.serverUrl = new URL(process.env.SENTINEL_SERVER).origin;
  signatures = new SignatureStore(join(dir, "signatures.json"));
  await signatures.open();
  quarantine = new Quarantine(join(dir, "quarantine"));
  try {
    history = JSON.parse(await readFile(join(dir, "history.json"), "utf8")) as ScanResult[];
  } catch {
    history = [];
  }
  clamBinary = await findClam();
  sevenZip = await findSevenZip();
  ransomware = new RansomwareMonitor(onRansomware);
  watcher = new FolderWatcher((path) => {
    if (excluded(path)) return;
    void scanFile(path, context()).then((result) => record(result, true));
  });

  // Nothing the page asks for (camera, notifications from web content, etc.) is granted.
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  telemetry = await Telemetry.open(join(dir, "telemetry.db")).catch(() => null);
  integrity = new IntegrityMonitor(join(dir, "integrity.json"), (changes) => {
    for (const change of changes) logEvent("integrity", "alert", `${change.kind}: ${change.path}`);
    notify(
      changes.length === 1 ? "A protected file changed" : `${changes.length} protected files changed`,
      changes.map((c) => `${c.path} (${c.kind})`).join("\n").slice(0, 240),
    );
    send("integrity-alert", integrity.state);
  });
  await integrity.load();
  integrity.start();
  startTelemetry();
  registerIpc();
  createWindow();
  createTray();
  applyWatching();
  void updateSignatures();
  // Decoys changed while Qalaa was not running are reported before new ones are planted.
  decoys = await loadJson<DecoyRecord>(decoyFile(), {});
  const tampered = await tamperedDecoys(decoys);
  if (tampered.length) {
    onRansomware({ reasons: [`${tampered.length} hidden decoy file(s) were changed or deleted while Qalaa was not running`], examples: tampered.map((t) => t.path).slice(0, 5) });
  }
  await applyDecoys(true);
  disabledStartup = await loadJson<tools.DisabledStartup[]>(disabledStartupFile(), []);
  const testDrives = process.env.QALAA_TEST_REMOVABLE_ROOT;
  removable = new RemovableWatcher(
    (mount) => void onRemovable(mount),
    testDrives ? async () => (await readdir(testDrives).catch(() => [] as string[])).map((name) => join(testDrives, name)) : () => removableMounts(),
  );
  removable.start(testDrives ? 1000 : 5000);
  dropWatcher = new DropWatcher((path) => void onDroppedFile(path));
  persistenceWatcher = new DropWatcher((path) => void onPersistenceFile(path), 1200);
  applySystemWatch();
  // On-access scanning: start answering the helper if the user enabled it.
  if (settings.onAccessScan) void startOnAccessServer();
  // VPN auto-connect: watch Wi-Fi if enabled.
  applyVpnAutoConnect();
  // Scheduled home-network rescan (every 6 hours) when the person turned it on.
  setInterval(() => {
    if (settings.networkWatch && !silent() && !networkScanning) void runNetworkScan().catch(() => {});
  }, 6 * 60 * 60 * 1000).unref();
  setInterval(() => void updateSignatures(), SIGNATURE_REFRESH_MS).unref();
  // Mailbox scanning: new mail every 15 minutes when the person turned it on.
  mailConfig = { ...mailConfig, ...(await loadJson<Partial<MailConfig>>(mailFile(), {})) };
  setInterval(() => {
    if (mailConfig.watch && mailConfig.account && !silent()) void checkMail().catch(() => {});
  }, 15 * 60 * 1000).unref();

  account = await loadAccount(accountFile());
  remote = new RemoteAgent({
    account: () => account,
    allowRemote: () => settings.allowRemote,
    folders: offeredFolders,
    homeFolder: () => process.env.SENTINEL_DESKTOP_HOME ?? homedir(),
    status: () => ({
      protection: settings.watchEnabled ? "watching" : "paused",
      signatures: signatures.size,
      signatures_updated: signatures.meta?.updatedAt ?? null,
      ransomware_watch: settings.ransomwareWatch,
      clamav: Boolean(clamBinary),
      os: process.platform,
      firewall: lastFirewall?.state ?? null,
      exposed_risky_ports: lastPorts ? lastPorts.filter((port) => port.risk).length : null,
      last_backup: settings.lastBackup?.at ?? null,
    }),
    version: () => app.getVersion(),
    scan: (targets, onProgress) => exclusive(() => scanLabelled(targets, onProgress)),
    quarantineByHash,
    updateSignatures,
    unlinked: () => {
      account = null;
      remote.stop();
      void saveAccount(accountFile(), null);
      send("remote-activity", "This computer was removed from your Qalaa account.");
    },
    activity: (message) => {
      if (Notification.isSupported()) new Notification({ title: "Qalaa Desktop", body: message }).show();
      send("remote-activity", message);
    },
  });
  if (account) remote.start();

  applyPrivacyWatch();
  void startCoreIpc().catch(() => undefined);
  void securityCheck().catch(() => undefined);
  setInterval(() => void checkSchedules(), 60_000).unref();
  setTimeout(() => void checkSchedules(), 15_000).unref();
  if (app.isPackaged) {
    setTimeout(() => void checkForUpdates(), 60_000).unref();
    setInterval(() => void checkForUpdates(), UPDATE_CHECK_MS).unref();
  }
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  // qalaa://safepay?url=… from the browser extension: Windows and Linux pass it
  // to a second instance, macOS sends open-url.
  app.setAsDefaultProtocolClient("qalaa");
  app.on("open-url", (event, link) => {
    event.preventDefault();
    openSafePayLink(link);
  });
  app.on("second-instance", (_event, argv) => {
    const link = argv.find((a) => a.startsWith("qalaa://"));
    if (link && openSafePayLink(link)) return;
    window?.show();
  });
  app.whenReady().then(start, (error: unknown) => {
    console.error(error);
    app.quit();
  });
  // Keep watching in the tray after the window closes; quit from the tray menu.
  app.on("window-all-closed", () => {
    if (!tray || !settings?.watchEnabled) app.quit();
  });
  app.on("activate", () => window ?? createWindow());
  app.on("before-quit", () => {
    watcher?.close();
    ransomware?.close();
    remote?.stop();
    if (privacyTimer) clearInterval(privacyTimer);
  });
}
