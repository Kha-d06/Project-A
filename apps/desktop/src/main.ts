/**
 * SENTINEL Desktop main process.
 *
 * The window shows only the app's own local page, with context isolation, the
 * Chromium sandbox, no Node.js in the page, no navigation, no new windows and
 * no permission grants. The page talks to this process through a fixed set of
 * IPC calls (see preload.ts), and every argument is validated here.
 */
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { BrowserWindow, Menu, Notification, Tray, app, dialog, ipcMain, nativeImage, session, shell } from "electron";

import { findClam } from "./engine/clamav";
import { findSevenZip } from "./engine/formats";
import { type RansomwareAlert, RansomwareMonitor } from "./engine/ransomware";
import { pendingUpdates, wifiStatus } from "./engine/system";
import { Quarantine } from "./engine/quarantine";
import { type ScanContext, scanFile } from "./engine/scanner";
import { fetchSignatures, lookupHash, uploadForFullScan } from "./engine/server";
import { type DesktopSettings, defaultSettings, loadSettings, sanitizeChanges, saveSettings } from "./engine/settings";
import { SignatureStore } from "./engine/signatures";
import type { ScanResult } from "./engine/types";
import { isDirectory, walk } from "./engine/walk";
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
  const entry = { ...result, quarantined };
  send("scan-result", entry);
  if (automatic && result.verdict !== "no_known_threat" && result.verdict !== "not_scanned" && Notification.isSupported()) {
    new Notification({
      title: result.verdict === "malicious" ? `Threat found: ${result.name}` : `Suspicious file: ${result.name}`,
      body: (quarantined ? "Moved to quarantine. " : "") + (result.findings[0]?.title ?? ""),
    }).show();
  }
  return entry;
}

async function scanPaths(paths: string[]): Promise<{ scanned: number; malicious: number; suspicious: number }> {
  const totals = { scanned: 0, malicious: 0, suspicious: 0 };
  const scanOne = async (path: string) => {
    const result = await scanFile(path, context());
    await record(result, false);
    totals.scanned += 1;
    if (result.verdict === "malicious") totals.malicious += 1;
    if (result.verdict === "suspicious") totals.suspicious += 1;
    send("scan-progress", { ...totals, current: path });
  };
  for (const path of paths) {
    if (await isDirectory(path)) {
      for await (const file of walk(path)) await scanOne(file);
    } else {
      await scanOne(path);
    }
  }
  return totals;
}

async function updateSignatures(): Promise<void> {
  try {
    await signatures.save(await fetchSignatures(settings.serverUrl));
    lastSignatureError = null;
  } catch (error) {
    lastSignatureError = error instanceof Error ? error.message : String(error);
  }
}

function onRansomware(alert: RansomwareAlert) {
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
  tray?.setToolTip(settings.watchEnabled ? "SENTINEL Desktop: watching for new files" : "SENTINEL Desktop: watching paused");
}

async function status() {
  return {
    settings,
    signatures: { count: signatures.size, ...(signatures.meta ?? {}), error: lastSignatureError },
    clamav: { available: Boolean(clamBinary), path: clamBinary },
    watching: watcher.folders,
    ransomwareAlert: lastRansomwareAlert,
    quarantineCount: (await quarantine.list()).length,
    platform: process.platform,
    version: app.getVersion(),
    locale: app.getLocale(),
  };
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
  ipcMain.handle("scan", (_event, paths: unknown) => scanPaths(stringArray(paths)));
  ipcMain.handle("quick-scan", () => scanPaths(settings.watchFolders));
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
    applyWatching();
    return status();
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
    title: "SENTINEL Desktop",
    backgroundColor: "#f4f6fa",
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
        { label: "Open SENTINEL Desktop", click: () => (window ? window.show() : createWindow()) },
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
  settings = await loadSettings(join(dir, "settings.json"), defaultSettings(app.getPath("downloads"), personal));
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
    void scanFile(path, context()).then((result) => record(result, true));
  });

  // Nothing the page asks for (camera, notifications from web content, etc.) is granted.
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  registerIpc();
  createWindow();
  createTray();
  applyWatching();
  void updateSignatures();
  setInterval(() => void updateSignatures(), SIGNATURE_REFRESH_MS).unref();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => window?.show());
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
  });
}
