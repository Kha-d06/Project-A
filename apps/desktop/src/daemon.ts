/**
 * Qalaa's headless background service: the scanning engine with no Electron and
 * no browser engine, serving the native interface over qalaa-ipc.
 *
 * During the move to the native app, the Electron shell serves the same methods
 * itself (src/core/handlers.ts); the daemon refuses to start while it runs, so
 * only one process ever writes the data folder.
 *
 *   node dist/daemon.js            # or the packaged single executable
 *   QALAA_DATA_DIR=… QALAA_IPC_ENDPOINT=… node dist/daemon.js   # tests
 */
import { readFile, stat, writeFile } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { join } from "node:path";

import { type CoreHost, createHandlers } from "./core/handlers";
import type { HomeInput } from "./core/home";
import { dataDirFor, ipcPaths } from "./core/paths";
import { startIpcServer } from "./core/server";
import { findClam } from "./engine/clamav";
import { findSevenZip } from "./engine/formats";
import { isExcluded } from "./engine/protection";
import { Quarantine } from "./engine/quarantine";
import { scanFile } from "./engine/scanner";
import { fetchSignatures, lookupHash } from "./engine/server";
import { type DesktopSettings, defaultSettings, loadSettings, saveSettings } from "./engine/settings";
import { SignatureStore } from "./engine/signatures";
import type { ScanResult } from "./engine/types";
import { isDirectory, walk } from "./engine/walk";

declare const __QALAA_VERSION__: string;
const VERSION = typeof __QALAA_VERSION__ === "string" ? __QALAA_VERSION__ : "dev";
const HISTORY_LIMIT = 300;

async function mtime(file: string): Promise<string | null> {
  try {
    return (await stat(file)).mtime.toISOString();
  } catch {
    return null;
  }
}

export async function createDaemonHost(dataDir: string): Promise<CoreHost & { settings: () => DesktopSettings }> {
  const settingsFile = join(dataDir, "settings.json");
  const historyFile = join(dataDir, "history.json");
  let settings = await loadSettings(settingsFile, defaultSettings(join(homedir(), "Downloads"), [], hostname().slice(0, 80) || "This computer"));
  const signatures = new SignatureStore(join(dataDir, "signatures.json"));
  await signatures.open();
  const quarantine = new Quarantine(join(dataDir, "quarantine"));
  let signatureError: string | null = null;
  let history: ScanResult[] = [];
  try {
    history = JSON.parse(await readFile(historyFile, "utf8")) as ScanResult[];
  } catch {
    history = [];
  }
  const clamBinary = await findClam();
  const sevenZip = await findSevenZip();

  return {
    version: VERSION,
    settings: () => settings,
    async homeInput(): Promise<HomeInput> {
      const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      return {
        now: new Date(),
        platform: process.platform,
        watchEnabled: settings.watchEnabled,
        onAccessScan: settings.onAccessScan,
        ransomwareWatch: settings.ransomwareWatch,
        networkWatch: settings.networkWatch,
        cloudLookup: settings.cloudLookup,
        signatures: { count: signatures.size, updatedAt: signatures.meta?.updatedAt ?? null, error: signatureError },
        lastScanAt: history[0]?.scannedAt ?? null,
        lastNetworkScanAt: await mtime(join(dataDir, "network-devices.json")),
        lastBackupAt: settings.lastBackup?.at ?? null,
        lastBackupError: settings.lastBackupError,
        backupConfigured: settings.backupFolders.length > 0 && Boolean(settings.backupDestination),
        quarantineCount: (await quarantine.list()).length,
        recentThreats: history.filter((r) => (r.verdict === "malicious" || r.verdict === "suspicious") && Date.parse(r.scannedAt) > weekAgo).length,
        ransomwareAlertAt: null,
        updateAvailable: null,
        silentUntil: settings.silentUntil,
      };
    },
    async updateToggles(changes) {
      settings = { ...settings, ...changes };
      await saveSettings(settingsFile, settings);
    },
    async quickScan() {
      const totals = { scanned: 0, malicious: 0, suspicious: 0 };
      const context = {
        signatures,
        clamBinary: settings.useClamav ? clamBinary : null,
        sevenZip,
        cloudLookup: settings.cloudLookup ? (sha: string) => lookupHash(settings.serverUrl, sha) : undefined,
      };
      const skip = (path: string) => isExcluded(path, settings.exclusions);
      for (const folder of settings.watchFolders) {
        if (!(await isDirectory(folder))) continue;
        for await (const file of walk(folder, 50_000, skip)) {
          const result = await scanFile(file, context);
          history = [result, ...history].slice(0, HISTORY_LIMIT);
          totals.scanned += 1;
          if (result.verdict === "malicious") totals.malicious += 1;
          if (result.verdict === "suspicious") totals.suspicious += 1;
        }
      }
      await writeFile(historyFile, JSON.stringify(history));
      return totals;
    },
    async updateSignatures() {
      try {
        await signatures.save(await fetchSignatures(settings.serverUrl));
        signatureError = null;
      } catch (error) {
        signatureError = error instanceof Error ? error.message : String(error);
      }
    },
  };
}

export async function runDaemon(env: NodeJS.ProcessEnv = process.env) {
  const dataDir = dataDirFor(process.platform, env);
  const host = await createDaemonHost(dataDir);
  let server: Awaited<ReturnType<typeof startIpcServer>> | null = null;
  const handlers = createHandlers(host, (event, payload) => server?.broadcast(event, payload));
  server = await startIpcServer(ipcPaths(process.platform, env, dataDir), handlers, { version: host.version });
  const stop = () => void server?.close().then(() => process.exit(0));
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  console.log("Qalaa background service ready.");
  return server;
}

if (require.main === module) {
  runDaemon().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
