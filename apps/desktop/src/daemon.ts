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
import { stat } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { join, sep } from "node:path";

import { type CoreHost, type Emit, createHandlers } from "./core/handlers";
import { AliasService } from "./core/alias-service";
import { BrokerService } from "./core/broker-service";
import { ClipboardService, POLL_MS } from "./core/clipboard-service";
import { loadAccount } from "./engine/account";
import { CredentialGuardService, pollMs as credentialPollMs } from "./core/credential-guard-service";
import { KeyboardService } from "./core/keyboard-service";
import { ListenerService } from "./core/listener-service";
import { ScanEngineService } from "./core/scan-engine-service";
import { HISTORY_LIMIT, ScanService } from "./core/scan-service";
import { SandboxService } from "./core/sandbox-service";
import { findDnsFilter } from "./engine/dns-filter";
import { BehaviourService } from "./core/behaviour-service";
import { ConnectorServer, installHelperCommand, uninstallHelperCommand } from "./engine/proc-connector";
import { runElevated } from "./core/listener-service";
import { findNativeScanner } from "./engine/native-scan";
import { SafeDnsService } from "./core/safe-dns-service";
import { SafePayService } from "./core/safepay-service";
import type { HomeInput } from "./core/home";
import { dataDirFor, ipcPaths } from "./core/paths";
import { startIpcServer } from "./core/server";
import { findClam } from "./engine/clamav";
import { systemClipboard } from "./engine/clipboard";
import { findSevenZip } from "./engine/formats";
import { listKeyboards, pollMs } from "./engine/hid";
import { Quarantine } from "./engine/quarantine";
import { scanFile } from "./engine/scanner";
import { deepCheck } from "./engine/tools";
import { fetchSignatures, lookupHash } from "./engine/server";
import { type DesktopSettings, defaultSettings, loadSettings, saveSettings } from "./engine/settings";
import { listeningPorts } from "./engine/security";
import { SignatureStore } from "./engine/signatures";
import { isDirectory, walk } from "./engine/walk";

declare const __QALAA_VERSION__: string;
const VERSION = typeof __QALAA_VERSION__ === "string" ? __QALAA_VERSION__ : "dev";
async function mtime(file: string): Promise<string | null> {
  try {
    return (await stat(file)).mtime.toISOString();
  } catch {
    return null;
  }
}

export async function createDaemonHost(dataDir: string, emit: Emit = () => {}): Promise<CoreHost & { settings: () => DesktopSettings; listeners: ListenerService; keyboards: KeyboardService; safeDns: SafeDnsService; clipboard: ClipboardService; credentials: CredentialGuardService; safePay: SafePayService; aliases: AliasService; brokers: BrokerService; scanEngine: ScanEngineService; behaviour: BehaviourService }> {
  const settingsFile = join(dataDir, "settings.json");
  const historyFile = join(dataDir, "history.json");
  let settings = await loadSettings(settingsFile, defaultSettings(join(homedir(), "Downloads"), [], hostname().slice(0, 80) || "This computer"));
  const signatures = new SignatureStore(join(dataDir, "signatures.json"));
  await signatures.open();
  const quarantine = new Quarantine(join(dataDir, "quarantine"));
  let signatureError: string | null = null;
  const listeners = new ListenerService(join(dataDir, "listeners.json"), process.platform, () => listeningPorts(), emit);
  await listeners.load();
  const keyboards = new KeyboardService(join(dataDir, "keyboards.json"), () => listKeyboards(), emit);
  await keyboards.load();
  const safeDns = new SafeDnsService(join(dataDir, "safe-dns.json"), () => settings.serverUrl, { platform: process.platform, filterBinary: await findDnsFilter(), listsDir: join(dataDir, "dns-lists") });
  await safeDns.load();
  const clipboard = new ClipboardService(systemClipboard(), emit);
  clipboard.configure({ enabled: settings.clipboardGuard, ttlSeconds: settings.clipboardTtl });
  const credentials = new CredentialGuardService({ file: join(dataDir, "credential-guard.json"), home: homedir(), platform: process.platform, emit });
  await credentials.load();
  credentials.configure({ enabled: settings.credentialGuard });
  const safePay = new SafePayService({ platform: process.platform, emit, safeDnsOn: () => safeDns.isOn() });
  await safePay.cleanup();
  // Uses the account the classic app linked (account.json in the same data folder).
  const brokers = new BrokerService(join(dataDir, "brokers.json"), undefined, undefined, (text) => clipboard.copyPlain(text));
  await brokers.load();
  const aliases = new AliasService(() => loadAccount(join(dataDir, "account.json")), (text) => clipboard.copyPlain(text));
  const scanEngine = new ScanEngineService({ root: join(dataDir, "scan-bundle"), binary: await findNativeScanner(), baseUrl: () => `${settings.serverUrl.replace(/\/+$/, "")}/api/v1/updates/scan-bundle/` });
  await scanEngine.load();
  const procSocket = join(dataDir, "proc.sock");
  const behaviour = new BehaviourService({
    platform: process.platform,
    emit,
    helper: (install) => runElevated(install ? installHelperCommand(join(__dirname, "procwatchd.py").replace(`app.asar${sep}`, `app.asar.unpacked${sep}`), procSocket) : uninstallHelperCommand()),
  });
  if (process.platform === "linux") {
    // Every program start from the root helper, when it's installed; /proc polling otherwise.
    await new ConnectorServer(procSocket, (event) => void behaviour.check(event), (connected) => behaviour.setConnector(connected)).start().catch(() => undefined);
  }
  const clamBinary = await findClam();
  const sevenZip = await findSevenZip();
  const scans = new ScanService({
    historyFile,
    quarantine,
    scanFile,
    walk,
    isDirectory,
    context: () => ({
      signatures,
      clamBinary: settings.useClamav ? clamBinary : null,
      nativeScanner: scanEngine.scanner(),
      sevenZip,
      cloudLookup: settings.cloudLookup ? (sha: string) => lookupHash(settings.serverUrl, sha) : undefined,
    }),
    watchFolders: () => settings.watchFolders,
    exclusions: () => settings.exclusions,
    async saveExclusions(exclusions) {
      settings = { ...settings, exclusions };
      await saveSettings(settingsFile, settings);
    },
    deepCheck: () => deepCheck(process.platform, homedir()),
    emit,
  });
  await scans.load();
  const history = () => scans.results();

  return {
    version: VERSION,
    settings: () => settings,
    listeners,
    scanEngine,
    behaviour,
    sandbox: new SandboxService({ server: () => settings.serverUrl }),
    keyboards,
    safeDns,
    clipboard,
    credentials,
    safePay,
    aliases,
    brokers,
    scans,
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
        lastScanAt: history()[0]?.scannedAt ?? null,
        lastNetworkScanAt: await mtime(join(dataDir, "network-devices.json")),
        lastBackupAt: settings.lastBackup?.at ?? null,
        lastBackupError: settings.lastBackupError,
        backupConfigured: settings.backupFolders.length > 0 && Boolean(settings.backupDestination),
        quarantineCount: (await quarantine.list()).length,
        recentThreats: history().filter((r) => (r.verdict === "malicious" || r.verdict === "suspicious") && Date.parse(r.scannedAt) > weekAgo).length,
        ransomwareAlertAt: null,
        updateAvailable: null,
        silentUntil: settings.silentUntil,
        newListeners: listeners.newCount(),
        newKeyboards: keyboards.newCount(),
        safeDns: { on: safeDns.isOn(), available: safeDns.isSupported() },
        dnsAdBlocking: { on: safeDns.status().adBlocking.on, available: safeDns.isOn() && safeDns.status().adBlocking.available },
        clipboardGuard: { on: settings.clipboardGuard, available: clipboard.status().supported },
        credentialGuard: { on: settings.credentialGuard, available: credentials.isSupported(), pending: credentials.pendingCount() },
        behaviourPending: behaviour.pendingCount(),
        brokersRecheckDue: brokers.recheckDueCount(),
      };
    },
    async updateToggles(changes) {
      settings = { ...settings, ...changes };
      await saveSettings(settingsFile, settings);
      clipboard.configure({ enabled: settings.clipboardGuard });
      credentials.configure({ enabled: settings.credentialGuard });
    },
    quickScan() {
      return scans.quick();
    },
    async updateSignatures() {
      try {
        await signatures.save(await fetchSignatures(settings.serverUrl));
        signatureError = null;
      } catch (error) {
        signatureError = error instanceof Error ? error.message : String(error);
      }
      // The native scanner's signed rules and model update with the signatures.
      await scanEngine.update();
    },
  };
}

export async function runDaemon(env: NodeJS.ProcessEnv = process.env) {
  const dataDir = dataDirFor(process.platform, env);
  let server: Awaited<ReturnType<typeof startIpcServer>> | null = null;
  const emit: Emit = (event, payload) => server?.broadcast(event, payload);
  const host = await createDaemonHost(dataDir, emit);
  const handlers = createHandlers(host, emit);
  server = await startIpcServer(ipcPaths(process.platform, env, dataDir), handlers, { version: host.version });
  // New listening ports: checked every minute; the first check only records what's there.
  const checkListeners = () => void host.listeners.check().then((fresh) => (fresh.length ? handlers["home.get"]?.(undefined).then((m) => emit("home.changed", m)) : undefined)).catch(() => undefined);
  checkListeners();
  setInterval(checkListeners, 60_000).unref();
  // Behaviour rules: new programs every second or two (the first look only records what runs).
  const behaviourCap = host.behaviour.capability();
  if (host.behaviour.isSupported()) {
    const checkBehaviour = () => void host.behaviour.poll().then((found) => (found.length ? handlers["home.get"]?.(undefined).then((m) => emit("home.changed", m)) : undefined)).catch(() => undefined);
    checkBehaviour();
    setInterval(checkBehaviour, behaviourCap.intervalMs || 1_000).unref();
  }
  // qalaa-scan's signed rule bundle: a few minutes after start, then daily.
  const updateScanEngine = () => void host.scanEngine.update().catch(() => undefined);
  setTimeout(updateScanEngine, 3 * 60_000).unref();
  setInterval(updateScanEngine, 24 * 60 * 60_000).unref();
  // New keyboards (BadUSB): checked every few seconds; the first look records what's there.
  const checkKeyboards = () => void host.keyboards.check().then((fresh) => (fresh.length ? handlers["home.get"]?.(undefined).then((m) => emit("home.changed", m)) : undefined)).catch(() => undefined);
  checkKeyboards();
  setInterval(checkKeyboards, pollMs(process.platform)).unref();
  // Safe DNS: if it was left on, the system already points at the proxy.
  void host.safeDns.resume();
  // Clipboard auto-clear: a cheap look every couple of seconds while it's on.
  setInterval(() => void host.clipboard.poll().catch(() => undefined), POLL_MS).unref();
  // Credential guardrails: who has SSH keys, .env files and browser secrets open.
  const checkCredentials = () => void host.credentials.poll().then((found) => (found.length ? handlers["home.get"]?.(undefined).then((m) => emit("home.changed", m)) : undefined)).catch(() => undefined);
  if (host.credentials.isSupported()) setInterval(checkCredentials, credentialPollMs(process.platform)).unref();
  setInterval(() => void host.safeDns.refreshDomains().catch(() => undefined), 60 * 60 * 1000).unref();
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
