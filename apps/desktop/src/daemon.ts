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
import { readFile, stat, unlink, writeFile } from "node:fs/promises";
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
import { NetworkService } from "./core/network-service";
import { PostureService } from "./core/posture-service";
import { PrivacyService } from "./core/privacy-service";
import { MailService } from "./core/mail-service";
import { systemKeychain } from "./core/keychain";
import { VpnService } from "./core/vpn-service";
import { ProtectionService, onAccessIdentity } from "./core/protection-service";
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
import { RansomwareBurst } from "./engine/behaviour";
import * as cfa from "./engine/cfa";
import * as fanotify from "./engine/fanotify";
import { isExcluded, plantDecoys, tamperedDecoys, type DecoyRecord } from "./engine/protection";
import { RansomwareMonitor } from "./engine/ransomware";
import { scanFile } from "./engine/scanner";
import { disableTerminal, enableTerminal, terminalStatus } from "./engine/shell-init";
import { pendingUpdates, wifiStatus } from "./engine/system";
import { checkHttp, checkLineService } from "./engine/network/credentials";
import { loadInventory, saveInventory } from "./engine/network/inventory";
import { scanNetwork } from "./engine/network/scan";
import { diskEncryption } from "./engine/encryption";
import { IntegrityMonitor } from "./engine/integrity";
import { posture } from "./engine/posture";
import { cameraAndMicrophoneUse, firewallStatus, newUses, startupItems } from "./engine/security";
import * as privacyBlock from "./engine/privacy-block";
import * as mail from "./engine/mail";
import { execFile } from "node:child_process";
import { canSwitchOff, switchOffStartup, switchOnStartup, type DisabledStartup } from "./engine/tools";
import * as vpn from "./engine/vpn";
import * as vpnGuard from "./engine/vpn-guard";
import { FolderWatcher } from "./engine/watcher";
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

export async function createDaemonHost(dataDir: string, emit: Emit = () => {}): Promise<CoreHost & { settings: () => DesktopSettings; listeners: ListenerService; keyboards: KeyboardService; safeDns: SafeDnsService; clipboard: ClipboardService; credentials: CredentialGuardService; safePay: SafePayService; aliases: AliasService; brokers: BrokerService; scanEngine: ScanEngineService; behaviour: BehaviourService; protection: ProtectionService; network: NetworkService; vpn: VpnService; posture: PostureService; integrity: IntegrityMonitor; privacy: PrivacyService; mail: MailService }> {
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
  const scanContext = () => ({
    signatures,
    clamBinary: settings.useClamav ? clamBinary : null,
    nativeScanner: scanEngine.scanner(),
    sevenZip,
    cloudLookup: settings.cloudLookup ? (sha: string) => lookupHash(settings.serverUrl, sha) : undefined,
  });
  const scans = new ScanService({
    historyFile,
    quarantine,
    scanFile,
    walk,
    isDirectory,
    context: () => scanContext(),
    watchFolders: () => settings.watchFolders,
    exclusions: () => settings.exclusions,
    async saveExclusions(exclusions) {
      settings = { ...settings, exclusions };
      await saveSettings(settingsFile, settings);
    },
    deepCheck: () => deepCheck(process.platform, homedir()),
    autoQuarantine: () => settings.autoQuarantine,
    emit,
  });
  await scans.load();
  const unpacked = (file: string) => join(__dirname, file).replace(`app.asar${sep}`, `app.asar.unpacked${sep}`);
  const decoyFile = join(dataDir, "decoys.json");
  const onAccessSocket = join(dataDir, "onaccess.sock");
  const burst = new RansomwareBurst();
  let protection: ProtectionService;
  const folderWatcher = new FolderWatcher((path) => protection.onNewFile(path));
  const ransomwareMonitor = new RansomwareMonitor((alert) => protection.ransomwareAlert(alert));
  protection = new ProtectionService({
    platform: process.platform,
    settings: () => settings,
    async saveSettings(changes) {
      settings = { ...settings, ...changes };
      await saveSettings(settingsFile, settings);
    },
    scanAutomatic: (path, known) => scans.scanAutomatic(path, known),
    scanFile: (path) => scanFile(path, scanContext()),
    isExcluded: (path) => isExcluded(path, settings.exclusions),
    emit,
    folderWatcher,
    ransomwareMonitor,
    decoys: {
      load: async () => JSON.parse(await readFile(decoyFile, "utf8")) as DecoyRecord,
      save: (record) => writeFile(decoyFile, JSON.stringify(record)),
      plant: (folders) => plantDecoys(folders),
      tampered: (record) => tamperedDecoys(record),
      remove: (path) => unlink(path),
    },
    onAccess: {
      supported: fanotify.onAccessSupported(),
      status: () => fanotify.onAccessStatus(),
      enable: () => fanotify.enableOnAccess({ bundledHelper: unpacked("onaccessd.py"), socketPath: onAccessSocket, markRoots: [onAccessIdentity().home], user: onAccessIdentity().user }),
      disable: () => fanotify.disableOnAccess(),
      async startResponder(hooks) {
        const server = new fanotify.OnAccessServer({
          socketPath: onAccessSocket,
          scan: hooks.scan,
          isExcluded: hooks.isExcluded,
          onBlocked: hooks.onBlocked,
          onOpen: hooks.onOpen,
          behaviour: { feed: hooks.feed },
          onHalt: hooks.onHalt,
        });
        await server.start();
        return server;
      },
      burst,
      // The helper froze it as root, so changing its state needs root too (a pkexec prompt).
      signal: (pid, action) => runElevated({ command: "pkexec", args: ["kill", action === "kill" ? "-KILL" : "-CONT", String(pid)] }),
    },
    observeOpen: (pid, path) => void credentials.observe(pid, path).catch(() => undefined),
    cfa: { status: () => cfa.cfaStatus(), apply: (action, path) => cfa.cfaApply(action, path) },
    acceptChanged: async (files) => {
      for (const file of files) if (integrity.state.paths.includes(file)) await integrity.accept(file).catch(() => undefined);
    },
    terminal: {
      status: () => terminalStatus(),
      // The qalaa command runs on this service's own Node runtime; cli.js is built beside daemon.js.
      enable: () => enableTerminal(process.execPath, unpacked("cli.js"), undefined, undefined, dataDir),
      disable: () => disableTerminal(),
    },
    wifi: () => wifiStatus(),
    updates: () => pendingUpdates(),
  });
  const inventoryFile = join(dataDir, "network-devices.json");
  // Test hook, as in the classic app: scan an explicit host list instead of the live network.
  const forceHosts = process.env.QALAA_TEST_NETWORK_HOST?.split(",").map((h) => h.trim()).filter(Boolean);
  const network = new NetworkService({
    scanFile: join(dataDir, "network-scan.json"),
    loadInventory: () => loadInventory(inventoryFile),
    saveInventory: (inventory) => saveInventory(inventoryFile, inventory),
    scanNetwork: (onProgress) => scanNetwork({ forceHosts: forceHosts?.length ? forceHosts : undefined, onProgress }),
    checkHttp: (ip, port) => checkHttp(ip, port),
    checkLineService: (ip, port, service) => checkLineService(ip, port, service),
    watchOn: () => settings.networkWatch,
    emit,
  });
  await network.load();
  // File integrity (hosts, authorized_keys, shell profiles…): watched by the service itself now.
  const integrity = new IntegrityMonitor(join(dataDir, "integrity.json"), (changes) => {
    emit("alert", { kind: "integrity", files: changes.map((c) => c.path).slice(0, 5), count: changes.length });
  });
  await integrity.load();
  const disabledStartupFile = join(dataDir, "startup-disabled.json");
  const postureService = new PostureService({
    platform: process.platform,
    posture: (facts) => posture(facts),
    firewall: () => firewallStatus(),
    encryption: () => diskEncryption(),
    pendingUpdates: async () => (await pendingUpdates())?.updates.length ?? null,
    ports: () => listeningPorts(),
    startup: () => startupItems(),
    canSwitchOff: (item) => canSwitchOff(item),
    switchOff: (item) => switchOffStartup(item),
    switchOn: (entry) => switchOnStartup(entry),
    knownStartup: () => settings.knownStartup,
    async saveKnownStartup(ids) {
      settings = { ...settings, knownStartup: ids };
      await saveSettings(settingsFile, settings);
    },
    loadDisabled: async () => JSON.parse(await readFile(disabledStartupFile, "utf8")) as DisabledStartup[],
    saveDisabled: (entries) => writeFile(disabledStartupFile, JSON.stringify(entries)),
    integrity,
    newKeyboards: () => keyboards.newCount(),
  });
  await postureService.load();
  const privacy = new PrivacyService({
    platform: process.platform,
    locks: {
      supported: () => privacyBlock.privacyBlockSupported(),
      async state(device) {
        if (process.platform === "win32") {
          return new Promise((resolve) =>
            execFile("reg.exe", privacyBlock.windowsRegQueryArgs(device), { windowsHide: true, timeout: 10_000 }, (_e, out) => resolve(privacyBlock.parseWindowsConsent(String(out)))),
          );
        }
        return privacyBlock.linuxState(device === "camera" ? await privacyBlock.cameraNodes() : await privacyBlock.micNodes());
      },
      async set(device, block) {
        if (process.platform === "win32") {
          await new Promise<void>((resolve, reject) =>
            execFile("reg.exe", privacyBlock.windowsRegSetArgs(device, !block), { windowsHide: true, timeout: 10_000 }, (e) => (e ? reject(e) : resolve())),
          );
          return;
        }
        const nodes = device === "camera" ? await privacyBlock.cameraNodes() : await privacyBlock.micNodes();
        if (!nodes.length) throw new Error(`No ${device} was found on this computer.`);
        await runElevated({ command: "pkexec", args: ["sh", "-c", privacyBlock.linuxBlockScript(nodes, block)] });
      },
    },
    deviceUse: () => cameraAndMicrophoneUse(),
    newUses: (before, now) => newUses(before, now),
    watchOn: () => settings.privacyWatch,
    async saveWatch(on) {
      settings = { ...settings, privacyWatch: on };
      await saveSettings(settingsFile, settings);
    },
    clipboard: () => clipboard.status(),
    serverUrl: () => settings.serverUrl,
    emit,
  });
  const mailService = new MailService({
    // The same file the classic app keeps the account (not the password) in.
    file: join(dataDir, "mail.json"),
    keychain: systemKeychain(process.platform, dataDir),
    emptyState: mail.EMPTY_STATE,
    sanitizeAccount: (input) => mail.sanitizeAccount(input),
    scanInbox: (account, password, state) =>
      mail.scanInbox(account, password, state, settings.serverUrl, { lang: settings.language === "ar" ? "ar" : "en" }),
    worrying: (results) => mail.worrying(results),
    emit,
  });
  await mailService.load();
  const vpnService = new VpnService({
    platform: process.platform,
    tunnelFile: join(dataDir, `${vpn.CONNECTION_NAME}.conf`),
    // The account the classic app (or a future native sign-in) linked, in the same data folder.
    account: () => loadAccount(join(dataDir, "account.json")),
    settings: () => settings,
    async saveSettings(changes) {
      settings = { ...settings, ...changes };
      await saveSettings(settingsFile, settings);
    },
    tunnel: {
      state: () => vpn.tunnelState(),
      keyPair: () => vpn.generateKeyPair(),
      requestPeer: (account, publicKey) => vpn.requestPeer(account, publicKey),
      build: (config, privateKey) => vpn.buildConfig(config, privateKey),
      save: (text) => vpn.saveTunnel(dataDir, text),
      importFile: (file) => vpn.importTunnel(file),
      connect: () => vpn.connectTunnel(),
      disconnect: () => vpn.disconnectTunnel(),
    },
    guard: {
      capable: () => vpnGuard.killSwitchCapable(),
      applySplit: (config, mode, cidrs) => vpnGuard.applySplitTunnel(config, mode, cidrs),
      killSwitchScript: (host, allowLan) => vpnGuard.killSwitchScript(vpnGuard.killSwitchRules(vpn.CONNECTION_NAME, host, allowLan)),
      removeKillSwitchScript: () => vpnGuard.removeKillSwitchScript(),
      shouldAutoConnect: (wifi, policy) => vpnGuard.shouldAutoConnect(wifi, policy),
    },
    elevate: (script) => runElevated({ command: "pkexec", args: ["sh", "-c", script] }),
    wifi: () => wifiStatus(),
    emit,
  });
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
    protection,
    network,
    vpn: vpnService,
    posture: postureService,
    integrity,
    privacy,
    mail: mailService,
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
        lastNetworkScanAt: network.lastScanAt() ?? (await mtime(join(dataDir, "network-devices.json"))),
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
      // On-access installs or removes a root helper, so it isn't just a saved setting.
      const { onAccessScan, ...rest } = changes;
      if (onAccessScan !== undefined && onAccessScan !== settings.onAccessScan) await protection.setOnAccess({ on: onAccessScan });
      settings = { ...settings, ...rest };
      await saveSettings(settingsFile, settings);
      clipboard.configure({ enabled: settings.clipboardGuard });
      credentials.configure({ enabled: settings.credentialGuard });
      // Real-time and ransomware watching follow their toggles at once.
      await protection.apply();
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
  // Real-time protection: new-file watching, ransomware watch and decoys, on-access.
  await host.protection.start().catch((error: unknown) => console.error(`Protection did not start: ${String(error)}`));
  // Watch my network: the scheduled rescan, checked hourly, runs when the last scan is 6 hours old.
  setInterval(() => void host.network.tick().catch(() => undefined), 60 * 60_000).unref();
  // VPN auto-connect on untrusted Wi-Fi, when it's on.
  host.vpn.applyAutoConnect();
  // File integrity: watch the protected files (and a 10-minute sweep).
  host.integrity.start();
  // Who's using the camera or microphone (Linux and Windows), when it's on.
  host.privacy.applyWatch();
  // New mail every 15 minutes, when the person turned it on.
  host.mail.applyWatch();
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
