/** The interface. Builds everything with textContent; never parses HTML. */
import type { SentinelApi } from "../preload";
import type { QuarantineItem } from "../engine/quarantine";
import type { DesktopSettings } from "../engine/settings";
import type { ScanResult } from "../engine/types";

import { DICTS, FINDINGS_AR, type Lang, resolve } from "./i18n";

declare global {
  interface Window {
    sentinel: SentinelApi;
  }
}

interface Status {
  ransomwareAlert: { reasons: string[]; examples: string[]; at: string } | null;
  settings: DesktopSettings;
  signatures: { count: number; updatedAt?: string; error: string | null };
  clamav: { available: boolean; path: string | null };
  watching: string[];
  quarantineCount: number;
  locale: string;
  account: { email: string; server: string } | null;
  remote: { lastContact: string | null; lastError: string | null };
  schedule: { nextScan: string | null; nextBackup: string | null };
  backup: { running: boolean; hasPassword: boolean; keychain: boolean };
  privacyWatchSupported: boolean;
  platform: string;
  version: string;
  update: UpdateView;
  installKind: string;
  silent: boolean;
  decoys: number;
  firewallBlock: boolean;
}

interface StartupRow { id: string; name: string; command: string; location: string; warnings: string[]; canSwitchOff: boolean }
interface DisabledRow { id: string; name: string; command: string; location: string; at: string }
interface JunkRow { id: string; label: string; files: number; bytes: number }
interface ExtensionRow { browser: string; profile: string; id: string; name: string; version: string; fromStore: boolean; enabled: boolean; risk: "high" | "medium" | "low"; reasons: string[] }
interface DeepResult { findings: { area: string; item: string; severity: "high" | "medium" | "low"; detail: string }[]; checked: string[]; checkedAt: string }

type UpdateView =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "none"; checkedAt: string }
  | { state: "available"; version: string }
  | { state: "downloading"; percent: number }
  | { state: "ready"; version: string }
  | { state: "manual"; version: string; reason: string }
  | { state: "error"; message: string };

interface SecurityResult {
  firewall: { state: "on" | "off" | "partial" | "unknown"; detail: string | null; source: string | null };
  ports: { port: number; address: string; process: string | null; pid: number | null; exposed: boolean; risk: string | null }[] | null;
  startup: { id: string; name: string; command: string; location: string; program: string | null; warnings: string[]; isNew: boolean }[];
  deviceUse: { uses: { device: "camera" | "microphone"; app: string }[]; unsupported: string[]; log: { at: string; device: "camera" | "microphone"; app: string }[] };
  encryption: { state: "on" | "off" | "partial" | "unknown"; detail: string | null; source: string | null };
  checkedAt: string;
}

interface ProcessReport {
  supported: boolean;
  checkedAt: string;
  unreadable: number;
  programs: { name: string; path: string; pids: number[]; concerns: string[]; verdict: ScanResult["verdict"] | null; title: string | null }[];
}

interface BrowsingReport {
  checkedAt: string;
  days: number;
  browsers: { browser: string; profile: string; visits: number; error: string | null }[];
  matches: { browser: string; profile: string; url: string; host: string; visitedAt: string | null; reason: "url" | "domain" }[];
}

interface VpnGuard {
  capable: boolean;
  killSwitch: boolean;
  allowLan: boolean;
  splitMode: "full" | "exclude" | "only";
  splitCidrs: string[];
  autoConnect: boolean;
  trusted: string[];
}
interface VpnView {
  linked: boolean;
  saved: boolean;
  state: "connected" | "disconnected" | "not_imported" | "unsupported";
  platform: string;
  guard?: VpnGuard;
}

type Entry = ScanResult & { quarantined?: string };
type Tab = "scan" | "protection" | "security" | "network" | "monitor" | "tools" | "quarantine" | "history" | "settings";

interface NetService { port: number; name: string; banner: string | null }
interface NetDevice { ip: string; mac: string | null; vendor: string | null; hostname: string | null; role: "router" | "self" | "device"; services: NetService[]; trusted: boolean; firstSeen: string | null }
interface NetFinding { severity: "critical" | "high" | "medium" | "low" | "info"; rule: string; title: string; detail: string; device: string | null }
interface NetworkScanView {
  startedAt: string; finishedAt: string; cidr: string | null; gateway: string | null; interface: string | null;
  wifi: { ssid: string | null; risk: string } | null;
  devices: NetDevice[];
  router: { ip: string | null; adminHttp: boolean; hint: string | null; portForwards: { external: number; internal: string; protocol: string; description: string }[]; upnp: boolean; dns: { address: string; known: boolean }[] } | null;
  findings: NetFinding[]; capabilities: Record<string, string>; newDevices: string[];
}
interface CredResult { device: string; service: string; defaultAccepted: boolean; user: string | null; tried: number; stopped: string | null }

interface MonitorSnapshot {
  at: string;
  cpu: { total: number; cores: number[]; speedMhz: number[]; model: string; temperature: number | null };
  memory: { total: number; used: number };
  swap: { total: number; used: number } | null;
  disk: { readPerSec: number; writePerSec: number; iops: number; used: number | null; size: number | null } | null;
  network: { rxPerSec: number; txPerSec: number } | null;
  gpus: { name: string; utilization: number | null; memoryUsed: number | null; memoryTotal: number | null; temperature: number | null }[];
  load: number[] | null;
  uptimeSeconds: number;
}
interface MonitorConnection { protocol: string; local: string; remote: string | null; state: string; process: string | null; pid: number | null }
interface MonitorService { name: string; description: string; state: "running" | "stopped" | "failed" | "other"; startup: string | null }
interface MonitorEvent { at: string; level: "error" | "warning" | "info"; source: string; message: string; security: boolean }
interface ProcessRow { pid: number; ppid: number | null; name: string; path: string | null; commandLine: string | null; user: string | null; threads: number | null; handles: number | null; memoryBytes: number | null; state: string | null }
interface Inspection { sha256: string | null; signature: { status: string; signer: string | null; detail: string | null } }
interface StorageView { disks: { name: string; model: string | null; kind: string; sizeBytes: number | null; health: string; healthDetail: string | null }[]; volumes: { mount: string; device: string | null; fileSystem: string | null; sizeBytes: number; usedBytes: number; label: string | null }[] }
interface DnsView { query: string; addresses: { address: string; family: number; class: string | null }[]; reverse: string[]; mx: { exchange: string; priority: number }[]; txt: string[]; error: string | null }
interface NicView { name: string; addresses: string[]; mac: string | null; rxBytes: number | null; txBytes: number | null; rxPackets: number | null; txPackets: number | null; errors: number | null; drops: number | null }
interface HistoryView { at: string; cpu: number; memory: number; rx: number; tx: number; read: number; write: number }
interface LogView { at: string; kind: string; level: "info" | "warning" | "alert"; message: string }
interface PostureView { score: number | null; checkedAt: string; checks: { id: string; title: string; status: "pass" | "fail" | "warn" | "unknown"; detail: string | null; fix: string | null }[] }
interface IntegrityView { paths: string[]; changes: { path: string; kind: string; at: string }[]; lastCheck: string | null; baseline: Record<string, { sha256: string | null }> }
interface ServiceDetail { name: string; description: string | null; account: string | null; command: string | null; startup: string | null; dependsOn: string[]; requiredBy: string[] }

const api = window.sentinel;
let lang: Lang = "en";
let t = DICTS.en;
let status: Status;
let tab: Tab = "scan";
const results: Entry[] = [];
// Kept separately so a status refresh that started earlier cannot hide it.
let ransomwareAlert: Status["ransomwareAlert"] = null;
let security: SecurityResult | null = null;
let backupProgress: { files: number; current: string | null } | null = null;
let processReport: ProcessReport | null = null;
let processBusy = false;
let browsingReport: BrowsingReport | null = null;
let browsingBusy = false;
let vpnView: VpnView | null = null;
let monitorSamples: MonitorSnapshot[] = [];
let monitorPane: "processes" | "connections" | "services" | "events" | "storage" | "network" | "history" = "processes";
let monitorProcesses: ProcessRow[] | null | undefined;
const inspected = new Map<number, Inspection | "loading">();
const suspended = new Set<number>();
let monitorStorage: StorageView | null | undefined;
let monitorNics: NicView[] | undefined;
let dnsAnswer: DnsView | null = null;
let historyHours = 24;
let historyPoints: HistoryView[] | undefined;
let securityLog: LogView[] | undefined;
let eventSource: "system" | "security" = "system";
let eventLevel: "all" | "error" | "warning" = "all";
let securityNote: string | null = null;
const serviceOpen = new Map<string, ServiceDetail | "loading">();
let postureView: PostureView | null = null;
let postureBusy = false;
let integrityView: IntegrityView | null = null;
let reportBusy: string | null = null;
let monitorConnections: MonitorConnection[] | null | undefined;
let monitorServices: MonitorService[] | null | undefined;
let monitorEvents: MonitorEvent[] | null | undefined;
let monitorFilter = "";
let monitorExternalOnly = true;
let monitorSecurityOnly = false;
let monitorRunning = false;
let vpnBusy = false;
let networkScan: NetworkScanView | null = null;
let networkBusy = false;
let networkProgress: { done: number; total: number; phase: string } | null = null;
const credResults = new Map<string, CredResult[] | { refused: string } | "loading">();

type Child = Node | string | null | undefined | false;

const SVG = "http://www.w3.org/2000/svg";

// Line icons for the sidebar (24px grid, stroked with currentColor).
const TAB_ICONS: Record<string, string[]> = {
  scan: ["M3 7V5a2 2 0 0 1 2-2h2", "M17 3h2a2 2 0 0 1 2 2v2", "M21 17v2a2 2 0 0 1-2 2h-2", "M7 21H5a2 2 0 0 1-2-2v-2", "M11 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "m16 16-2.2-2.2"],
  protection: ["M20 13c0 5-3.5 7.5-7.7 9a1 1 0 0 1-.7 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1Z", "m9 12 2 2 4-4"],
  security: ["M3 21V7h3v2h2V7h3v4h2V7h3v2h2V7h3v14Z", "M10 21v-4a2 2 0 0 1 4 0v4"],
  network: ["M5 12.55a11 11 0 0 1 14 0", "M1.42 9a16 16 0 0 1 21.16 0", "M8.53 16.11a6 6 0 0 1 6.95 0", "M12 20h.01"],
  monitor: ["M22 12h-2.5a2 2 0 0 0-1.9 1.5l-2.4 8.4a.25.25 0 0 1-.5 0L9.2 2.2a.25.25 0 0 0-.5 0l-2.3 8.3A2 2 0 0 1 4.5 12H2"],
  quarantine: ["M21 8v13H3V8", "M1 3h22v5H1z", "M10 12h4"],
  tools: ["M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"],
  history: ["M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8", "M3 3v5h5", "M12 7v5l4 2"],
  settings: ["M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"],
};

function icon(name: string): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  for (const d of TAB_ICONS[name] ?? []) {
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}
function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === "function") element.addEventListener(key.slice(2), value as EventListener);
    // Set through the CSSOM: the page's CSP (style-src 'self') blocks style attributes.
    else if (key === "style") element.style.cssText = String(value);
    // Live value of form fields (an attribute only sets the initial value).
    else if (key === "value" && "value" in element) (element as HTMLInputElement).value = String(value);
    else if (value === true) element.setAttribute(key, "");
    else if (value !== false && value !== undefined && value !== null) element.setAttribute(key, String(value));
  }
  for (const child of children) if (child) element.append(child);
  return element;
}

function date(iso?: string): string {
  return iso ? new Date(iso).toLocaleString(lang) : "";
}

function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

let toastTimer: number | undefined;

/** Shows a message; a newer message restarts the timer so it is never cut short. */
function flash(message: string, tone: "info" | "error" = "info") {
  const box = document.getElementById("toast")!;
  box.textContent = message;
  box.className = `toast ${tone}`;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (box.className = "toast hidden"), tone === "error" ? 7000 : 4500);
}

async function guard<T>(action: () => Promise<T>): Promise<T | undefined> {
  try {
    return await action();
  } catch (error) {
    flash(`${t.error} ${error instanceof Error ? error.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : String(error)}`, "error");
    return undefined;
  }
}

function verdictBadge(verdict: ScanResult["verdict"]) {
  return h("span", { class: `badge ${verdict}` }, t.verdicts[verdict]);
}

function resultRow(entry: Entry) {
  const serious = entry.verdict === "malicious" || entry.verdict === "suspicious";
  const actions = h("div", { class: "actions" });
  if (entry.quarantined) {
    actions.append(h("span", { class: "muted" }, t.actions.quarantined));
  } else if (serious || entry.verdict === "no_known_threat") {
    if (serious) {
      actions.append(
        h("button", {
          class: "danger",
          type: "button",
          onclick: async () => {
            const item = await guard(() => api.quarantineAdd(entry.path));
            if (item) {
              entry.quarantined = (item as QuarantineItem).id;
              await refresh();
            }
          },
        }, t.actions.quarantine),
      );
    }
    actions.append(
      h("button", {
        class: "secondary",
        type: "button",
        onclick: () => window.confirm(t.confirmFull) && guard(() => api.fullScan(entry.path)),
      }, t.actions.fullScan),
    );
  }
  return h(
    "li",
    { class: `result ${entry.verdict}`, "data-verdict": entry.verdict },
    h(
      "div",
      { class: "row" },
      verdictBadge(entry.verdict),
      h("strong", { class: "name", dir: "auto" }, entry.name),
      h("span", { class: "muted small" }, bytes(entry.size)),
    ),
    h("p", { class: "path muted small", dir: "ltr" }, entry.path),
    entry.error ? h("p", { class: "muted" }, entry.error) : null,
    entry.findings.length
      ? h(
          "ul",
          { class: "findings" },
          ...entry.findings.map((finding) => {
            const arabic = lang === "ar" ? FINDINGS_AR[finding.rule] : undefined;
            const title = arabic ? arabic.title + (finding.member ? ` (${finding.member})` : "") : finding.title;
            return h("li", { class: `finding ${finding.severity}` }, h("strong", { dir: "auto" }, title), h("span", { class: "muted", dir: "auto" }, arabic?.detail ?? finding.detail));
          }),
        )
      : null,
    h("div", { class: "row spread" }, h("span", { class: "muted small" }, entry.engines.join(" · ")), actions),
  );
}

function scanView() {
  const progress = h("p", { class: "muted", id: "progress", "aria-live": "polite" });
  const run = async (paths: Promise<string[]> | string[] | "quick") => {
    progress.textContent = "…";
    const totals =
      paths === "quick"
        ? await guard(() => api.quickScan())
        : await guard(async () => {
            const chosen = await paths;
            return chosen.length ? api.scan(chosen) : null;
          });
    if (totals) progress.textContent = t.scan.done(totals.scanned, totals.malicious + totals.suspicious);
    else progress.textContent = "";
  };
  const drop = h(
    "div",
    {
      class: "drop",
      tabindex: "0",
      ondragover: (event: DragEvent) => {
        event.preventDefault();
        drop.classList.add("over");
      },
      ondragleave: () => drop.classList.remove("over"),
      ondrop: (event: DragEvent) => {
        event.preventDefault();
        drop.classList.remove("over");
        const paths = [...(event.dataTransfer?.files ?? [])].map((file) => api.pathOf(file)).filter(Boolean);
        void run(paths);
      },
    },
    h("p", {}, t.scan.drop),
    h(
      "div",
      { class: "row center" },
      h("button", { type: "button", id: "choose-files", onclick: () => run(api.choose("files")) }, t.scan.files),
      h("button", { type: "button", class: "secondary", onclick: () => run(api.choose("folder")) }, t.scan.folder),
      h("button", { type: "button", class: "secondary", id: "quick-scan", onclick: () => run("quick") }, t.scan.quick),
    ),
  );
  const list = h("ul", { class: "results", id: "results" }, ...results.map(resultRow));
  return [
    h("h1", {}, t.scan.heading),
    h("p", { class: "muted" }, t.scan.intro),
    drop,
    progress,
    h("h2", {}, t.scan.results),
    results.length ? list : h("p", { class: "muted", id: "results-empty" }, t.scan.none),
  ];
}

function toggle(label: string, checked: boolean, onchange: (value: boolean) => void, hint?: string, id?: string) {
  return h(
    "label",
    { class: "toggle" },
    h("input", { type: "checkbox", checked, id, onchange: (event: Event) => onchange((event.target as HTMLInputElement).checked) }),
    h("span", {}, label, hint ? h("small", { class: "muted block" }, hint) : null),
  );
}

async function change(changes: Partial<DesktopSettings>) {
  const next = await guard(() => api.settings(changes));
  if (next) {
    status = next as Status;
    render();
  }
}

function wifiPanel() {
  const p = t.protection;
  const text = h("p", { id: "wifi-status", class: "muted" }, "…");
  void api.wifi().then((wifi: { ssid: string | null; security: string | null; risk: string }) => {
    const ssid = wifi.ssid ?? "?";
    text.textContent =
      wifi.risk === "open" ? p.wifiOpen(ssid)
      : wifi.risk === "weak" ? p.wifiWeak(ssid)
      : wifi.risk === "ok" ? p.wifiOk(ssid, wifi.security ?? "")
      : wifi.risk === "none" ? p.wifiNone
      : p.wifiUnknown;
    text.className = wifi.risk === "open" || wifi.risk === "weak" ? "warning-text" : "muted";
  });
  return h("section", { class: "panel" }, h("h2", {}, p.wifi), text);
}

function updatesPanel() {
  const p = t.protection;
  const list = h("div", { id: "updates" });
  const check = async () => {
    list.replaceChildren(h("p", { class: "muted" }, "…"));
    const result = (await api.updates()) as { updates: { name: string; current: string | null; available: string | null }[]; source: string } | null;
    if (!result) return list.replaceChildren(h("p", { class: "muted" }, p.updatesUnavailable));
    if (!result.updates.length) return list.replaceChildren(h("p", {}, p.upToDate));
    list.replaceChildren(
      h("p", { class: "warning-text" }, p.updatesCount(result.updates.length)),
      h("ul", { class: "folders" }, ...result.updates.slice(0, 50).map((u) => h("li", {}, h("code", {}, u.name), u.available ? h("span", { class: "muted small" }, ` → ${u.available}`) : null))),
    );
  };
  return h(
    "section",
    { class: "panel" },
    h("h2", {}, p.updates),
    h("p", { class: "muted" }, p.updatesHint),
    h("div", {}, h("button", { type: "button", class: "secondary", onclick: check }, p.checkUpdates)),
    list,
  );
}

interface HaltedProc { pid: number; reason: string; files: number; at: string }
let haltedProcs: HaltedProc[] = [];

function ransomwarePanel() {
  const k = t.ransomware;
  if (!haltedProcs.length) return null;
  return h(
    "section",
    { class: "panel danger", id: "ransomware-frozen" },
    h("h2", {}, k.frozen),
    ...haltedProcs.map((proc) =>
      h("div", { class: "item risky" },
        h("p", {}, k.frozenBody(proc.reason)),
        h("div", { class: "row spread" },
          h("code", { dir: "ltr" }, k.pid(proc.pid)),
          h("span", { class: "row" },
            h("button", { type: "button", class: "secondary", onclick: () => void resolveHalted(proc.pid, "resume") }, k.release),
            h("button", { type: "button", class: "danger", onclick: () => void resolveHalted(proc.pid, "kill") }, k.remove))))),
  );
}

async function resolveHalted(pid: number, action: "resume" | "kill") {
  const result = await guard(() => api.ransomwareResolve(pid, action) as Promise<{ ok?: boolean; error?: string }>);
  if (result?.error) { flash(result.error, "error"); return; }
  haltedProcs = haltedProcs.filter((p) => p.pid !== pid);
  void render();
}

interface CfaView { supported: boolean; state: "on" | "off" | "audit" | "unknown"; folders: string[]; allowedApps: string[] }
let cfaView: CfaView | null | undefined;

function cfaPanel() {
  const k = t.cfa;
  if (status.platform !== "win32") return null;
  if (cfaView === undefined) {
    cfaView = null;
    void guard(() => api.cfaStatus() as Promise<CfaView>).then((value) => { cfaView = value; if (tab === "protection") void render(); });
  }
  if (!cfaView || !cfaView.supported) return null;
  const on = cfaView.state === "on" || cfaView.state === "audit";
  const apply = async (action: string, path?: string) => {
    const next = await guard(() => api.cfaApply(action, path) as Promise<CfaView | { error: string }>);
    if (next && "error" in next) { flash(next.error, "error"); return; }
    if (next) { cfaView = next; void render(); }
  };
  const stateText = cfaView.state === "on" ? k.on : cfaView.state === "audit" ? k.audit : cfaView.state === "off" ? k.off : k.unknown;
  return h(
    "section",
    { class: "panel", id: "cfa" },
    h("h2", {}, k.heading),
    h("p", { class: "muted" }, k.intro),
    h("p", { id: "cfa-state" }, stateText),
    h("div", { class: "row" },
      h("button", { type: "button", class: on ? "secondary" : "", id: on ? "cfa-off" : "cfa-on", onclick: () => void apply(on ? "disable" : "enable") }, on ? k.turnOff : k.turnOn)),
    on ? h("h3", {}, k.foldersHeading) : null,
    on ? (cfaView.folders.length ? h("ul", { class: "folders" }, ...cfaView.folders.map((f) => h("li", {}, h("code", { dir: "ltr" }, f)))) : h("p", { class: "muted small" }, k.none)) : null,
    on ? h("button", { type: "button", class: "secondary", id: "cfa-add-folder", onclick: async () => { const path = await guard(() => api.cfaPickFolder() as Promise<string | null>); if (path) void apply("add-folder", path); } }, k.addFolder) : null,
  );
}

function protectionView() {
  const s = status.settings;
  const p = t.protection;
  const alert = ransomwareAlert ?? status.ransomwareAlert;
  if (status.platform === "linux" && !haltedProcs.length) void api.ransomwareHalted().then((list) => { const next = list as HaltedProc[]; if (next.length) { haltedProcs = next; if (tab === "protection") void render(); } });
  return [
    ransomwarePanel(),
    cfaPanel(),
    h("h1", {}, p.heading),
    alert
      ? h(
          "section",
          { class: "panel alert", role: "alert" },
          h("h2", {}, p.ransomwareAlert),
          ...alert.reasons.map((reason) => h("p", {}, reason)),
          h("p", { class: "muted small" }, alert.examples.join(" · ")),
          h("p", {}, h("strong", {}, p.ransomwareAdvice)),
        )
      : null,
    wifiPanel(),
    h(
      "section",
      { class: "panel" },
      toggle(p.watching, s.watchEnabled, (value) => change({ watchEnabled: value }), p.watchingHint, "watch-enabled"),
      h(
        "ul",
        { class: "folders" },
        ...s.watchFolders.map((folder) =>
          h(
            "li",
            { class: "row spread" },
            h("code", { dir: "ltr" }, folder),
            h("button", { type: "button", class: "link", onclick: () => change({ watchFolders: s.watchFolders.filter((f) => f !== folder) }) }, p.remove),
          ),
        ),
      ),
      h("button", { type: "button", class: "secondary", onclick: async () => { const next = await guard(() => api.addWatchFolder()); if (next) { status = next as Status; render(); } } }, p.addFolder),
      toggle(p.autoQuarantine, s.autoQuarantine, (value) => change({ autoQuarantine: value }), undefined, "auto-quarantine"),
    ),
    h(
      "section",
      { class: "panel" },
      h("h2", {}, p.engines),
      h(
        "p",
        { id: "signature-count" },
        status.signatures.count ? `${p.signatures(status.signatures.count)} · ${p.updated(date(status.signatures.updatedAt))}` : p.noSignatures,
      ),
      status.signatures.error ? h("p", { class: "muted small" }, status.signatures.error) : null,
      h("button", { type: "button", class: "secondary", onclick: async () => { const next = await guard(() => api.updateSignatures()); if (next) { status = next as Status; render(); } } }, p.update),
      h("p", {}, p.heuristics),
      h("p", {}, status.clamav.available ? p.clamOn(status.clamav.path ?? "") : p.clamOff),
    ),
    h(
      "section",
      { class: "panel" },
      toggle(p.ransomware, s.ransomwareWatch, (value) => change({ ransomwareWatch: value }), p.ransomwareHint, "ransomware-watch"),
      h(
        "ul",
        { class: "folders" },
        ...s.protectedFolders.map((folder) =>
          h(
            "li",
            { class: "row spread" },
            h("code", { dir: "ltr" }, folder),
            h("button", { type: "button", class: "link", onclick: () => change({ protectedFolders: s.protectedFolders.filter((f) => f !== folder) }) }, p.remove),
          ),
        ),
      ),
      h("button", { type: "button", class: "secondary", onclick: async () => { const next = await guard(() => api.addProtectedFolder()); if (next) { status = next as Status; render(); } } }, p.addFolder),
    ),
    morePanel(),
    status.platform === "linux" ? onAccessPanel() : null,
    status.platform !== "win32" ? terminalPanel() : null,
    updatesPanel(),
    vpnPanel(),
    h("section", { class: "panel subtle" }, h("h2", {}, p.limits), h("p", { class: "muted" }, p.limitsBody)),
  ];
}

/** Removable drives, decoys, silent mode and exclusions. */
function morePanel() {
  const s = status.settings;
  const p = t.protection;
  const setSilent = async (hours: number) => {
    const next = await guard(() => api.silent(hours));
    if (next) { status = next as Status; flash(hours ? p.silentOn : p.silentOff); void render(); }
  };
  const addExclusion = async (kind: "file" | "folder") => {
    const next = await guard(() => api.exclusionAdd(kind));
    if (next) { status = next as Status; void render(); }
  };
  return h(
    "section",
    { class: "panel", id: "more-protection" },
    h("h2", {}, p.more),
    toggle(p.removable, s.scanRemovable, (value) => change({ scanRemovable: value }), p.removableHint, "scan-removable"),
    toggle(p.decoys, s.ransomwareDecoys, (value) => change({ ransomwareDecoys: value }), p.decoysHint(status.decoys), "ransomware-decoys"),
    status.platform !== "win32" ? toggle(p.systemWatch, s.watchSystemChanges, (value) => change({ watchSystemChanges: value }), p.systemWatchHint, "watch-system") : null,
    h("h3", {}, p.silent),
    h("p", { class: "muted", id: "silent-state" }, status.silent && s.silentUntil ? p.silentUntil(date(s.silentUntil)) : p.silentHint),
    h(
      "div",
      { class: "row" },
      ...[1, 3, 8].map((hours) => h("button", { type: "button", class: "secondary", "data-silent": String(hours), onclick: () => void setSilent(hours) }, p.silentFor(hours))),
      status.silent ? h("button", { type: "button", class: "link", id: "silent-off", onclick: () => void setSilent(0) }, p.silentEnd) : null,
    ),
    h("h3", {}, p.exclusions),
    h("p", { class: "muted" }, p.exclusionsHint),
    s.exclusions.length
      ? h(
          "ul",
          { class: "folders", id: "exclusions" },
          ...s.exclusions.map((path) =>
            h("li", { class: "row spread" }, h("code", { dir: "ltr" }, path), h("button", { type: "button", class: "link", onclick: () => change({ exclusions: s.exclusions.filter((e) => e !== path) }) }, p.remove)),
          ),
        )
      : h("p", { class: "muted small", id: "exclusions" }, p.exclusionsNone),
    h("div", { class: "row" },
      h("button", { type: "button", class: "secondary", id: "exclude-folder", onclick: () => void addExclusion("folder") }, p.excludeFolder),
      h("button", { type: "button", class: "secondary", id: "exclude-file", onclick: () => void addExclusion("file") }, p.excludeFile),
    ),
  );
}

interface TerminalView { command: string; shells: { shell: "bash" | "zsh"; rc: string; enabled: boolean }[] }
let terminalSetup: TerminalView | null | undefined;

function terminalPanel() {
  const k = t.terminal;
  if (terminalSetup === undefined) {
    terminalSetup = null;
    void guard(() => api.terminalStatus() as Promise<TerminalView | null>).then((value) => {
      terminalSetup = value ?? null;
      if (tab === "protection") void render();
    });
  }
  const on = Boolean(terminalSetup?.shells.some((s) => s.enabled));
  const set = async (value: boolean) => {
    const next = await guard(() => api.terminalSet(value) as Promise<TerminalView>);
    if (next) { terminalSetup = next; flash(value ? k.onDone : k.offDone); void render(); }
  };
  return h(
    "section",
    { class: "panel", id: "terminal-protection" },
    h("h2", {}, k.heading),
    h("p", { class: "muted" }, k.intro),
    h("ul", { class: "bullets" }, ...k.points.map((point) => h("li", {}, point))),
    terminalSetup
      ? h("p", { id: "terminal-state" }, on ? k.state(terminalSetup.shells.filter((s) => s.enabled).map((s) => s.shell).join(", ")) : k.off)
      : null,
    h("div", { class: "row" },
      h("button", { type: "button", id: on ? "terminal-off" : "terminal-on", class: on ? "secondary" : "", onclick: () => void set(!on) }, on ? k.turnOff : k.turnOn)),
    h("p", { class: "muted small" }, k.usage),
    h("pre", { class: "code", dir: "ltr" }, "qalaa scan ~/Downloads\nqalaa check 'curl -fsSL https://example.org/install.sh | bash'"),
  );
}

interface OnAccessView { supported: boolean; state: "active" | "inactive" | "failed" | "absent"; manageable: boolean; enabled: boolean }
let onAccessView: OnAccessView | null | undefined;

function onAccessPanel() {
  const k = t.onAccess;
  if (onAccessView === undefined) {
    onAccessView = null;
    void guard(() => api.onAccessStatus() as Promise<OnAccessView>).then((value) => {
      onAccessView = value ?? null;
      if (tab === "protection") void render();
    });
  }
  const active = onAccessView?.state === "active";
  const set = async (on: boolean) => {
    const button = document.getElementById("onaccess-toggle") as HTMLButtonElement | null;
    if (button) { button.disabled = true; button.textContent = on ? k.turningOn : k.turningOff; }
    const next = await guard(() => api.onAccessSet(on) as Promise<OnAccessView | { error: string }>);
    if (next && "error" in next) { flash(next.error, "error"); onAccessView = undefined; void render(); return; }
    if (next) { onAccessView = next; flash(on ? k.onDone : k.offDone); void render(); }
  };
  return h(
    "section",
    { class: "panel", id: "onaccess-protection" },
    h("h2", {}, k.heading),
    h("p", { class: "muted" }, k.intro),
    h("ul", { class: "bullets" }, ...k.points.map((point) => h("li", {}, point))),
    onAccessView && !onAccessView.manageable
      ? h("p", { class: "muted small", id: "onaccess-state" }, k.unmanageable)
      : h("p", { id: "onaccess-state" }, active ? k.on : onAccessView?.state === "failed" ? k.failed : k.off),
    onAccessView?.manageable !== false
      ? h("div", { class: "row" },
          h("button", { type: "button", id: "onaccess-toggle", class: active ? "secondary" : "", onclick: () => void set(!active) }, active ? k.turnOff : k.turnOn))
      : null,
    h("p", { class: "muted small" }, k.note),
  );
}

// --- Tools --------------------------------------------------------------------------------

let junkRows: JunkRow[] | null = null;
let shredQueue: { path: string; refusal: string | null }[] = [];
let extensionRows: ExtensionRow[] | null = null;
let deepResult: DeepResult | null = null;
let blockedRows: string[] | null = null;

async function toolsView() {
  const k = t.tools;
  const list = (await guard(() => api.startupList() as Promise<{ active: StartupRow[]; disabled: DisabledRow[] }>)) ?? { active: [], disabled: [] };
  if (!list.active.length && !list.disabled.length) {
    await guard(() => api.securityCheck());
    Object.assign(list, (await guard(() => api.startupList() as Promise<{ active: StartupRow[]; disabled: DisabledRow[] }>)) ?? {});
  }
  const startup = h(
    "section",
    { class: "panel", id: "startup-manager" },
    h("h2", {}, k.startup),
    h("p", { class: "muted" }, k.startupHint),
    h(
      "ul",
      { class: "folders" },
      ...list.active.map((item) =>
        h("li", { class: item.warnings.length ? "item risky" : "item" },
          h("div", { class: "row spread" },
            h("strong", { dir: "auto" }, item.name),
            item.canSwitchOff
              ? h("button", { type: "button", class: "secondary small-button", "data-startup-off": item.id, onclick: async () => {
                  if (await guard(() => api.startupOff(item.id))) { flash(k.switchedOff(item.name)); void render(); }
                } }, k.switchOff)
              : h("span", { class: "muted small" }, k.needsAdmin)),
          h("code", { class: "block muted", dir: "ltr" }, item.command),
          ...item.warnings.map((warning) => h("span", { class: "warning-text block small" }, warning)))),
    ),
    list.disabled.length ? h("h3", {}, k.switchedOffList) : null,
    list.disabled.length
      ? h("ul", { class: "folders", id: "startup-disabled" },
          ...list.disabled.map((item) =>
            h("li", { class: "row spread" },
              h("span", {}, h("strong", { dir: "auto" }, item.name), h("span", { class: "muted small block" }, date(item.at))),
              h("button", { type: "button", class: "secondary small-button", "data-startup-on": item.id, onclick: async () => {
                if (await guard(() => api.startupOn(item.id))) { flash(k.switchedOn(item.name)); void render(); }
              } }, k.switchOn))))
      : null,
  );

  const junkTotal = (junkRows ?? []).reduce((sum, row) => sum + row.bytes, 0);
  const junk = h(
    "section",
    { class: "panel", id: "junk" },
    h("h2", {}, k.junk),
    h("p", { class: "muted" }, k.junkHint),
    junkRows
      ? h("ul", { class: "folders" },
          ...junkRows.map((row) => h("li", { class: "row spread" },
            h("label", { class: "check" }, h("input", { type: "checkbox", "data-junk": row.id, checked: row.bytes > 0 && row.id !== "trash" }), h("span", {}, k.junkNames[row.id as keyof typeof k.junkNames] ?? row.label)),
            h("span", { class: "muted" }, `${bytes(row.bytes)} · ${k.files(row.files)}`))))
      : null,
    h("div", { class: "row" },
      h("button", { type: "button", class: "secondary", id: "junk-measure", onclick: async () => {
        junkRows = (await guard(() => api.junkMeasure() as Promise<JunkRow[]>)) ?? null;
        void render();
      } }, junkRows ? k.measureAgain : k.measure),
      junkRows
        ? h("button", { type: "button", id: "junk-clean", disabled: junkTotal === 0, onclick: async () => {
            const ids = [...document.querySelectorAll<HTMLInputElement>("[data-junk]")].filter((box) => box.checked).map((box) => box.dataset.junk!);
            if (!ids.length || !window.confirm(k.confirmClean)) return;
            const done = await guard(() => api.junkClean(ids) as Promise<{ files: number; bytes: number; skipped: number }>);
            if (done) { flash(k.cleaned(done.files, bytes(done.bytes), done.skipped)); junkRows = (await guard(() => api.junkMeasure() as Promise<JunkRow[]>)) ?? null; void render(); }
          } }, k.clean)
        : null),
  );

  const shredder = h(
    "section",
    { class: "panel", id: "shredder" },
    h("h2", {}, k.shredder),
    h("p", { class: "muted" }, k.shredderHint),
    shredQueue.length
      ? h("ul", { class: "folders", id: "shred-queue" },
          ...shredQueue.map((item) => h("li", { class: "row spread" },
            h("code", { dir: "ltr" }, item.path),
            item.refusal ? h("span", { class: "warning-text small" }, item.refusal) : h("button", { type: "button", class: "link", onclick: () => { shredQueue = shredQueue.filter((q) => q !== item); void render(); } }, t.protection.remove))))
      : null,
    h("div", { class: "row" },
      h("button", { type: "button", class: "secondary", id: "shred-files", onclick: async () => { shredQueue = [...shredQueue, ...((await guard(() => api.pickPaths("file") as Promise<typeof shredQueue>)) ?? [])]; void render(); } }, k.addFiles),
      h("button", { type: "button", class: "secondary", id: "shred-folders", onclick: async () => { shredQueue = [...shredQueue, ...((await guard(() => api.pickPaths("folder") as Promise<typeof shredQueue>)) ?? [])]; void render(); } }, k.addFolders),
      shredQueue.some((q) => !q.refusal)
        ? h("button", { type: "button", class: "danger", id: "shred-go", onclick: async () => {
            const paths = shredQueue.filter((q) => !q.refusal).map((q) => q.path);
            if (!window.confirm(k.confirmShred(paths.length))) return;
            const done = await guard(() => api.shred(paths, 1) as Promise<{ files: number; bytes: number; refused: string[] }>);
            if (done) { flash(k.shredded(done.files)); shredQueue = []; void render(); }
          } }, k.shred)
        : null),
  );

  const extensions = h(
    "section",
    { class: "panel", id: "extensions" },
    h("h2", {}, k.extensions),
    h("p", { class: "muted" }, k.extensionsHint),
    extensionRows
      ? extensionRows.length
        ? h("ul", { class: "folders" },
            ...extensionRows.map((row) => h("li", { class: row.risk === "high" ? "item risky" : "item" },
              h("div", { class: "row spread" },
                h("span", {}, h("strong", { dir: "auto" }, row.name), h("span", { class: "muted small" }, ` ${row.browser} · ${row.version}${row.enabled ? "" : ` · ${k.disabled}`}`)),
                h("span", { class: `badge ${row.risk === "high" ? "malicious" : row.risk === "medium" ? "suspicious" : "no_known_threat"}` }, k.risk[row.risk])),
              row.reasons.length ? h("span", { class: "muted small block" }, row.reasons.join("; ")) : null)))
        : h("p", { class: "muted" }, k.noExtensions)
      : null,
    h("p", { class: "muted small" }, k.extensionsRemove),
    h("button", { type: "button", class: "secondary", id: "extensions-check", onclick: async () => { extensionRows = (await guard(() => api.extensions() as Promise<ExtensionRow[]>)) ?? null; void render(); } }, extensionRows ? k.checkAgain : k.check),
  );

  const deep = h(
    "section",
    { class: "panel", id: "deep" },
    h("h2", {}, k.deep),
    h("p", { class: "muted" }, k.deepHint),
    deepResult
      ? h("div", {},
          h("p", { id: "deep-summary" }, deepResult.findings.length ? k.deepFound(deepResult.findings.length) : k.deepNone, h("span", { class: "muted small block" }, `${k.deepChecked}: ${deepResult.checked.join(", ")} · ${date(deepResult.checkedAt)}`)),
          ...deepResult.findings.map((f) => h("div", { class: f.severity === "high" ? "item risky" : "item" }, h("strong", {}, `${f.area}: `), h("span", { dir: "auto" }, f.item), h("span", { class: "muted small block", dir: "auto" }, f.detail))))
      : null,
    h("button", { type: "button", class: "secondary", id: "deep-run", onclick: async (event: Event) => {
      const button = event.currentTarget as HTMLButtonElement;
      button.disabled = true;
      button.textContent = k.deepRunning;
      deepResult = (await guard(() => api.deepCheck() as Promise<DeepResult>)) ?? deepResult;
      void render();
    } }, deepResult ? k.checkAgain : k.deepRun),
  );

  if (status.firewallBlock && blockedRows === null) blockedRows = (await guard(() => api.firewallBlocked() as Promise<string[]>)) ?? [];
  const firewall = h(
    "section",
    { class: "panel", id: "blocked-programs" },
    h("h2", {}, k.firewall),
    h("p", { class: "muted" }, status.firewallBlock ? k.firewallHint : k.firewallLinux),
    status.firewallBlock
      ? h("div", {},
          (blockedRows ?? []).length
            ? h("ul", { class: "folders" }, ...(blockedRows ?? []).map((path) => h("li", { class: "row spread" }, h("code", { dir: "ltr" }, path),
                h("button", { type: "button", class: "link", onclick: async () => { blockedRows = (await guard(() => api.firewallUnblock(path) as Promise<string[]>)) ?? blockedRows; void render(); } }, k.unblock))))
            : h("p", { class: "muted small" }, k.noneBlocked),
          h("button", { type: "button", class: "secondary", onclick: async () => {
            const picked = (await guard(() => api.pickPaths("file") as Promise<{ path: string }[]>)) ?? [];
            for (const { path } of picked) blockedRows = (await guard(() => api.firewallBlock(path) as Promise<string[]>)) ?? blockedRows;
            void render();
          } }, k.blockProgram))
      : null,
  );

  return [h("h1", {}, k.heading), h("p", { class: "muted" }, k.intro), startup, deep, extensions, junk, shredder, firewall];
}

async function quarantineView() {
  const items = ((await api.quarantineList()) as QuarantineItem[]).slice().reverse();
  const q = t.quarantine;
  return [
    h("h1", {}, q.heading),
    h("p", { class: "muted" }, q.intro),
    items.length
      ? h(
          "ul",
          { class: "results", id: "quarantine" },
          ...items.map((item) =>
            h(
              "li",
              { class: `result ${item.verdict}` },
              h("div", { class: "row" }, verdictBadge(item.verdict), h("strong", { dir: "auto" }, item.name), h("span", { class: "muted small" }, date(item.quarantinedAt))),
              h("p", { class: "muted small", dir: "ltr" }, `${q.from}: ${item.originalPath}`),
              h("p", { dir: "auto" }, item.reason),
              h(
                "div",
                { class: "actions" },
                h("button", { type: "button", class: "secondary", onclick: async () => { const path = await guard(() => api.quarantineRestore(item.id)); if (path) { flash(String(path)); await refresh(); } } }, t.actions.restore),
                h("button", { type: "button", class: "danger", onclick: async () => { await guard(() => api.quarantineDelete(item.id)); await refresh(); } }, t.actions.delete),
              ),
            ),
          ),
        )
      : h("p", { class: "muted", id: "quarantine-empty" }, q.empty),
  ];
}

async function historyView() {
  const items = (await api.history()) as Entry[];
  return [
    h("h1", {}, t.history.heading),
    items.length ? h("ul", { class: "results" }, ...items.slice(0, 100).map(resultRow)) : h("p", { class: "muted" }, t.history.empty),
  ];
}

function settingsView() {
  const s = status.settings;
  const st = t.settings;
  const server = h("input", { type: "url", value: s.serverUrl, dir: "ltr", id: "server-url" });
  return [
    h("h1", {}, st.heading),
    h(
      "section",
      { class: "panel" },
      h("label", { for: "server-url" }, st.server),
      h("div", { class: "row" }, server, h("button", { type: "button", onclick: () => change({ serverUrl: server.value.trim() }).then(() => flash(st.saved)) }, st.save)),
      toggle(st.cloud, s.cloudLookup, (value) => change({ cloudLookup: value }), st.cloudHint),
      toggle(st.clam, s.useClamav, (value) => change({ useClamav: value })),
      h("label", { for: "language" }, st.language),
      h(
        "select",
        { id: "language", onchange: (event: Event) => change({ language: (event.target as HTMLSelectElement).value as DesktopSettings["language"] }) },
        ...[["auto", st.auto], ["en", "English"], ["ar", "العربية"]].map(([value, label]) => h("option", { value, selected: s.language === value }, label!)),
      ),
      h("label", { for: "theme" }, st.theme),
      h(
        "select",
        { id: "theme", onchange: (event: Event) => change({ theme: (event.target as HTMLSelectElement).value as DesktopSettings["theme"] }) },
        ...[["system", st.themeSystem], ["light", st.themeLight], ["dark", st.themeDark]].map(([value, label]) => h("option", { value, selected: s.theme === value }, label!)),
      ),
    ),
    accountPanel(),
    appUpdatesPanel(),
  ];
}

function updateText(update: UpdateView): string {
  const u = t.updates;
  switch (update.state) {
    case "checking": return u.checking;
    case "none": return u.none(date(update.checkedAt));
    case "available": return u.available(update.version);
    case "downloading": return u.downloading(update.percent);
    case "ready": return u.ready(update.version);
    case "manual": return update.reason === "development" ? u.development : u.packageManager(update.version);
    case "error": return u.error(update.message);
    default: return "";
  }
}

function appUpdatesPanel() {
  const u = t.updates;
  const s = status.settings;
  return h(
    "section",
    { class: "panel", id: "updates-panel" },
    h("h2", {}, u.heading),
    h("p", { class: "muted" }, u.version(status.version)),
    toggle(u.auto, s.autoUpdate, (value) => change({ autoUpdate: value }), u.autoHint, "auto-update"),
    h("p", { id: "update-state", "aria-live": "polite" }, updateText(status.update)),
    h(
      "div",
      { class: "row" },
      h("button", {
        type: "button",
        class: "secondary",
        id: "update-check",
        disabled: status.update.state === "checking" || status.update.state === "downloading",
        onclick: async () => {
          const next = await guard(() => api.updateCheck() as Promise<UpdateView>);
          if (next) {
            status = { ...status, update: next };
            void render();
          }
        },
      }, u.check),
      status.update.state === "ready" ? h("button", { type: "button", id: "update-install", onclick: () => api.updateInstall() }, u.restart) : null,
    ),
  );
}

function accountPanel() {
  const a = t.account;
  const s = status.settings;
  if (!status.account) {
    const code = h("input", { id: "link-code", dir: "ltr", autocomplete: "off", maxlength: 32, spellcheck: false });
    return h(
      "section",
      { class: "panel", id: "account" },
      h("h2", {}, a.heading),
      h("p", { class: "muted" }, a.intro),
      h("label", { for: "link-code" }, a.codeLabel),
      h(
        "div",
        { class: "row" },
        code,
        h("button", {
          type: "button",
          id: "link-button",
          onclick: async () => {
            const next = await guard(() => api.accountLink(code.value));
            if (next) {
              status = next as Status;
              flash(a.linked);
              void render();
            }
          },
        }, a.link),
      ),
      h("p", { class: "muted" }, a.codeHint),
    );
  }
  const name = h("input", { id: "device-name", value: s.deviceName, maxlength: 80 });
  return h(
    "section",
    { class: "panel", id: "account" },
    h("h2", {}, a.heading),
    h("p", { id: "linked-as" }, a.linkedAs(status.account.email)),
    h("label", { for: "device-name" }, a.name),
    h("div", { class: "row" }, name, h("button", { type: "button", onclick: () => change({ deviceName: name.value }).then(() => flash(t.settings.saved)) }, t.settings.save)),
    toggle(a.allowRemote, s.allowRemote, (value) => change({ allowRemote: value }), a.allowRemoteHint, "allow-remote"),
    status.remote.lastContact ? h("p", { class: "muted" }, a.lastContact(date(status.remote.lastContact))) : null,
    status.remote.lastError ? h("p", { class: "error", role: "status" }, status.remote.lastError) : null,
    h("button", {
      type: "button",
      class: "secondary",
      id: "unlink-button",
      onclick: async () => {
        if (!window.confirm(a.confirmUnlink)) return;
        const next = await guard(() => api.accountUnlink());
        if (next) {
          status = next as Status;
          void render();
        }
      },
    }, a.unlink),
  );
}

async function loadSecurity(force = false) {
  if (security && !force) return security;
  security = (await guard(() => api.securityCheck() as Promise<SecurityResult>)) ?? security;
  return security;
}

function securityPanels(sec: SecurityResult) {
  const c = t.security;
  const fw = sec.firewall;
  const fwText = { on: c.firewallOn, off: c.firewallOff, partial: c.firewallPartial, unknown: c.firewallUnknown }[fw.state];
  const firewall = h(
    "section",
    { class: "panel", id: "firewall" },
    h("h2", {}, c.firewall),
    h("p", { class: fw.state === "on" ? "good-text" : fw.state === "unknown" ? "muted" : "warning-text" }, fwText),
    fw.detail ? h("p", { class: "muted small" }, fw.detail) : null,
    fw.state !== "on" ? h("p", { class: "small" }, c.firewallHow[status.platform] ?? c.firewallHow.linux!) : null,
    fw.source ? h("p", { class: "muted small" }, c.from(fw.source)) : null,
  );

  const exposed = (sec.ports ?? []).filter((port) => port.exposed);
  const local = (sec.ports ?? []).length - exposed.length;
  const ports = h(
    "section",
    { class: "panel", id: "ports" },
    h("h2", {}, c.ports),
    h("p", { class: "muted" }, c.portsHint),
    sec.ports === null
      ? h("p", { class: "muted" }, c.portsUnknown)
      : exposed.length === 0
        ? h("p", { class: "good-text" }, c.portsNone)
        : h(
            "ul",
            { class: "folders" },
            ...exposed.map((port) =>
              h(
                "li",
                { class: port.risk ? "item risky" : "item" },
                h("span", {}, h("strong", {}, c.port(port.port)), " · ", h("span", { dir: port.process ? "ltr" : "auto" }, port.process ?? c.unknownProgram)),
                port.risk ? h("span", { class: "warning-text block small" }, port.risk) : null,
              ),
            ),
          ),
    local > 0 ? h("p", { class: "muted small" }, c.localOnly(local)) : null,
  );

  const anyNew = sec.startup.some((item) => item.isNew);
  const startup = h(
    "section",
    { class: "panel", id: "startup" },
    h("h2", {}, c.startup),
    h("p", { class: "muted" }, c.startupHint),
    sec.startup.length === 0
      ? h("p", { class: "muted" }, c.startupNone)
      : h(
          "ul",
          { class: "folders" },
          ...sec.startup
            .slice()
            .sort((a, b) => Number(b.isNew) - Number(a.isNew) || b.warnings.length - a.warnings.length)
            .map((item) =>
              h(
                "li",
                { class: item.warnings.length ? "item risky" : "item" },
                h(
                  "div",
                  { class: "row spread" },
                  h("span", {}, h("strong", { dir: "auto" }, item.name), item.isNew ? h("span", { class: "badge suspicious" }, c.startupNew) : null),
                  item.program
                    ? h("button", {
                        type: "button",
                        class: "secondary small-button",
                        onclick: async () => {
                          const result = await guard(() => api.scanProgram(item.id) as Promise<{ scanned: number; malicious: number; suspicious: number }>);
                          if (result) flash(t.scan.done(result.scanned, result.malicious + result.suspicious), result.malicious + result.suspicious ? "error" : "info");
                        },
                      }, c.scanProgram)
                    : null,
                ),
                h("code", { class: "block muted", dir: "ltr" }, item.command),
                h("span", { class: "muted small block", dir: "ltr" }, item.location),
                ...item.warnings.map((warning) => h("span", { class: "warning-text block small" }, warning)),
              ),
            ),
        ),
    anyNew
      ? h("button", {
          type: "button",
          class: "secondary",
          onclick: async () => {
            const next = await guard(() => api.startupAcknowledge() as Promise<SecurityResult>);
            if (next) {
              security = next;
              void render();
            }
          },
        }, c.startupReviewed)
      : null,
  );
  const enc = sec.encryption;
  const encryption = h(
    "section",
    { class: "panel", id: "encryption" },
    h("h2", {}, c.encryption),
    h(
      "p",
      { class: enc.state === "on" ? "good-text" : enc.state === "unknown" ? "muted" : "warning-text" },
      { on: c.encryptionOn, off: c.encryptionOff, partial: c.encryptionPartial, unknown: c.encryptionUnknown }[enc.state],
    ),
    enc.detail && enc.state !== "on" ? h("p", { class: "muted small" }, enc.detail) : null,
    enc.state === "off" || enc.state === "partial" ? h("p", { class: "small" }, c.encryptionHow[status.platform] ?? c.encryptionHow.linux!) : null,
    enc.source ? h("p", { class: "muted small" }, c.from(enc.source)) : null,
  );
  return [firewall, encryption, ports, startup];
}

function programsPanel() {
  const c = t.security;
  const report = processReport;
  const flagged = report?.programs.filter((p) => p.concerns.length || p.verdict === "malicious" || p.verdict === "suspicious") ?? [];
  return h(
    "section",
    { class: "panel", id: "programs" },
    h("h2", {}, c.programs),
    h("p", { class: "muted" }, c.programsHint),
    h("button", {
      type: "button",
      class: "secondary",
      id: "programs-check",
      disabled: processBusy,
      onclick: async () => {
        processBusy = true;
        void render();
        processReport = (await guard(() => api.processCheck() as Promise<ProcessReport>)) ?? processReport;
        processBusy = false;
        void render();
      },
    }, processBusy ? c.programsChecking : c.programsCheck),
    report && !report.supported ? h("p", { class: "muted" }, c.programsUnsupported) : null,
    report && report.supported
      ? h("p", { class: flagged.length ? "warning-text" : "good-text", id: "programs-summary" }, flagged.length ? c.programsSummary(report.programs.length, flagged.length) : c.programsAllClear(report.programs.length))
      : null,
    flagged.length
      ? h(
          "ul",
          { class: "folders" },
          ...flagged.map((program) =>
            h(
              "li",
              { class: "item risky" },
              h("span", {}, h("strong", { dir: "auto" }, program.name), program.verdict === "malicious" || program.verdict === "suspicious" ? " " : null, program.verdict === "malicious" || program.verdict === "suspicious" ? verdictBadge(program.verdict) : null),
              h("code", { class: "block muted", dir: "ltr" }, program.path),
              program.title ? h("span", { class: "warning-text block small" }, program.title) : null,
              ...program.concerns.map((concern) => h("span", { class: "warning-text block small" }, c.concern[concern] ?? concern)),
              h("span", { class: "muted small block" }, c.processIds(program.pids.join(", "))),
            ),
          ),
        )
      : null,
    report && report.unreadable ? h("p", { class: "muted small" }, c.programsHidden(report.unreadable)) : null,
    report ? h("p", { class: "muted small" }, c.checkedAt(date(report.checkedAt))) : null,
  );
}

function browsingPanel() {
  const c = t.security;
  const report = browsingReport;
  const days = 30;
  const visits = report?.browsers.reduce((sum, b) => sum + b.visits, 0) ?? 0;
  return h(
    "section",
    { class: "panel", id: "browsing" },
    h("h2", {}, c.browsing),
    h("p", { class: "muted" }, c.browsingHint),
    h("button", {
      type: "button",
      class: "secondary",
      id: "browsing-check",
      disabled: browsingBusy,
      onclick: async () => {
        browsingBusy = true;
        void render();
        browsingReport = (await guard(() => api.historyCheck(days) as Promise<BrowsingReport>)) ?? browsingReport;
        browsingBusy = false;
        void render();
      },
    }, browsingBusy ? c.browsingChecking : c.browsingCheck(days)),
    report && report.browsers.length === 0 ? h("p", { class: "muted" }, c.browsingNoBrowsers) : null,
    report && report.browsers.length > 0
      ? h("p", { class: report.matches.length ? "warning-text" : "good-text", id: "browsing-summary" }, report.matches.length ? c.browsingFound(report.matches.length) : c.browsingNone(visits, report.days))
      : null,
    report && report.matches.length
      ? h(
          "ul",
          { class: "folders" },
          ...report.matches.map((match) =>
            h(
              "li",
              { class: "item risky" },
              h("strong", { dir: "ltr" }, match.host),
              h("span", { class: "muted small block" }, `${match.browser} · ${match.reason === "url" ? c.browsingExact : c.browsingDomain}${match.visitedAt ? ` · ${date(match.visitedAt)}` : ""}`),
              h("code", { class: "block muted", dir: "ltr" }, match.url),
            ),
          ),
        )
      : null,
    ...(report?.browsers.filter((b) => b.error).map((b) => h("p", { class: "muted small" }, c.browsingError(b.browser, b.error!))) ?? []),
  );
}

function vpnPanel() {
  const c = t.security;
  const view = vpnView;
  const act = (action: () => Promise<unknown>) => async () => {
    vpnBusy = true;
    void render();
    vpnView = ((await guard(action)) as VpnView | undefined) ?? vpnView;
    vpnBusy = false;
    void render();
  };
  const body: (Node | null)[] = [];
  // Refresh on every visit (linking or unlinking the account changes it); redraw only on a change.
  if (!vpnBusy) {
    void api.vpnStatus().then((next) => {
      if (JSON.stringify(next) === JSON.stringify(vpnView)) return;
      vpnView = next as VpnView;
      if (tab === "protection") void render();
    });
  }
  if (!view) {
    // waiting for the first answer
  } else if (!view.linked) {
    body.push(h("p", { class: "muted" }, c.vpnNeedsAccount));
  } else if (!view.saved) {
    body.push(h("button", { type: "button", id: "vpn-setup", disabled: vpnBusy, onclick: act(() => api.vpnSetup()) }, vpnBusy ? c.vpnSettingUp : c.vpnSetup));
  } else if (view.state === "connected" || view.state === "disconnected") {
    const on = view.state === "connected";
    body.push(
      h("p", { class: on ? "good-text" : "muted", id: "vpn-state" }, on ? c.vpnConnected : c.vpnDisconnected),
      h("button", { type: "button", id: "vpn-toggle", class: on ? "secondary" : "", disabled: vpnBusy, onclick: act(() => (on ? api.vpnDisconnect() : api.vpnConnect())) }, on ? c.vpnDisconnect : c.vpnConnect),
    );
  } else {
    body.push(
      h("p", { class: "small" }, view.platform === "linux" ? c.vpnNoNetworkManager : c.vpnManual),
      h("button", { type: "button", class: "secondary", onclick: () => void api.vpnShowFile() }, c.vpnShowFile),
    );
  }
  if (view?.saved) body.push(h("p", { class: "muted small" }, c.vpnLimitNote));
  if (view?.saved && view.guard?.capable) body.push(vpnGuardPanel(view.guard));
  return h("section", { class: "panel", id: "vpn" }, h("h2", {}, c.vpn), h("p", { class: "muted" }, c.vpnHint), ...body);
}

function vpnGuardPanel(g: VpnGuard) {
  const k = t.vpnGuard;
  const setGuard = async (changes: Record<string, unknown>) => {
    const next = await guard(() => api.vpnGuardSet(changes) as Promise<VpnGuard>);
    if (next && vpnView) { vpnView = { ...vpnView, guard: next }; void render(); }
  };
  const setKill = async (on: boolean) => {
    const button = document.getElementById("vpn-kill-toggle") as HTMLButtonElement | null;
    if (button) button.disabled = true;
    const next = await guard(() => api.vpnKillSwitchSet(on) as Promise<VpnGuard | { error: string }>);
    if (next && "error" in next) { flash(next.error, "error"); void render(); return; }
    if (next && vpnView) { vpnView = { ...vpnView, guard: next }; flash(on ? k.killOnDone : k.killOffDone); void render(); }
  };
  return h(
    "div",
    { class: "subpanel", id: "vpn-guard" },
    h("h3", {}, k.heading),
    // Kill switch
    h("p", { id: "vpn-kill-state" }, g.killSwitch ? k.killOn : k.killOff),
    h("p", { class: "muted small" }, k.killHint),
    h("div", { class: "row" },
      h("button", { type: "button", id: "vpn-kill-toggle", class: g.killSwitch ? "secondary" : "", onclick: () => void setKill(!g.killSwitch) }, g.killSwitch ? k.killTurnOff : k.killTurnOn)),
    g.killSwitch ? toggle(k.allowLan, g.allowLan, (value) => void setGuard({ allowLan: value }), k.allowLanHint, "vpn-allow-lan") : null,
    // Split tunnelling
    h("h3", {}, k.split),
    select("vpn-split-mode", k.splitMode, g.splitMode, [["full", k.splitFull], ["exclude", k.splitExclude], ["only", k.splitOnly]] as ["full" | "exclude" | "only", string][], (value) => void setGuard({ splitMode: value })),
    g.splitMode !== "full"
      ? h("div", {},
          h("p", { class: "muted small" }, k.splitCidrsHint),
          g.splitCidrs.length
            ? h("ul", { class: "folders", id: "vpn-split-cidrs" }, ...g.splitCidrs.map((cidr) =>
                h("li", { class: "row spread" }, h("code", { dir: "ltr" }, cidr),
                  h("button", { type: "button", class: "link", onclick: () => void setGuard({ splitCidrs: g.splitCidrs.filter((x) => x !== cidr) }) }, t.protection.remove))))
            : h("p", { class: "muted small" }, k.splitNone),
          h("div", { class: "row" },
            h("input", { type: "text", id: "vpn-cidr-input", placeholder: "192.168.1.0/24", dir: "ltr" }),
            h("button", { type: "button", class: "secondary", onclick: () => {
              const input = document.getElementById("vpn-cidr-input") as HTMLInputElement | null;
              const value = input?.value.trim();
              if (value && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(value)) void setGuard({ splitCidrs: [...g.splitCidrs, value] });
              else flash(k.cidrInvalid, "error");
            } }, k.addCidr)))
      : null,
    // Auto-connect on untrusted Wi-Fi
    h("h3", {}, k.auto),
    toggle(k.autoToggle, g.autoConnect, (value) => void setGuard({ autoConnect: value }), k.autoHint, "vpn-autoconnect"),
    g.autoConnect
      ? h("div", {},
          h("p", { class: "muted small" }, k.trustedHint),
          g.trusted.length
            ? h("ul", { class: "folders", id: "vpn-trusted" }, ...g.trusted.map((ssid) =>
                h("li", { class: "row spread" }, h("span", { dir: "auto" }, ssid),
                  h("button", { type: "button", class: "link", onclick: () => void setGuard({ trusted: g.trusted.filter((x) => x !== ssid) }) }, t.protection.remove))))
            : h("p", { class: "muted small" }, k.trustedNone),
          h("div", { class: "row" },
            h("input", { type: "text", id: "vpn-ssid-input", dir: "auto", placeholder: k.ssidPlaceholder }),
            h("button", { type: "button", class: "secondary", onclick: () => {
              const input = document.getElementById("vpn-ssid-input") as HTMLInputElement | null;
              const value = input?.value.trim();
              if (value) void setGuard({ trusted: [...g.trusted, value] });
            } }, k.addTrusted)))
      : null,
  );
}

function privacyPanel(sec: SecurityResult | null) {
  const c = t.security;
  const s = status.settings;
  if (!status.privacyWatchSupported) return h("section", { class: "panel", id: "privacy" }, h("h2", {}, c.privacy), h("p", { class: "muted" }, c.privacyMac));
  const use = sec?.deviceUse;
  const word = (device: "camera" | "microphone") => (device === "camera" ? c.camera : c.microphone);
  return h(
    "section",
    { class: "panel", id: "privacy" },
    h("h2", {}, c.privacy),
    toggle(c.privacyToggle, s.privacyWatch, (value) => change({ privacyWatch: value }), c.privacyHint, "privacy-watch"),
    use && use.unsupported.includes("microphone") ? h("p", { class: "muted small" }, c.privacyMicUnsupported) : null,
    use
      ? use.uses.length
        ? h("ul", { class: "folders", id: "device-uses" }, ...use.uses.map((u) => h("li", { class: "warning-text" }, c.inUse(word(u.device), u.app))))
        : h("p", { class: "muted" }, c.nothingInUse)
      : null,
    use && use.log.length
      ? h("details", {}, h("summary", {}, c.recent), h("ul", { class: "folders small" }, ...use.log.map((entry) => h("li", {}, `${date(entry.at)} · ${c.inUse(word(entry.device), entry.app)}`))))
      : null,
  );
}

function select<T extends string | number>(id: string, label: string, value: T, options: [T, string][], onchange: (value: T) => void, disabled = false) {
  return h(
    "label",
    { class: "field", for: id },
    h("span", { class: "small muted block" }, label),
    h(
      "select",
      {
        id,
        disabled,
        onchange: (event: Event) => {
          const raw = (event.target as HTMLSelectElement).value;
          const match = options.find(([option]) => String(option) === raw);
          if (match) onchange(match[0]);
        },
      },
      ...options.map(([option, text]) => h("option", { value: String(option), selected: option === value }, text)),
    ),
  );
}

function scheduleFields(prefix: string, schedule: DesktopSettings["scanSchedule"], save: (next: DesktopSettings["scanSchedule"]) => void) {
  const c = t.security;
  const off = schedule.frequency === "off";
  return h(
    "div",
    { class: "row" },
    select(`${prefix}-frequency`, c.frequency, schedule.frequency, [["off", c.off], ["daily", c.daily], ["weekly", c.weekly]], (frequency) => save({ ...schedule, frequency })),
    schedule.frequency === "weekly" ? select(`${prefix}-day`, c.day, schedule.day, c.days.map((name, index) => [index, name] as [number, string]), (day) => save({ ...schedule, day })) : null,
    select(`${prefix}-hour`, c.hour, schedule.hour, Array.from({ length: 24 }, (_, hour) => [hour, `${String(hour).padStart(2, "0")}:00`] as [number, string]), (hour) => save({ ...schedule, hour }), off),
  );
}

function schedulePanel() {
  const c = t.security;
  const s = status.settings;
  return h(
    "section",
    { class: "panel", id: "schedule" },
    h("h2", {}, c.schedule),
    scheduleFields("scan", s.scanSchedule, (scanSchedule) => change({ scanSchedule })),
    s.scanSchedule.frequency !== "off"
      ? h("div", { class: "row" }, select("scan-kind", c.kind, s.scheduledScanKind, [["quick", c.quick], ["full", c.full]], (scheduledScanKind) => change({ scheduledScanKind })))
      : null,
    status.schedule.nextScan && s.scanSchedule.frequency !== "off" ? h("p", { class: "muted small" }, c.next(date(status.schedule.nextScan))) : null,
  );
}

function backupPanel() {
  const c = t.security;
  const s = status.settings;
  const refresh = (next: unknown) => {
    if (next) {
      status = next as Status;
      void render();
    }
  };
  const password = h("input", { type: "password", id: "backup-password", autocomplete: "new-password", minlength: 10 });
  const openPassword = h("input", { type: "password", id: "open-password", autocomplete: "off" });
  const progress = h("p", { id: "backup-progress", class: "muted small", "aria-live": "polite" }, backupProgress ? c.backingUp(backupProgress.files, backupProgress.current ?? "") : "");
  const open = async (mode: "verify" | "restore") => {
    const result = await guard(() => api.backupOpen(mode, openPassword.value) as Promise<{ files: number; created: string; restoredTo: string | null } | null>);
    if (result) flash(mode === "restore" ? c.restored(result.files) : c.verified(result.files, date(result.created)));
  };
  return h(
    "section",
    { class: "panel", id: "backup" },
    h("h2", {}, c.backup),
    h("p", { class: "muted" }, c.backupHint),
    h("h3", {}, c.backupFolders),
    h(
      "ul",
      { class: "folders", id: "backup-folders" },
      ...s.backupFolders.map((folder) =>
        h("li", { class: "row spread" }, h("code", { dir: "ltr" }, folder), h("button", { type: "button", class: "link", onclick: async () => refresh(await guard(() => api.backupRemoveFolder(folder))) }, c.remove)),
      ),
    ),
    h("div", {}, h("button", { type: "button", class: "secondary", id: "backup-add-folder", onclick: async () => refresh(await guard(() => api.backupAddFolder())) }, c.addFolder)),
    h("h3", {}, c.destination),
    h(
      "div",
      { class: "row" },
      h("code", { dir: "ltr", id: "backup-destination" }, s.backupDestination ?? c.noDestination),
      h("button", { type: "button", class: "secondary", onclick: async () => refresh(await guard(() => api.backupDestination())) }, c.chooseDestination),
    ),
    h("h3", {}, c.password),
    status.backup.hasPassword ? h("p", { class: "good-text small" }, `${c.passwordSet} ${status.backup.keychain ? c.passwordKeychain : c.passwordSession}`) : null,
    h(
      "div",
      { class: "row" },
      password,
      h("button", {
        type: "button",
        class: "secondary",
        id: "backup-save-password",
        onclick: async () => {
          const saved = await guard(() => api.backupPassword(password.value));
          if (saved) {
            flash(c.passwordSaved);
            refresh(await api.status());
          }
        },
      }, c.savePassword),
    ),
    h("p", { class: "muted small" }, c.passwordHint),
    scheduleFields("backup", s.backupSchedule, (backupSchedule) => change({ backupSchedule })),
    h("div", { class: "row" }, select("backup-keep", c.keep, s.backupKeep, [1, 3, 5, 10, 20].map((n) => [n, String(n)] as [number, string]), (backupKeep) => change({ backupKeep }))),
    status.schedule.nextBackup && s.backupSchedule.frequency !== "off" ? h("p", { class: "muted small" }, c.next(date(status.schedule.nextBackup))) : null,
    h(
      "div",
      { class: "row" },
      h("button", {
        type: "button",
        id: "backup-now",
        disabled: status.backup.running || !s.backupFolders.length || !s.backupDestination || !status.backup.hasPassword,
        onclick: async () => {
          const summary = await guard(() => api.backupRun() as Promise<{ files: number; skipped: string[] }>);
          if (summary) flash(`${c.backupDone(summary.files)}${summary.skipped.length ? ` ${c.skipped(summary.skipped.length)}` : ""}`);
          refresh(await api.status());
        },
      }, c.backupNow),
    ),
    progress,
    h("p", { id: "last-backup" }, s.lastBackup ? c.lastBackup(date(s.lastBackup.at), s.lastBackup.files, bytes(s.lastBackup.bytes)) : c.noBackup),
    s.lastBackupError ? h("p", { class: "error" }, s.lastBackupError) : null,
    h(
      "details",
      {},
      h("summary", {}, c.open),
      h("p", { class: "muted small" }, c.openHint),
      h("label", { for: "open-password" }, c.openPassword),
      h(
        "div",
        { class: "row" },
        openPassword,
        h("button", { type: "button", class: "secondary", onclick: () => open("verify") }, c.verify),
        h("button", { type: "button", class: "secondary", onclick: () => open("restore") }, c.restore),
      ),
    ),
  );
}

// --- System monitor ------------------------------------------------------------------

/** A small line chart of the last readings (0..max). */
function sparkline(series: number[][], max: number): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", "0 0 100 40");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("aria-hidden", "true");
  series.forEach((values, index) => {
    if (values.length < 2) return;
    const top = Math.max(max, 1);
    const points = values.map((v, i) => `${(i / (values.length - 1)) * 100},${40 - (Math.min(v, top) / top) * 38}`);
    if (index === 0) {
      const area = document.createElementNS(SVG, "polygon");
      area.setAttribute("points", `0,40 ${points.join(" ")} 100,40`);
      svg.append(area);
    }
    const line = document.createElementNS(SVG, "polyline");
    line.setAttribute("points", points.join(" "));
    if (index > 0) line.setAttribute("class", "second");
    svg.append(line);
  });
  return svg;
}

function meter(fraction: number) {
  const pct = Math.max(0, Math.min(100, Math.round(fraction * 100)));
  return h("div", { class: `meter${pct >= 95 ? " full" : pct >= 80 ? " high" : ""}`, role: "img", "aria-label": `${pct}%` }, h("span", { style: `width:${pct}%` }));
}

function duration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d ? `${d}d ${hours}h` : hours ? `${hours}h ${m}m` : `${m}m`;
}

function liveCards(): Node[] {
  const m = t.monitor;
  const last = monitorSamples[monitorSamples.length - 1];
  if (!last) return [h("p", { class: "muted" }, "…")];
  const pick = (f: (s: MonitorSnapshot) => number) => monitorSamples.map(f);
  const card = (id: string, title: string, ...children: Child[]) => h("section", { class: "panel", id }, h("h2", {}, title), ...children);
  const cards: Node[] = [];
  const mhz = last.cpu.speedMhz.filter(Boolean);
  cards.push(
    card(
      "monitor-cpu",
      m.cpu,
      h("div", { class: "big" }, `${Math.round(last.cpu.total)}%`),
      sparkline([pick((s) => s.cpu.total)], 100),
      h("div", { class: "cores", title: m.cores }, ...last.cpu.cores.map((v) => h("span", { style: `height:${Math.max(2, v)}%`, title: `${v}%` }))),
      h("span", { class: "muted small" }, [last.cpu.model, mhz.length ? `${Math.round(Math.max(...mhz))} MHz` : null, last.cpu.temperature !== null ? m.temperature(last.cpu.temperature) : null].filter(Boolean).join(" · ")),
      last.load ? h("span", { class: "muted small" }, `${m.load(last.load.join(" / "))} · ${m.uptime(duration(last.uptimeSeconds))}`) : h("span", { class: "muted small" }, m.uptime(duration(last.uptimeSeconds))),
    ),
  );
  cards.push(
    card(
      "monitor-memory",
      m.memory,
      h("div", { class: "big" }, `${Math.round((last.memory.used / last.memory.total) * 100)}%`),
      sparkline([pick((s) => (s.memory.used / s.memory.total) * 100)], 100),
      h("span", { class: "muted small" }, m.of(bytes(last.memory.used), bytes(last.memory.total))),
      last.swap ? h("span", { class: "muted small" }, m.swap(bytes(last.swap.used), bytes(last.swap.total))) : null,
    ),
  );
  cards.push(
    card(
      "monitor-gpu",
      m.gpu,
      ...(last.gpus.length
        ? last.gpus.flatMap((gpu) => [
            h("div", { class: "big" }, gpu.utilization !== null ? `${Math.round(gpu.utilization)}%` : "—"),
            gpu.utilization !== null ? meter(gpu.utilization / 100) : null,
            h("span", { class: "muted small" }, [gpu.name, gpu.memoryUsed !== null ? (gpu.memoryTotal ? m.of(bytes(gpu.memoryUsed), bytes(gpu.memoryTotal)) : m.vram(bytes(gpu.memoryUsed))) : null, gpu.temperature !== null ? m.temperature(gpu.temperature) : null].filter(Boolean).join(" · ")),
          ])
        : [h("p", { class: "muted" }, m.unavailable)]),
    ),
  );
  const disk = last.disk;
  cards.push(
    card(
      "monitor-disk",
      m.disk,
      disk ? h("div", { class: "big" }, `${bytes(disk.readPerSec + disk.writePerSec)}/s`) : h("p", { class: "muted" }, m.unavailable),
      disk ? sparkline([pick((s) => s.disk?.readPerSec ?? 0), pick((s) => s.disk?.writePerSec ?? 0)], Math.max(1, ...pick((s) => Math.max(s.disk?.readPerSec ?? 0, s.disk?.writePerSec ?? 0)))) : null,
      disk ? h("span", { class: "muted small" }, `${m.read(bytes(disk.readPerSec))} · ${m.write(bytes(disk.writePerSec))} · ${m.iops(disk.iops)}`) : null,
      disk?.size ? meter((disk.used ?? 0) / disk.size) : null,
      disk?.size ? h("span", { class: "muted small" }, m.space(bytes(disk.used ?? 0), bytes(disk.size))) : null,
    ),
  );
  const net = last.network;
  cards.push(
    card(
      "monitor-network",
      m.network,
      net ? h("div", { class: "big" }, `${bytes(net.rxPerSec + net.txPerSec)}/s`) : h("p", { class: "muted" }, m.unavailable),
      net ? sparkline([pick((s) => s.network?.rxPerSec ?? 0), pick((s) => s.network?.txPerSec ?? 0)], Math.max(1, ...pick((s) => Math.max(s.network?.rxPerSec ?? 0, s.network?.txPerSec ?? 0)))) : null,
      net ? h("span", { class: "muted small" }, `${m.down(bytes(net.rxPerSec))} · ${m.up(bytes(net.txPerSec))}`) : null,
    ),
  );
  return cards;
}

function isExternal(remote: string | null): boolean {
  if (!remote) return false;
  const host = remote.replace(/^\[|\](?=:)/g, "").replace(/:\d+$/, "");
  return !/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|fc|fd|0\.0\.0\.0|::$|\*)/i.test(host);
}

function table(headers: string[], rows: Node[]) {
  return h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ...headers.map((name) => h("th", { scope: "col" }, name)))), h("tbody", {}, ...rows)));
}

function paneControls(onRefresh: () => void, extra: Child) {
  const m = t.monitor;
  return h(
    "div",
    { class: "row" },
    h("input", { type: "search", id: "monitor-filter", placeholder: m.filter, "aria-label": m.filter, value: monitorFilter, oninput: (event: Event) => { monitorFilter = (event.target as HTMLInputElement).value; void renderPane(); } }),
    extra,
    h("button", { type: "button", class: "secondary", onclick: onRefresh }, m.refresh),
  );
}

function matches(...fields: (string | null | number)[]): boolean {
  const q = monitorFilter.trim().toLowerCase();
  return !q || fields.some((f) => String(f ?? "").toLowerCase().includes(q));
}

async function renderPane() {
  const box = document.getElementById("monitor-pane");
  if (!box) return;
  const m = t.monitor;
  const nodes: (Node | null)[] = [];
  if (monitorPane === "processes") {
    if (monitorProcesses === undefined) monitorProcesses = (await guard(() => api.explorerList() as Promise<ProcessRow[] | null>)) ?? null;
    const all = monitorProcesses ?? [];
    const byPid = new Map(all.map((p) => [p.pid, p]));
    const children = new Map<number | null, ProcessRow[]>();
    for (const p of all) {
      const parent = p.ppid !== null && byPid.has(p.ppid) ? p.ppid : null;
      children.set(parent, [...(children.get(parent) ?? []), p]);
    }
    const ordered: { p: ProcessRow; depth: number }[] = [];
    const walkTree = (parent: number | null, depth: number) => {
      for (const p of (children.get(parent) ?? []).sort((a, b) => a.pid - b.pid)) {
        ordered.push({ p, depth });
        if (depth < 24) walkTree(p.pid, depth + 1);
      }
    };
    walkTree(null, 0);
    const filtering = monitorFilter.trim() !== "";
    const shown = filtering ? ordered.filter(({ p }) => matches(p.name, p.pid, p.user, p.path, p.commandLine)).map(({ p }) => ({ p, depth: 0 })) : ordered;
    const act = (p: ProcessRow, action: "end" | "suspend" | "resume", label: string) =>
      h("button", { type: "button", class: action === "end" ? "secondary small-button danger-text" : "secondary small-button", onclick: async () => {
        if (action !== "resume" && !window.confirm(m.confirmProcess(label, p.name, p.pid))) return;
        const ok = await guard(() => api.explorerControl(p.pid, action, p.name));
        if (!ok) return;
        if (action === "suspend") suspended.add(p.pid); else suspended.delete(p.pid);
        if (action === "end") monitorProcesses = undefined;
        flash(m.processDone(label, p.name));
        void renderPane();
      } }, label);
    const rows: Node[] = [];
    for (const { p, depth } of shown.slice(0, 600)) {
      const info = inspected.get(p.pid);
      rows.push(h("tr", { class: suspended.has(p.pid) ? "flag" : "" },
        h("td", { dir: "auto" }, h("span", { class: "tree", style: `padding-inline-start:${depth * 14}px` }, depth ? "└ " : "", h("strong", {}, p.name)), p.user ? h("span", { class: "muted block small" }, p.user) : null),
        h("td", { class: "num" }, String(p.pid)),
        h("td", { class: "num" }, p.memoryBytes !== null ? bytes(p.memoryBytes) : "—"),
        h("td", { class: "num" }, p.threads === null ? "—" : String(p.threads)),
        h("td", { class: "num" }, p.handles === null ? "—" : String(p.handles)),
        h("td", {}, h("div", { class: "actions" },
          h("button", { type: "button", class: "secondary small-button", "aria-expanded": info ? "true" : "false", onclick: async () => {
            if (inspected.has(p.pid)) { inspected.delete(p.pid); void renderPane(); return; }
            if (!p.path) { inspected.set(p.pid, { sha256: null, signature: { status: "unknown", signer: null, detail: m.noPath } }); void renderPane(); return; }
            inspected.set(p.pid, "loading"); void renderPane();
            const result = await guard(() => api.explorerInspect(p.path!) as Promise<Inspection>);
            if (result) inspected.set(p.pid, result); else inspected.delete(p.pid);
            void renderPane();
          } }, m.inspect),
          status.platform !== "win32" ? (suspended.has(p.pid) ? act(p, "resume", m.resume) : act(p, "suspend", m.suspend)) : null,
          status.firewallBlock && p.path
            ? h("button", { type: "button", class: "secondary small-button", onclick: async () => {
                if (!window.confirm(t.tools.confirmBlock(p.name))) return;
                const next = await guard(() => api.firewallBlock(p.path!) as Promise<string[]>);
                if (next) { blockedRows = next; flash(t.tools.blocked(p.name)); }
              } }, t.tools.blockShort)
            : null,
          act(p, "end", m.end)))));
      if (info) {
        const sig = info === "loading" ? null : info.signature;
        rows.push(h("tr", { class: "detail" }, h("td", { colspan: "6" }, h("dl", { class: "facts" },
          h("dt", {}, m.path), h("dd", {}, p.path ? h("code", { dir: "ltr" }, p.path) : "—",
            p.path ? h("button", { type: "button", class: "link-quiet", onclick: () => void navigator.clipboard.writeText(p.path!).then(() => flash(m.copied)) }, m.copy) : null,
            p.path ? h("button", { type: "button", class: "link-quiet", onclick: () => void api.revealPath(p.path!) }, m.openFolder) : null),
          h("dt", {}, m.commandLine), h("dd", {}, p.commandLine ? h("code", { dir: "ltr" }, p.commandLine) : "—"),
          h("dt", {}, "SHA-256"), h("dd", {}, info === "loading" ? m.working : info.sha256 ? h("code", { dir: "ltr" }, info.sha256) : "—",
            info !== "loading" && info.sha256 ? h("button", { type: "button", class: "link-quiet", onclick: () => void navigator.clipboard.writeText(info.sha256!).then(() => flash(m.copied)) }, m.copy) : null),
          h("dt", {}, m.signature), h("dd", {}, info === "loading" || !sig ? m.working : h("span", { class: `sig sig-${sig.status}` }, m.signatureStates[sig.status] ?? sig.status, sig.signer ? ` · ${sig.signer}` : ""), sig?.detail ? h("span", { class: "muted block small" }, sig.detail) : null)))));
      }
    }
    nodes.push(
      h("p", { class: "muted small" }, m.processesHint),
      paneControls(() => { monitorProcesses = undefined; inspected.clear(); void renderPane(); }, null),
      monitorProcesses === null ? h("p", { class: "muted" }, m.unavailable) : shown.length === 0 ? h("p", { class: "muted" }, m.noRows) : table([m.process, "PID", m.memory, m.threads, m.handles, ""], rows),
      h("p", { class: "muted small" }, m.rows(Math.min(shown.length, 600), all.length)),
    );
  } else if (monitorPane === "storage") {
    if (monitorStorage === undefined) monitorStorage = (await guard(() => api.storage() as Promise<StorageView | null>)) ?? null;
    const st = monitorStorage;
    nodes.push(h("p", { class: "muted small" }, m.storageHint));
    if (!st) nodes.push(h("p", { class: "muted" }, m.unavailable));
    else {
      nodes.push(h("h3", {}, m.disks), table([m.disk, m.model, m.kind, m.size, m.health], st.disks.map((d) =>
        h("tr", { class: d.health === "failing" ? "flag" : "" }, h("td", {}, h("code", { dir: "ltr" }, d.name)), h("td", {}, d.model ?? "—"), h("td", {}, d.kind.toUpperCase()), h("td", { class: "num" }, d.sizeBytes ? bytes(d.sizeBytes) : "—"),
          h("td", {}, h("span", { class: `sig sig-${d.health === "ok" ? "signed" : d.health === "failing" ? "invalid" : d.health === "warning" ? "warn" : "unknown"}` }, m.healthStates[d.health] ?? d.health), d.healthDetail ? h("span", { class: "muted block small" }, d.healthDetail) : null)))));
      nodes.push(h("h3", {}, m.volumes), ...st.volumes.map((v) => h("div", { class: "volume" },
        h("div", { class: "row spread" }, h("span", {}, h("strong", { dir: "ltr" }, v.mount), v.label ? ` · ${v.label}` : "", v.fileSystem ? h("span", { class: "muted" }, ` · ${v.fileSystem}`) : null), h("span", { class: "muted small" }, m.space(bytes(v.usedBytes), bytes(v.sizeBytes)))),
        meter(v.sizeBytes ? v.usedBytes / v.sizeBytes : 0))));
    }
    nodes.push(h("div", { class: "row" }, h("button", { type: "button", class: "secondary", onclick: () => { monitorStorage = undefined; void renderPane(); } }, m.refresh)));
  } else if (monitorPane === "network") {
    if (monitorNics === undefined) monitorNics = ((await guard(() => api.netInterfaces() as Promise<NicView[]>)) ?? []);
    const input = h("input", { type: "search", id: "dns-query", placeholder: m.dnsPlaceholder, "aria-label": m.dnsLookup, dir: "ltr" }) as HTMLInputElement;
    const run = async () => {
      if (!input.value.trim()) return;
      dnsAnswer = (await guard(() => api.netLookup(input.value) as Promise<DnsView>)) ?? null;
      void renderPane();
    };
    input.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void run(); });
    if (dnsAnswer) input.value = dnsAnswer.query;
    nodes.push(h("h3", {}, m.dnsLookup), h("p", { class: "muted small" }, m.dnsHint), h("div", { class: "row" }, input, h("button", { type: "button", id: "dns-go", onclick: run }, m.lookUp)));
    if (dnsAnswer) {
      const a = dnsAnswer;
      nodes.push(a.error ? h("p", { class: "warning-text" }, a.error) : h("dl", { class: "facts", id: "dns-result" },
        a.addresses.length ? h("dt", {}, m.addresses) : null, a.addresses.length ? h("dd", {}, ...a.addresses.map((x) => h("span", { class: "block" }, h("code", { dir: "ltr" }, x.address), " ", h("span", { class: `ipclass ip-${x.class}` }, m.ipClasses[x.class ?? ""] ?? x.class ?? "")))) : null,
        a.reverse.length ? h("dt", {}, m.reverse) : null, a.reverse.length ? h("dd", {}, h("code", { dir: "ltr" }, a.reverse.join(", "))) : null,
        a.mx.length ? h("dt", {}, "MX") : null, a.mx.length ? h("dd", {}, ...a.mx.map((x) => h("code", { class: "block", dir: "ltr" }, `${x.priority} ${x.exchange}`))) : null,
        a.txt.length ? h("dt", {}, "TXT") : null, a.txt.length ? h("dd", {}, ...a.txt.map((x) => h("code", { class: "block", dir: "ltr" }, x))) : null));
    }
    nodes.push(h("h3", {}, m.interfaces), table([m.interface, m.addresses, m.received, m.sent, m.errors], monitorNics.map((n) =>
      h("tr", { class: n.errors ? "flag" : "" }, h("td", {}, h("strong", { dir: "ltr" }, n.name), n.mac ? h("span", { class: "muted block small", dir: "ltr" }, n.mac) : null), h("td", {}, ...n.addresses.map((x) => h("code", { class: "block", dir: "ltr" }, x))),
        h("td", { class: "num" }, n.rxBytes !== null ? `${bytes(n.rxBytes)} · ${n.rxPackets ?? 0} pkts` : "—"), h("td", { class: "num" }, n.txBytes !== null ? `${bytes(n.txBytes)} · ${n.txPackets ?? 0} pkts` : "—"),
        h("td", { class: "num" }, n.errors !== null ? `${n.errors} / ${n.drops ?? 0}` : "—")))));
  } else if (monitorPane === "history") {
    if (historyPoints === undefined) historyPoints = ((await guard(() => api.telemetryHistory(historyHours) as Promise<HistoryView[]>)) ?? []);
    if (securityLog === undefined) securityLog = ((await guard(() => api.securityLog() as Promise<LogView[]>)) ?? []);
    const range = (hours: number, label: string) => h("button", { type: "button", class: "secondary small-button", "aria-pressed": historyHours === hours ? "true" : "false", onclick: () => { historyHours = hours; historyPoints = undefined; void renderPane(); } }, label);
    const pts = historyPoints;
    const chart = (title: string, series: number[][], max: number, legend: string) => h("div", { class: "history-chart" }, h("div", { class: "row spread" }, h("strong", {}, title), h("span", { class: "muted small" }, legend)), sparkline(series, max));
    nodes.push(h("p", { class: "muted small" }, m.historyHint), h("div", { class: "row" }, range(1, m.lastHour), range(24, m.lastDay), range(168, m.lastWeek)));
    if (pts.length < 2) nodes.push(h("p", { class: "muted" }, m.historyEmpty));
    else {
      const peak = (f: (p: HistoryView) => number) => Math.max(1, ...pts.map(f));
      nodes.push(h("div", { class: "history-grid" },
        chart(m.cpu, [pts.map((p) => p.cpu)], 100, m.peak(`${Math.round(peak((p) => p.cpu))}%`)),
        chart(m.memory, [pts.map((p) => p.memory)], 100, m.peak(`${Math.round(peak((p) => p.memory))}%`)),
        chart(m.network, [pts.map((p) => p.rx), pts.map((p) => p.tx)], peak((p) => Math.max(p.rx, p.tx)), m.peak(`${bytes(peak((p) => Math.max(p.rx, p.tx)))}/s`)),
        chart(m.disk, [pts.map((p) => p.read), pts.map((p) => p.write)], peak((p) => Math.max(p.read, p.write)), m.peak(`${bytes(peak((p) => Math.max(p.read, p.write)))}/s`))),
        h("p", { class: "muted small" }, `${date(pts[0]!.at)} → ${date(pts[pts.length - 1]!.at)}`));
    }
    nodes.push(h("h3", {}, m.securityLog), securityLog.length === 0 ? h("p", { class: "muted" }, m.noRows) : table(["", m.events, ""], securityLog.slice(0, 200).map((e) =>
      h("tr", { class: e.level === "alert" ? "flag" : "" }, h("td", { class: `level-${e.level === "alert" ? "error" : e.level}` }, m.logLevels[e.level] ?? e.level), h("td", { dir: "auto" }, h("strong", {}, e.kind), " ", e.message), h("td", { class: "muted" }, date(e.at))))));
  } else if (monitorPane === "connections") {
    if (monitorConnections === undefined) monitorConnections = (await guard(() => api.monitorConnections() as Promise<MonitorConnection[] | null>)) ?? null;
    const all = monitorConnections ?? [];
    const shown = all.filter((c) => (!monitorExternalOnly || isExternal(c.remote)) && matches(c.process, c.local, c.remote, c.state, c.pid));
    nodes.push(
      h("p", { class: "muted small" }, m.connectionsHint),
      paneControls(() => { monitorConnections = undefined; void renderPane(); }, toggle(m.externalOnly, monitorExternalOnly, (v) => { monitorExternalOnly = v; void renderPane(); }, undefined, "monitor-external")),
      monitorConnections === null ? h("p", { class: "muted" }, m.unavailable) : shown.length === 0 ? h("p", { class: "muted" }, m.noRows) : table([m.process, m.local, m.remote, m.state], shown.slice(0, 500).map((c) =>
        h("tr", {}, h("td", { dir: "auto" }, c.process ? `${c.process}${c.pid ? ` (${c.pid})` : ""}` : m.unknownProcess), h("td", { dir: "ltr" }, `${c.protocol.toUpperCase()} ${c.local}`), h("td", { dir: "ltr" }, c.remote ?? "—"), h("td", {}, c.state)))),
      h("p", { class: "muted small" }, m.rows(Math.min(shown.length, 500), all.length)),
    );
  } else if (monitorPane === "services") {
    if (monitorServices === undefined) monitorServices = (await guard(() => api.monitorServices() as Promise<MonitorService[] | null>)) ?? null;
    const all = monitorServices ?? [];
    const shown = all.filter((s) => matches(s.name, s.description, s.state)).sort((a, b) => Number(b.state === "failed") - Number(a.state === "failed") || a.name.localeCompare(b.name));
    const canControl = status.platform !== "darwin";
    const act = (service: MonitorService, action: "start" | "stop" | "restart", label: string) =>
      h("button", { type: "button", class: "secondary small-button", onclick: async () => {
        if (!window.confirm(m.confirmService(label, service.name))) return;
        const next = await guard(() => api.monitorServiceControl(service.name, action) as Promise<MonitorService[] | null>);
        if (next) { monitorServices = next; void renderPane(); }
      } }, label);
    nodes.push(
      h("p", { class: "muted small" }, m.servicesHint),
      paneControls(() => { monitorServices = undefined; void renderPane(); }, null),
      monitorServices === null ? h("p", { class: "muted" }, m.unavailable) : shown.length === 0 ? h("p", { class: "muted" }, m.noRows) : table([m.services, m.state, ""], shown.slice(0, 800).flatMap((s) => [
        h("tr", { class: s.state === "failed" ? "flag" : "" },
          h("td", {}, h("code", { dir: "ltr" }, s.name), s.description ? h("span", { class: "muted block" }, s.description) : null),
          h("td", {}, (m.serviceStates[s.state] ?? s.state) + (s.startup ? ` · ${s.startup}` : "")),
          h("td", {}, h("div", { class: "actions" },
            h("button", { type: "button", class: "secondary small-button", "aria-expanded": serviceOpen.has(s.name) ? "true" : "false", onclick: async () => {
              if (serviceOpen.has(s.name)) { serviceOpen.delete(s.name); void renderPane(); return; }
              serviceOpen.set(s.name, "loading"); void renderPane();
              const detail = await guard(() => api.monitorServiceDetails(s.name) as Promise<ServiceDetail | null>);
              if (detail) serviceOpen.set(s.name, detail); else serviceOpen.delete(s.name);
              void renderPane();
            } }, m.details),
            canControl && s.state === "running" ? act(s, "restart", m.restart) : null,
            canControl ? (s.state === "running" ? act(s, "stop", m.stop) : act(s, "start", m.start)) : null))),
        ...(() => {
          const d = serviceOpen.get(s.name);
          if (!d) return [];
          if (d === "loading") return [h("tr", { class: "detail" }, h("td", { colspan: "3" }, m.working))];
          const startup = (enabled: boolean, label: string) => h("button", { type: "button", class: "secondary small-button", onclick: async () => {
            if (!window.confirm(m.confirmService(label, s.name))) return;
            const next = await guard(() => api.monitorServiceStartup(s.name, enabled) as Promise<MonitorService[] | null>);
            if (next) { monitorServices = next; serviceOpen.delete(s.name); void renderPane(); }
          } }, label);
          return [h("tr", { class: "detail" }, h("td", { colspan: "3" }, h("dl", { class: "facts" },
            h("dt", {}, m.account), h("dd", {}, d.account ?? "—"),
            h("dt", {}, m.commandLine), h("dd", {}, d.command ? h("code", { dir: "ltr" }, d.command) : "—"),
            h("dt", {}, m.startup), h("dd", {}, d.startup ?? "—", canControl ? h("span", { class: "actions inline" }, startup(true, m.enable), startup(false, m.disable)) : null),
            h("dt", {}, m.dependsOn), h("dd", {}, d.dependsOn.length ? d.dependsOn.join(", ") : "—"),
            h("dt", {}, m.requiredBy), h("dd", {}, d.requiredBy.length ? d.requiredBy.join(", ") : "—"))))];
        })(),
      ])),
      h("p", { class: "muted small" }, m.rows(Math.min(shown.length, 800), all.length)),
    );
  } else {
    if (monitorEvents === undefined) {
      if (eventSource === "security") {
        const result = await guard(() => api.monitorSecurityEvents(24 * 60) as Promise<{ events: MonitorEvent[] | null; note: string | null }>);
        monitorEvents = result?.events ?? null;
        securityNote = result?.note ?? null;
      } else {
        monitorEvents = (await guard(() => api.monitorEvents(60) as Promise<MonitorEvent[] | null>)) ?? null;
        securityNote = null;
      }
    }
    const all = monitorEvents ?? [];
    const shown = all.filter((e) => (!monitorSecurityOnly || e.security) && (eventLevel === "all" || e.level === eventLevel || (eventLevel === "warning" && e.level === "error")) && matches(e.source, e.message, e.level));
    nodes.push(
      h("p", { class: "muted small" }, eventSource === "security" ? m.securityEventsHint : m.eventsHint),
      h("div", { class: "row" },
        select("event-source", m.logSource, eventSource, [["system", m.systemLog], ["security", m.securityLogSource]], (v) => { eventSource = v; monitorEvents = undefined; void renderPane(); }),
        select("event-level", m.severity, eventLevel, [["all", m.allLevels], ["warning", m.warningsUp], ["error", m.errorsOnly]], (v) => { eventLevel = v; void renderPane(); }),
        h("button", { type: "button", class: "secondary", disabled: !shown.length, onclick: () => void guard(() => api.monitorEventsExport(shown, "csv")).then((path) => path && flash(m.saved(String(path)))) }, m.exportCsv),
        h("button", { type: "button", class: "secondary", disabled: !shown.length, onclick: () => void guard(() => api.monitorEventsExport(shown, "json")).then((path) => path && flash(m.saved(String(path)))) }, m.exportJson)),
      securityNote ? h("p", { class: "warning-text small" }, securityNote) : null,
      paneControls(() => { monitorEvents = undefined; void renderPane(); }, toggle(m.securityOnly, monitorSecurityOnly, (v) => { monitorSecurityOnly = v; void renderPane(); }, undefined, "monitor-security-only")),
      monitorEvents === null ? h("p", { class: "muted" }, m.unavailable) : shown.length === 0 ? h("p", { class: "muted" }, m.noRows) : table(["", m.events, ""], shown.slice(0, 300).map((e) =>
        h("tr", { class: e.security ? "flag" : "" },
          h("td", { class: `level-${e.level}` }, m.eventLevels[e.level] ?? e.level),
          h("td", { dir: "auto" }, h("strong", {}, e.source), " ", e.message),
          h("td", { class: "muted" }, date(e.at))))),
      h("p", { class: "muted small" }, m.rows(Math.min(shown.length, 300), all.length)),
    );
  }
  if (tab !== "monitor") return;
  const focused = document.activeElement as HTMLInputElement | null;
  const keep = focused?.id === "monitor-filter" ? focused.selectionStart : null;
  box.replaceChildren(...nodes.filter((node): node is Node => node !== null));
  if (keep !== null) {
    const input = document.getElementById("monitor-filter") as HTMLInputElement | null;
    input?.focus();
    input?.setSelectionRange(keep, keep);
  }
}

async function monitorView() {
  const m = t.monitor;
  if (!monitorRunning) {
    monitorRunning = true;
    monitorSamples = ((await api.monitorStart()) as MonitorSnapshot[]) ?? [];
  }
  const pane = (key: typeof monitorPane, label: string) =>
    h("button", { type: "button", class: "secondary", "aria-pressed": monitorPane === key ? "true" : "false", "data-pane": key, onclick: () => { monitorPane = key; monitorFilter = ""; void render(); } }, label);
  return [
    h("h1", {}, m.heading),
    h("p", { class: "muted" }, m.intro),
    h("div", { class: "monitor-grid", id: "monitor-live" }, ...liveCards()),
    h("div", { class: "tabs-inline", role: "group" },
      pane("processes", m.processes), pane("connections", m.connections), pane("services", m.services), pane("events", m.events),
      pane("storage", m.storage), pane("network", m.networkTools), pane("history", m.history)),
    h("section", { class: "panel", id: "monitor-pane" }, h("p", { class: "muted" }, "…")),
  ];
}

// --- Security posture, file integrity and reports ---------------------------------------

function postureRing(score: number | null) {
  const ring = document.createElementNS(SVG, "svg");
  ring.setAttribute("viewBox", "0 0 80 80");
  ring.setAttribute("class", "posture-ring");
  ring.setAttribute("aria-hidden", "true");
  const track = document.createElementNS(SVG, "circle");
  track.setAttribute("cx", "40"); track.setAttribute("cy", "40"); track.setAttribute("r", "34"); track.setAttribute("class", "ring-track");
  const arc = document.createElementNS(SVG, "circle");
  arc.setAttribute("cx", "40"); arc.setAttribute("cy", "40"); arc.setAttribute("r", "34");
  arc.setAttribute("class", `ring-arc ${score === null ? "" : score >= 80 ? "good" : score >= 55 ? "fair" : "weak"}`);
  const length = 2 * Math.PI * 34;
  arc.setAttribute("stroke-dasharray", `${((score ?? 0) / 100) * length} ${length}`);
  ring.append(track, arc);
  return h("div", { class: "posture-score" }, ring, h("span", { class: "big", id: "posture-score" }, score === null ? "—" : String(score)));
}

function posturePanel() {
  const c = t.security;
  const p = postureView;
  const run = async () => {
    postureBusy = true;
    void render();
    postureView = (await guard(() => api.posture() as Promise<PostureView>)) ?? postureView;
    postureBusy = false;
    void render();
  };
  const order = { fail: 0, warn: 1, unknown: 2, pass: 3 } as const;
  return h(
    "section",
    { class: "panel", id: "posture" },
    h("h2", {}, c.posture),
    h("p", { class: "muted" }, c.postureHint),
    p
      ? h("div", { class: "posture" }, postureRing(p.score), h("div", {},
          h("p", { class: p.score === null ? "muted" : p.score >= 80 ? "good-text" : "warning-text" }, p.score === null ? c.postureUnknown : c.postureSummary(p.checks.filter((x) => x.status === "fail").length, p.checks.filter((x) => x.status === "warn").length)),
          h("p", { class: "muted small" }, c.checkedAt(date(p.checkedAt)))))
      : null,
    p
      ? h("ul", { class: "folders checks" }, ...p.checks.slice().sort((a, b) => order[a.status] - order[b.status]).map((check) =>
          h("li", { class: `item check-${check.status}` },
            h("span", { class: "row spread" }, h("strong", {}, check.title), h("span", { class: `sig sig-${check.status === "pass" ? "signed" : check.status === "fail" ? "invalid" : check.status}` }, c.checkStates[check.status])),
            check.detail ? h("span", { class: "muted small block" }, check.detail) : null,
            check.status !== "pass" && check.fix ? h("span", { class: "small block" }, check.fix) : null)))
      : null,
    h("div", { class: "row" }, h("button", { type: "button", id: "posture-run", disabled: postureBusy, onclick: run }, postureBusy ? c.checking : p ? c.recheck : c.postureRun)),
  );
}

function integrityPanel() {
  const c = t.security;
  const view = integrityView;
  if (!view) {
    void api.integrityState().then((next) => {
      integrityView = next as IntegrityView;
      if (tab === "security") void render();
    });
    return h("section", { class: "panel", id: "integrity" }, h("h2", {}, c.integrity), h("div", { class: "skeleton-line" }));
  }
  const set = async (action: () => Promise<unknown>) => {
    integrityView = ((await guard(action)) as IntegrityView | undefined) ?? integrityView;
    void render();
  };
  return h(
    "section",
    { class: "panel", id: "integrity" },
    h("h2", {}, c.integrity),
    h("p", { class: "muted" }, c.integrityHint),
    view.changes.length
      ? h("ul", { class: "folders", id: "integrity-changes" }, ...view.changes.map((change) =>
          h("li", { class: "item risky" },
            h("span", { class: "row spread" }, h("strong", { dir: "ltr" }, change.path), h("button", { type: "button", class: "secondary small-button", onclick: () => set(() => api.integrityAccept(change.path)) }, c.acceptChange)),
            h("span", { class: "warning-text small" }, `${c.changeKinds[change.kind] ?? change.kind} · ${date(change.at)}`))))
      : h("p", { class: "good-text", id: "integrity-ok" }, c.integrityOk(view.paths.length)),
    h("details", {}, h("summary", {}, c.watchedFiles(view.paths.length)),
      h("ul", { class: "folders small" }, ...view.paths.map((path) =>
        h("li", { class: "row spread" }, h("code", { dir: "ltr" }, path, view.baseline[path]?.sha256 ? "" : ` (${c.missing})`), h("button", { type: "button", class: "link", onclick: () => set(() => api.integrityRemove(path)) }, c.remove))))),
    h("div", { class: "row" },
      h("button", { type: "button", class: "secondary", id: "integrity-check", onclick: () => set(() => api.integrityCheck()) }, c.checkNow),
      h("button", { type: "button", class: "secondary", onclick: () => set(() => api.integrityAdd()) }, c.addFiles),
      h("button", { type: "button", class: "secondary", onclick: () => { if (window.confirm(c.confirmRebaseline)) void set(() => api.integrityReset()); } }, c.rebaseline)),
    view.lastCheck ? h("p", { class: "muted small" }, c.checkedAt(date(view.lastCheck))) : null,
  );
}

function reportsPanel() {
  const c = t.security;
  const make = (kind: "inventory" | "security" | "performance", format: "json" | "csv" | "html" | "pdf") =>
    h("button", { type: "button", class: "secondary small-button", "data-report": `${kind}-${format}`, disabled: reportBusy !== null, onclick: async () => {
      reportBusy = `${kind}-${format}`;
      void render();
      const path = await guard(() => api.report(kind, format));
      reportBusy = null;
      void render();
      if (path) flash(t.monitor.saved(String(path)));
    } }, reportBusy === `${kind}-${format}` ? c.checking : format.toUpperCase());
  return h(
    "section",
    { class: "panel", id: "reports" },
    h("h2", {}, c.reports),
    h("p", { class: "muted" }, c.reportsHint),
    ...(["security", "inventory", "performance"] as const).map((kind) =>
      h("div", { class: "report-row" }, h("span", {}, h("strong", { class: "block" }, c.reportKinds[kind]), h("span", { class: "muted small" }, c.reportAbout[kind])),
        h("div", { class: "actions" }, make(kind, "pdf"), make(kind, "html"), make(kind, "csv"), make(kind, "json")))),
  );
}

async function securityView() {
  const c = t.security;
  const sec = await loadSecurity();
  return [
    h("h1", {}, c.heading),
    h("p", { class: "muted" }, c.intro),
    h(
      "div",
      { class: "row" },
      h("button", {
        type: "button",
        class: "secondary",
        id: "security-recheck",
        onclick: async (event: Event) => {
          (event.target as HTMLButtonElement).textContent = c.checking;
          await loadSecurity(true);
          void render();
        },
      }, c.recheck),
      sec ? h("span", { class: "muted small" }, c.checkedAt(date(sec.checkedAt))) : null,
    ),
    posturePanel(),
    ...(sec ? securityPanels(sec) : []),
    integrityPanel(),
    programsPanel(),
    browsingPanel(),
    privacyPanel(sec),
    reportsPanel(),
    schedulePanel(),
    backupPanel(),
  ];
}

// --- Home network -----------------------------------------------------------------------

const sevBadge = (s: NetFinding["severity"]) => (s === "critical" || s === "high" ? "malicious" : s === "medium" ? "suspicious" : "no_known_threat");

function deviceKeyOf(d: NetDevice): string {
  return d.mac ? `mac:${d.mac}` : `ip:${d.ip}`;
}

function credPanel(device: NetDevice) {
  const k = t.network;
  const state = credResults.get(device.ip);
  const canCheck = device.services.some((s) => [80, 8080, 23, 2323, 21].includes(s.port));
  if (!canCheck) return null;
  const run = async () => {
    const box = document.getElementById(`cred-consent-${device.ip}`) as HTMLInputElement | null;
    if (!box?.checked) { flash(k.credConsent, "error"); return; }
    credResults.set(device.ip, "loading");
    void render();
    const result = await guard(() => api.networkCredentialCheck(device.ip, true) as Promise<{ results?: CredResult[]; refused?: string }>);
    credResults.set(device.ip, result?.refused ? { refused: result.refused } : (result?.results ?? []));
    void render();
  };
  return h(
    "details",
    { class: "cred" },
    h("summary", {}, k.credTitle),
    h("p", { class: "muted small" }, k.credIntro),
    state === "loading"
      ? h("p", { class: "muted" }, k.credChecking)
      : state && "refused" in (state as object)
        ? h("p", { class: "muted small" }, (state as { refused: string }).refused)
        : Array.isArray(state)
          ? h("div", {}, ...(state.length
              ? state.map((r) =>
                  r.defaultAccepted
                    ? h("p", { class: "warning-text small" }, k.credDefault(r.service, r.user ?? "?"))
                    : r.stopped
                      ? h("p", { class: "muted small" }, k.credStopped(r.stopped))
                      : h("p", { class: "muted small" }, k.credSafe))
              : [h("p", { class: "muted small" }, k.credSafe)]))
          : h("div", {},
              h("label", { class: "check" }, h("input", { type: "checkbox", id: `cred-consent-${device.ip}` }), h("span", {}, k.credConsent)),
              h("button", { type: "button", class: "secondary small-button", onclick: () => void run() }, k.credButton)),
  );
}

function deviceCard(device: NetDevice, isNew: boolean) {
  const k = t.network;
  const name = device.hostname || device.vendor || (device.role === "router" ? k.router : device.role === "self" ? k.thisComputer : device.ip);
  return h(
    "li",
    { class: device.services.some((s) => [23, 2323, 5555, 445].includes(s.port)) ? "item risky" : "item" },
    h("div", { class: "row spread" },
      h("span", {},
        h("strong", { dir: "auto" }, name),
        device.role === "router" ? h("span", { class: "badge no_known_threat" }, k.router) : null,
        device.role === "self" ? h("span", { class: "muted small" }, ` ${k.thisComputer}`) : null,
        isNew ? h("span", { class: "badge suspicious" }, k.newBadge) : null,
        device.trusted ? h("span", { class: "badge no_known_threat" }, k.trusted) : null),
      device.role === "device"
        ? h("button", { type: "button", class: "link", onclick: async () => {
            const next = await guard(() => api.networkTrust(deviceKeyOf(device), !device.trusted) as Promise<NetworkScanView | null>);
            if (next) { networkScan = next; void render(); }
          } }, device.trusted ? k.markUnknown : k.markKnown)
        : null),
    h("code", { class: "block muted small", dir: "ltr" }, `${device.ip}${device.mac ? ` · ${device.mac}` : ""}${device.vendor ? ` · ${device.vendor}` : ""}`),
    device.services.length
      ? h("p", { class: "small", dir: "ltr" }, `${k.services}: ${device.services.map((s) => `${s.name}/${s.port}`).join(", ")}`)
      : h("p", { class: "muted small" }, k.noServices),
    credPanel(device),
  );
}

async function networkView(): Promise<(Node | null)[]> {
  const k = t.network;
  if (networkScan === null) {
    networkScan = ((await guard(() => api.networkStatus() as Promise<NetworkScanView | null>)) ?? null) as NetworkScanView | null;
  }
  const scan = networkScan;
  const newKeys = new Set(scan?.newDevices ?? []);
  const start = async () => {
    networkBusy = true;
    networkProgress = null;
    void render();
    const result = await guard(() => api.networkScan() as Promise<NetworkScanView>);
    if (result) networkScan = result;
    networkBusy = false;
    networkProgress = null;
    void render();
  };
  return [
    h("section", { class: "panel", id: "network-overview" },
      h("h2", {}, k.heading),
      h("p", { class: "muted" }, k.intro),
      scan?.cidr ? h("p", { class: "small", dir: "ltr" }, k.onNetwork(scan.wifi?.ssid ?? null, scan.cidr)) : null,
      scan ? h("p", { class: "muted small" }, k.lastScan(date(scan.finishedAt))) : null,
      Object.values(scan?.capabilities ?? {}).includes("unavailable") ? h("p", { class: "muted small" }, k.capUnavailable) : null,
      h("div", { class: "row" },
        h("button", { type: "button", id: "network-scan", disabled: networkBusy, onclick: () => void start() }, networkBusy ? k.scanning : scan ? k.rescan : k.scan)),
      networkBusy && networkProgress ? h("p", { class: "muted small", id: "network-progress" }, k.phase(networkProgress.phase, networkProgress.done, networkProgress.total)) : null,
      toggle(k.watch, status.settings.networkWatch, (value) => change({ networkWatch: value }), k.watchHint, "network-watch")),
    scan
      ? h("section", { class: "panel", id: "network-findings" },
          h("h2", {}, k.findings),
          scan.findings.length
            ? h("ul", { class: "folders" }, ...scan.findings.map((f) =>
                h("li", { class: f.severity === "critical" || f.severity === "high" ? "item risky" : "item" },
                  h("div", { class: "row spread" }, h("strong", { dir: "auto" }, f.title), h("span", { class: `badge ${sevBadge(f.severity)}` }, k.severity[f.severity])),
                  h("span", { class: "muted small block", dir: "auto" }, f.detail))))
            : h("p", { class: "muted", id: "network-clean" }, k.noFindings))
      : null,
    scan && scan.devices.length
      ? h("section", { class: "panel", id: "network-devices" },
          h("h2", {}, `${k.devices} · ${k.deviceCount(scan.devices.length)}`),
          h("ul", { class: "folders" }, ...scan.devices.map((d) => deviceCard(d, newKeys.has(deviceKeyOf(d))))))
      : scan && !scan.cidr
        ? h("section", { class: "panel" }, h("p", { class: "muted" }, k.noNetwork))
        : null,
  ];
}

let renderToken = 0;

async function render() {
  const token = ++renderToken;
  lang = resolve(status.settings.language, status.locale);
  t = DICTS[lang];
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.title = t.title;
  const nav = document.getElementById("nav")!;
  nav.replaceChildren(
    ...(Object.keys(t.tabs) as Tab[]).map((key) =>
      h(
        "button",
        {
          type: "button",
          class: key === tab ? "current" : "",
          "aria-current": key === tab ? "page" : false,
          "data-tab": key,
          onclick: () => {
            if (key === tab) return;
            if (tab === "monitor" && key !== "monitor" && monitorRunning) {
              monitorRunning = false;
              void api.monitorStop();
            }
            tab = key;
            void render();
          },
        },
        icon(key),
        h("span", { class: "label" }, t.tabs[key]),
        key === "quarantine" && status.quarantineCount ? h("span", { class: "count" }, String(status.quarantineCount)) : null,
      ),
    ),
  );
  document.getElementById("brand")!.textContent = t.title;
  const main = document.getElementById("main")!;
  const views: Record<Tab, () => (Node | null)[] | Promise<(Node | null)[]>> = {
    scan: scanView,
    protection: protectionView,
    security: securityView,
    network: networkView,
    monitor: monitorView,
    tools: toolsView,
    quarantine: quarantineView,
    history: historyView,
    settings: settingsView,
  };
  const nodes = await views[tab]();
  // A slower render that started earlier must not replace a newer one.
  if (token !== renderToken) return;
  main.replaceChildren(...nodes.filter((node): node is Node => node !== null));
  if (tab === "monitor") void renderPane();
}

async function refresh() {
  status = (await api.status()) as Status;
  await render();
}

api.on("scan-result", (payload) => {
  if ((payload as Entry).quarantined) void api.status().then((next) => { status = next as Status; });
  results.unshift(payload as Entry);
  results.splice(200);
  if (tab === "scan") {
    const list = document.getElementById("results");
    if (list) list.prepend(resultRow(payload as Entry));
    else void render();
  }
});
api.on("signatures-updated", () => {
  if (tab === "protection" || tab === "scan") void refresh();
  else void api.status().then((next) => { status = next as Status; });
});
api.on("ransomware-alert", (payload) => {
  ransomwareAlert = payload as Status["ransomwareAlert"];
  tab = "protection";
  void render();
});
api.on("remote-activity", (payload) => {
  flash(`${t.account.remoteActivity} ${String(payload)}`);
  void api.status().then((next) => {
    status = next as Status;
    if (tab === "settings") void render();
  });
});
api.on("device-use", (payload) => {
  if (security) security = { ...security, deviceUse: { ...security.deviceUse, ...(payload as Partial<SecurityResult["deviceUse"]>) } };
  if (tab === "security") void render();
});
api.on("backup-progress", (payload) => {
  backupProgress = payload as typeof backupProgress;
  const line = document.getElementById("backup-progress");
  if (line) line.textContent = backupProgress ? t.security.backingUp(backupProgress.files, backupProgress.current ?? "") : "";
});
api.on("schedule-ran", () => {
  void api.status().then((next) => {
    status = next as Status;
    if (tab === "security") void render();
  });
});
api.on("update-state", (payload) => {
  status = { ...status, update: payload as UpdateView };
  if (tab === "settings") void render();
});
api.on("integrity-alert", (payload) => {
  integrityView = payload as IntegrityView;
  if (tab === "security") void render();
  else flash(t.security.integrityAlert, "error");
});
api.on("monitor-sample", (payload) => {
  monitorSamples = [...monitorSamples, payload as MonitorSnapshot].slice(-90);
  const live = document.getElementById("monitor-live");
  if (live && tab === "monitor") live.replaceChildren(...liveCards());
});
api.on("monitor-event", (payload) => {
  if (!monitorEvents) return;
  monitorEvents = [payload as MonitorEvent, ...monitorEvents].slice(0, 500);
  if (tab === "monitor" && monitorPane === "events") void renderPane();
});

api.on("network-progress", (payload) => {
  networkProgress = payload as { done: number; total: number; phase: string };
  const line = document.getElementById("network-progress");
  if (line && tab === "network") line.textContent = t.network.phase(networkProgress.phase, networkProgress.done, networkProgress.total);
});
api.on("network-scanned", (payload) => {
  networkScan = payload as NetworkScanView;
  if (tab === "network") void render();
});
api.on("ransomware-halt", (payload) => {
  const proc = payload as HaltedProc;
  if (!haltedProcs.some((p) => p.pid === proc.pid)) haltedProcs = [...haltedProcs, proc];
  tab = "protection";
  void render();
});

api.on("scan-progress", (payload) => {
  const { scanned, malicious, suspicious } = payload as { scanned: number; malicious: number; suspicious: number };
  const progress = document.getElementById("progress");
  if (progress) progress.textContent = t.scan.progress(scanned, malicious + suspicious);
});

void refresh();
