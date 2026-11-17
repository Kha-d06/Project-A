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
}

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
  checkedAt: string;
}

type Entry = ScanResult & { quarantined?: string };
type Tab = "scan" | "protection" | "security" | "quarantine" | "history" | "settings";

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

type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === "function") element.addEventListener(key.slice(2), value as EventListener);
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

function flash(message: string, tone: "info" | "error" = "info") {
  const box = document.getElementById("toast")!;
  box.textContent = message;
  box.className = `toast ${tone}`;
  window.setTimeout(() => (box.className = "toast hidden"), 4000);
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

function protectionView() {
  const s = status.settings;
  const p = t.protection;
  const alert = ransomwareAlert ?? status.ransomwareAlert;
  return [
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
    updatesPanel(),
    h("section", { class: "panel subtle" }, h("h2", {}, p.limits), h("p", { class: "muted" }, p.limitsBody)),
  ];
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
  return [firewall, ports, startup];
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
    ...(sec ? securityPanels(sec) : []),
    privacyPanel(sec),
    schedulePanel(),
    backupPanel(),
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
        { type: "button", class: key === tab ? "current" : "", "aria-current": key === tab ? "page" : false, "data-tab": key, onclick: () => { tab = key; void render(); } },
        t.tabs[key],
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
    quarantine: quarantineView,
    history: historyView,
    settings: settingsView,
  };
  const nodes = await views[tab]();
  // A slower render that started earlier must not replace a newer one.
  if (token !== renderToken) return;
  main.replaceChildren(...nodes.filter((node): node is Node => node !== null));
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
api.on("scan-progress", (payload) => {
  const { scanned, malicious, suspicious } = payload as { scanned: number; malicious: number; suspicious: number };
  const progress = document.getElementById("progress");
  if (progress) progress.textContent = t.scan.progress(scanned, malicious + suspicious);
});

void refresh();
