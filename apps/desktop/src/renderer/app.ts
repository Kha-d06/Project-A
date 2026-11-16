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
  settings: DesktopSettings;
  signatures: { count: number; updatedAt?: string; error: string | null };
  clamav: { available: boolean; path: string | null };
  watching: string[];
  quarantineCount: number;
  locale: string;
}

type Entry = ScanResult & { quarantined?: string };
type Tab = "scan" | "protection" | "quarantine" | "history" | "settings";

const api = window.sentinel;
let lang: Lang = "en";
let t = DICTS.en;
let status: Status;
let tab: Tab = "scan";
const results: Entry[] = [];

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

function protectionView() {
  const s = status.settings;
  const p = t.protection;
  return [
    h("h1", {}, p.heading),
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
  ];
}

async function render() {
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
  const views: Record<Tab, () => Node[] | Promise<Node[]>> = {
    scan: scanView,
    protection: protectionView,
    quarantine: quarantineView,
    history: historyView,
    settings: settingsView,
  };
  main.replaceChildren(...(await views[tab]()));
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
api.on("scan-progress", (payload) => {
  const { scanned, malicious, suspicious } = payload as { scanned: number; malicious: number; suspicious: number };
  const progress = document.getElementById("progress");
  if (progress) progress.textContent = t.scan.progress(scanned, malicious + suspicious);
});

void refresh();
