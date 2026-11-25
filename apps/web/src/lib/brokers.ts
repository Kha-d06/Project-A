/**
 * The data-broker opt-out checklist on the website: the same versioned catalog
 * the desktop app ships (a test keeps the two copies identical), with the
 * person's progress kept only in this browser. Nothing about which companies
 * the person contacted goes to the server; the request letter is filled in
 * here and copied, never sent.
 */
import catalogFile from "./data/brokers.json";

export type BrokerState = "todo" | "requested" | "removed" | "not_listed";

export interface Broker {
  id: string;
  name: string;
  site: string;
  optOutUrl: string;
  regions: string[];
  verification: string;
  removalDays: number;
  steps: string[];
  template: string | null;
}

export interface Catalog {
  version: string;
  reviewed: string | null;
  note: string;
  recheckDays: number;
  brokers: Broker[];
  templates: Record<string, { subject: string; body: string }>;
}

export type Progress = Record<string, { state: BrokerState; at: string }>;

export interface BrokerRow extends Broker {
  state: BrokerState;
  at: string | null;
  recheckDue: boolean;
  expectedBy: string | null;
}

export const CATALOG = catalogFile as Catalog;
export const STATES: BrokerState[] = ["todo", "requested", "removed", "not_listed"];
export const STORAGE_KEY = "qalaa.brokers.v1";
const DAY = 24 * 60 * 60 * 1000;

/** Only the opt-out pages the catalog names, over https on the company's own site. */
export function safeOptOutUrl(b: Broker): string | null {
  try {
    const url = new URL(b.optOutUrl);
    return url.protocol === "https:" && (url.hostname === b.site || url.hostname.endsWith(`.${b.site}`)) ? url.toString() : null;
  } catch {
    return null;
  }
}

export function cleanProgress(raw: unknown, catalog: Catalog = CATALOG): Progress {
  if (!raw || typeof raw !== "object") return {};
  const ids = new Set(catalog.brokers.map((b) => b.id));
  const out: Progress = {};
  for (const [id, p] of Object.entries(raw as Record<string, { state?: unknown; at?: unknown }>)) {
    if (!ids.has(id) || !p || typeof p.at !== "string" || Number.isNaN(Date.parse(p.at))) continue;
    if (p.state === "requested" || p.state === "removed" || p.state === "not_listed") out[id] = { state: p.state, at: p.at };
  }
  return out;
}

export function rows(progress: Progress, now: number, catalog: Catalog = CATALOG): { rows: BrokerRow[]; done: number; recheckDue: number } {
  const list = catalog.brokers.map((b): BrokerRow => {
    const p = progress[b.id];
    const at = p ? Date.parse(p.at) : null;
    const active = p?.state === "requested" || p?.state === "removed";
    return {
      ...b,
      state: p?.state ?? "todo",
      at: p?.at ?? null,
      recheckDue: Boolean(active && at !== null && now - at >= catalog.recheckDays * DAY),
      expectedBy: p?.state === "requested" && at !== null ? new Date(at + b.removalDays * DAY).toISOString() : null,
    };
  });
  return {
    rows: list,
    done: list.filter((r) => r.state !== "todo" && !r.recheckDue).length,
    recheckDue: list.filter((r) => r.recheckDue).length,
  };
}

/** Marking again restarts the re-check clock; "todo" forgets the company. */
export function mark(progress: Progress, id: string, state: BrokerState, now: number): Progress {
  const next = { ...progress };
  if (state === "todo") delete next[id];
  else next[id] = { state, at: new Date(now).toISOString() };
  return next;
}

export function letterFor(b: Broker, name: string, email: string, catalog: Catalog = CATALOG): { subject: string; body: string } | null {
  const template = catalog.templates[b.template ?? "pdpl"];
  if (!template || !name.trim() || name.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return null;
  const values = { broker: b.name, name: name.trim(), email: email.trim() };
  const fill = (text: string) => text.replace(/\{(broker|name|email)\}/g, (_m, key: keyof typeof values) => values[key]);
  return { subject: fill(template.subject), body: fill(template.body) };
}

export function loadProgress(): Progress {
  try {
    return cleanProgress(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}"));
  } catch {
    return {};
  }
}

export function saveProgress(progress: Progress): boolean {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
    return true;
  } catch {
    return false; // private window or storage blocked: the list still works for this visit
  }
}
