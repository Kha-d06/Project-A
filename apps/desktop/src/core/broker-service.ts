/**
 * Data-broker opt-out checklist: a versioned catalog of people-search and
 * marketing-data companies (opt-out page, how they verify, how long removal
 * takes, a request letter where the law gives one), and the person's own
 * progress, kept only on this computer. No paid removal service and no API:
 * the person opens each page themselves. Ninety days after a request or a
 * removal, a broker is due for a re-check, because listings come back.
 */
import { readFile } from "node:fs/promises";

import catalogFile from "./data/brokers.json";
import { atomicWrite } from "./atomic-write";
import { IpcError } from "./protocol";

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

export interface BrokerProgress {
  state: BrokerState;
  /** When the state last changed (ISO). */
  at: string;
}

export interface BrokerRow extends Broker {
  state: BrokerState;
  at: string | null;
  /** A request or removal more than recheckDays old: look again. */
  recheckDue: boolean;
  /** Expected removal date for a pending request. */
  expectedBy: string | null;
}

export interface BrokerStatus {
  catalogVersion: string;
  reviewed: string | null;
  note: string;
  brokers: BrokerRow[];
  done: number;
  recheckDue: number;
}

const STATES: BrokerState[] = ["todo", "requested", "removed", "not_listed"];
const DAY = 24 * 60 * 60 * 1000;

export const CATALOG = catalogFile as Catalog;

/** Checks a catalog's shape (also used on the bundled one by the tests). */
export function validateCatalog(catalog: Catalog): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(catalog.version)) problems.push("version must be a date");
  for (const b of catalog.brokers) {
    if (!/^[a-z0-9-]+$/.test(b.id) || ids.has(b.id)) problems.push(`${b.id}: bad or duplicate id`);
    ids.add(b.id);
    let url: URL | null = null;
    try {
      url = new URL(b.optOutUrl);
    } catch {
      problems.push(`${b.id}: optOutUrl is not a URL`);
    }
    if (url && (url.protocol !== "https:" || !(url.hostname === b.site || url.hostname.endsWith(`.${b.site}`)))) problems.push(`${b.id}: optOutUrl must be https on ${b.site}`);
    if (!b.steps.length) problems.push(`${b.id}: no steps`);
    if (!(b.removalDays > 0 && b.removalDays <= 90)) problems.push(`${b.id}: removalDays out of range`);
    if (b.template && !catalog.templates[b.template]) problems.push(`${b.id}: unknown template ${b.template}`);
  }
  for (const [key, t] of Object.entries(catalog.templates)) {
    if (!t.body.includes("{name}") || !t.body.includes("{email}") || !t.body.includes("{broker}")) problems.push(`template ${key}: needs {name}, {email}, {broker}`);
  }
  return problems;
}

/** Fills a request letter. Name and email are used once and never stored. */
export function fillTemplate(template: { subject: string; body: string }, values: { broker: string; name: string; email: string }): { subject: string; body: string } {
  const fill = (text: string) => text.replace(/\{(broker|name|email)\}/g, (_m, key: "broker" | "name" | "email") => values[key]);
  return { subject: fill(template.subject), body: fill(template.body) };
}

export class BrokerService {
  private progress: Record<string, BrokerProgress> = {};

  constructor(
    private readonly file: string,
    private readonly catalog: Catalog = CATALOG,
    private readonly now: () => number = Date.now,
    private readonly copy: ((text: string) => Promise<void>) | null = null,
  ) {}

  async load(): Promise<void> {
    try {
      const saved = JSON.parse(await readFile(this.file, "utf8")) as { progress?: Record<string, BrokerProgress> };
      this.progress = Object.fromEntries(Object.entries(saved.progress ?? {}).filter(([, p]) => STATES.includes(p?.state) && !Number.isNaN(Date.parse(p.at))));
    } catch {
      this.progress = {};
    }
  }

  private save(): Promise<void> {
    return atomicWrite(this.file, JSON.stringify({ catalogVersion: this.catalog.version, progress: this.progress }));
  }

  status(): BrokerStatus {
    const now = this.now();
    const rows = this.catalog.brokers.map((b): BrokerRow => {
      const p = this.progress[b.id];
      const at = p ? Date.parse(p.at) : null;
      const active = p?.state === "requested" || p?.state === "removed";
      return {
        ...b,
        state: p?.state ?? "todo",
        at: p?.at ?? null,
        recheckDue: Boolean(active && at !== null && now - at >= this.catalog.recheckDays * DAY),
        expectedBy: p?.state === "requested" && at !== null ? new Date(at + b.removalDays * DAY).toISOString() : null,
      };
    });
    return {
      catalogVersion: this.catalog.version,
      reviewed: this.catalog.reviewed,
      note: this.catalog.note,
      brokers: rows,
      done: rows.filter((r) => r.state !== "todo" && !r.recheckDue).length,
      recheckDue: rows.filter((r) => r.recheckDue).length,
    };
  }

  recheckDueCount(): number {
    return this.status().recheckDue;
  }

  private broker(id: unknown): Broker {
    const broker = this.catalog.brokers.find((b) => b.id === id);
    if (!broker) throw new IpcError("not_found", "That company isn't in the list.");
    return broker;
  }

  /** Records progress; marking again (for a re-check) restarts the 90 days. */
  async mark(params: unknown): Promise<BrokerStatus> {
    const { id, state } = (params ?? {}) as { id?: unknown; state?: unknown };
    const broker = this.broker(id);
    if (!STATES.includes(state as BrokerState)) throw new IpcError("bad_params", "Expected todo, requested, removed or not_listed.");
    if (state === "todo") delete this.progress[broker.id];
    else this.progress[broker.id] = { state: state as BrokerState, at: new Date(this.now()).toISOString() };
    await this.save();
    return this.status();
  }

  /** The request letter for a broker, filled in; optionally put on the clipboard. */
  async template(params: unknown): Promise<{ subject: string; body: string; copied: boolean }> {
    const { id, name, email, copy } = (params ?? {}) as { id?: unknown; name?: unknown; email?: unknown; copy?: unknown };
    const broker = this.broker(id);
    const key = broker.template ?? "pdpl";
    const template = this.catalog.templates[key];
    if (!template) throw new IpcError("not_found", "No request letter for this company.");
    if (typeof name !== "string" || !name.trim() || name.length > 120) throw new IpcError("bad_params", "Enter your name.");
    if (typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new IpcError("bad_params", "Enter your email address.");
    const letter = fillTemplate(template, { broker: broker.name, name: name.trim(), email: email.trim() });
    let copied = false;
    if (copy === true && this.copy) await this.copy(`${letter.subject}\n\n${letter.body}`).then(() => (copied = true)).catch(() => undefined);
    return { ...letter, copied };
  }
}
