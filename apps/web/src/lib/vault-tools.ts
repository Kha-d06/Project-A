/** Password health checks and CSV import/export for the vault. Pure, so it is tested. */
import { type VaultItem, newItem } from "./vault";

// --- Strength ---------------------------------------------------------------------

const COMMON = new Set([
  "password", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwertyuiop", "abc123", "111111", "000000",
  "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon", "football", "baseball", "sunshine", "princess",
  "password1", "passw0rd", "p@ssw0rd", "qwerty123", "1q2w3e4r", "zaq12wsx", "trustno1", "master", "shadow", "superman",
]);

const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm", "01234567890"];

/**
 * A rough estimate of how many guesses a password would take, in bits. It is
 * deliberately pessimistic about patterns people use (common words, sequences,
 * repeats, a year or "!" at the end), so "strong" is not promised too easily.
 */
export function strengthBits(password: string): number {
  if (!password) return 0;
  const lower = password.toLowerCase();
  const base = lower.replace(/[0-9!@#$%^&*.?_-]+$/, "").replace(/^[0-9]+/, "");
  if (COMMON.has(lower) || COMMON.has(base) || COMMON.has(lower.replace(/[@4]/g, "a").replace(/0/g, "o").replace(/[1!]/g, "i").replace(/3/g, "e").replace(/\$/g, "s"))) return 10;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
  // Count runs of repeated characters and keyboard/alphabet sequences as one character each.
  let effective = 0;
  for (let i = 0; i < password.length; i++) {
    const prev = lower[i - 1];
    const current = lower[i]!;
    const repeated = prev === current;
    const sequential = prev !== undefined && SEQUENCES.some((sequence) => {
      const at = sequence.indexOf(prev);
      return at >= 0 && sequence[at + 1] === current;
    });
    effective += repeated || sequential ? 0.25 : 1;
  }
  // A trailing year or symbol adds almost nothing: everyone does it.
  if (/(19|20)\d\d[!.?]*$/.test(password)) effective -= 3;
  return Math.max(0, Math.round(effective * Math.log2(Math.max(pool, 2))));
}

export type StrengthLevel = "weak" | "fair" | "strong";

export function strengthLevel(password: string): StrengthLevel {
  const bits = strengthBits(password);
  return bits < 45 ? "weak" : bits < 70 ? "fair" : "strong";
}

// --- Health report ----------------------------------------------------------------

export interface HealthReport {
  weak: string[];
  /** Groups of item ids sharing one password (only groups of two or more). */
  reused: string[][];
  old: string[];
  /** Filled in separately, from the breach check. */
  breached: string[];
  score: number;
}

export const OLD_AFTER_DAYS = 365;

export function healthReport(items: VaultItem[], breached: string[] = [], now = new Date()): HealthReport {
  const logins = items.filter((item) => item.kind === "login" && item.password);
  const byPassword = new Map<string, string[]>();
  for (const item of logins) byPassword.set(item.password, [...(byPassword.get(item.password) ?? []), item.id]);
  const reused = [...byPassword.values()].filter((ids) => ids.length > 1);
  const weak = logins.filter((item) => strengthLevel(item.password) === "weak").map((item) => item.id);
  const cutoff = now.getTime() - OLD_AFTER_DAYS * 86_400_000;
  const old = logins.filter((item) => new Date(item.passwordChanged).getTime() < cutoff).map((item) => item.id);
  const problems = new Set([...weak, ...reused.flat(), ...breached]);
  const score = logins.length ? Math.round((100 * (logins.length - problems.size)) / logins.length) : 100;
  return { weak, reused, old, breached, score };
}

// --- CSV ---------------------------------------------------------------------------

/** RFC 4180 CSV: quoted fields, doubled quotes, newlines inside quotes. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  const input = text.replace(/^﻿/, "");
  for (let i = 0; i < input.length; i++) {
    const char = input[i]!;
    if (quoted) {
      if (char === '"' && input[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && input[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += char;
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((cell) => cell.trim()));
}

/** Column names used by Chrome, Edge, Safari, Firefox, Bitwarden, 1Password and LastPass exports. */
const COLUMNS: Record<keyof Pick<VaultItem, "title" | "url" | "username" | "password" | "notes">, string[]> = {
  title: ["name", "title", "login_name"],
  url: ["url", "login_uri", "website", "uri"],
  username: ["username", "login_username", "user", "email", "login"],
  password: ["password", "login_password"],
  notes: ["note", "notes", "extra", "comments"],
};

export interface ImportResult {
  items: VaultItem[];
  skipped: number;
}

export function importCsv(text: string, now = new Date()): ImportResult {
  const [header, ...rows] = parseCsv(text);
  if (!header) return { items: [], skipped: 0 };
  const names = header.map((cell) => cell.trim().toLowerCase());
  const column = (key: keyof typeof COLUMNS) => names.findIndex((name) => COLUMNS[key].includes(name));
  const index = { title: column("title"), url: column("url"), username: column("username"), password: column("password"), notes: column("notes") };
  if (index.password < 0 && index.notes < 0) throw new Error("This file has no password or notes column. Export it as CSV from your browser or password manager.");
  const items: VaultItem[] = [];
  let skipped = 0;
  for (const row of rows.slice(0, 20_000)) {
    const get = (i: number) => (i >= 0 ? (row[i] ?? "").trim() : "");
    const password = index.password >= 0 ? (row[index.password] ?? "") : "";
    const notes = get(index.notes);
    const url = get(index.url);
    if (!password && !notes) {
      skipped += 1;
      continue;
    }
    let title = get(index.title);
    if (!title && url) {
      try {
        title = new URL(url).hostname.replace(/^www\./, "");
      } catch {
        title = url;
      }
    }
    items.push(
      newItem(password ? "login" : "note", {
        title: (title || "Imported").slice(0, 200),
        url: url.slice(0, 2000),
        username: get(index.username).slice(0, 500),
        password: password.slice(0, 1000),
        notes: notes.slice(0, 10_000),
      }, now),
    );
  }
  return { items, skipped };
}

/**
 * Values are written exactly as saved (a password may start with "=" or "-"),
 * so the file is for importing into a password manager, not for opening in a
 * spreadsheet; the interface says so.
 */
function csvCell(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/** Chrome's format, which every password manager can import. */
export function exportCsv(items: VaultItem[]): string {
  const lines = [["name", "url", "username", "password", "note"].join(",")];
  for (const item of items) lines.push([item.title, item.url, item.username, item.password, item.notes].map(csvCell).join(","));
  return `${lines.join("\r\n")}\r\n`;
}

/** Does this item's address match a site (same registrable host or a subdomain)? */
export function matchesSite(item: VaultItem, host: string): boolean {
  try {
    const itemHost = new URL(item.url).hostname.replace(/^www\./, "");
    const target = host.replace(/^www\./, "");
    return itemHost === target || target.endsWith(`.${itemHost}`);
  } catch {
    return false;
  }
}
