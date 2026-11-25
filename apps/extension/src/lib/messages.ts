import type { AccountLink } from "./api";
import type { Settings } from "./settings";
import type { Alert, CheckResult, ProtectionState, Verdict } from "./types";

/** Messages the extension pages send to the background service worker. */
export type Request =
  | { type: "status"; tabId?: number; url?: string }
  | { type: "check"; url: string }
  | { type: "verdict-for"; url: string }
  | { type: "proceed"; url: string; tabId?: number }
  | { type: "go-back"; url: string; verdict: Verdict }
  | { type: "hover"; href: string }
  | { type: "search-check"; urls: string[] }
  | { type: "assistant-summary"; url: string; resourceHosts: string[] }
  | { type: "assistant-ask"; url: string; question: string; hasPasswordField: boolean }
  | { type: "enroll"; linkCode?: string }
  | { type: "link"; code: string }
  | { type: "unlink" }
  | { type: "refresh-account" }
  | { type: "apply-rules" }
  | { type: "settings"; changes: Partial<Settings> }
  | { type: "clear-alerts" }
  | { type: "clear-cache" }
  | { type: "vault-status"; url?: string }
  | { type: "vault-unlock"; master: string }
  | { type: "vault-lock" }
  | { type: "vault-fill"; tabId: number; url: string; itemId: string }
  | { type: "vault-secret"; url: string; itemId: string }
  | { type: "vault-totp"; url: string; itemId: string }
  | { type: "new-alias"; url: string };

export interface VaultLogin {
  id: string;
  title: string;
  username: string;
  /** True when this login has a two-factor secret, so the popup can offer its code. */
  hasTotp: boolean;
}

export interface VaultStatus {
  linked: boolean;
  unlocked: boolean;
  /** Logins saved for the page in the active tab (no passwords). */
  logins: VaultLogin[];
  /** Why filling would be refused on this page, if it would. */
  refusal: "not_https" | "dangerous_site" | null;
}

export interface Status {
  state: ProtectionState;
  settings: Settings;
  page: { url: string; result: CheckResult | null } | null;
  alerts: Alert[];
  account: AccountLink | null;
  /** Domains blocked before they load, from the downloaded blocklist. */
  preloadedCount: number;
}

export type Response<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

export async function ask<T>(request: Request): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T> | undefined;
  if (!response) throw new Error("The extension background is not responding. Reload the extension.");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}
