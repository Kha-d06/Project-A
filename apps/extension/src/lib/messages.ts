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
  | { type: "enroll"; linkCode?: string }
  | { type: "link"; code: string }
  | { type: "unlink" }
  | { type: "refresh-account" }
  | { type: "settings"; changes: Partial<Settings> }
  | { type: "clear-alerts" }
  | { type: "clear-cache" };

export interface Status {
  state: ProtectionState;
  settings: Settings;
  page: { url: string; result: CheckResult | null } | null;
  alerts: Alert[];
  account: AccountLink | null;
}

export type Response<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

export async function ask<T>(request: Request): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T> | undefined;
  if (!response) throw new Error("The extension background is not responding. Reload the extension.");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}
