import type { LanguageSetting } from "./i18n";
import type { ThemeSetting } from "./theme";
import type { BlockReason, ScreenTimeRule } from "./screentime";

export type PrivacyMode = "full" | "host";

export interface Settings {
  serverUrl: string;
  paused: boolean;
  /** "host" sends only the scheme and domain of each page, never paths or queries. */
  privacyMode: PrivacyMode;
  warnOnSuspicious: boolean;
  downloadChecks: boolean;
  /** Needs the optional host permission; off until the user turns it on. */
  hoverChecks: boolean;
  /** Block domains on the downloaded blocklist before they load (declarativeNetRequest). */
  preloadBlocking: boolean;
  /** On-screen assistant: needs optional page and cookie permissions; off by default. */
  assistant: boolean;
  language: LanguageSetting;
  theme: ThemeSetting;
  /** Optional: block well-known advertising and analytics trackers on other sites. */
  blockTrackers: boolean;
  /** Optional: mark dangerous results on Google, Bing and DuckDuckGo search pages. */
  searchBadges: boolean;
  /** From the linked account: domains a family or organisation group asked to block,
   * applied only because the account holder chose to. */
  familyBlocklist: string[];
  familyGroups: string[];
  /** Family rules the account holder chose to follow (from the linked account). */
  safeSearch: boolean;
  lockProtection: boolean;
  /** Family screen time rule, and whether it is blocking browsing right now. */
  screenTime: ScreenTimeRule | null;
  screenTimeBlocked: BlockReason | null;
  keepLocalAlerts: boolean;
  allowlist: string[];
  blocklist: string[];
}

declare const __SENTINEL_SERVER__: string;

export const DEFAULT_SETTINGS: Settings = {
  serverUrl: typeof __SENTINEL_SERVER__ === "string" ? __SENTINEL_SERVER__ : "http://localhost:8080",
  paused: false,
  privacyMode: "full",
  warnOnSuspicious: true,
  downloadChecks: true,
  hoverChecks: false,
  preloadBlocking: true,
  assistant: false,
  language: "auto",
  theme: "system",
  blockTrackers: false,
  searchBadges: false,
  familyBlocklist: [],
  familyGroups: [],
  safeSearch: false,
  lockProtection: false,
  screenTime: null,
  screenTimeBlocked: null,
  keepLocalAlerts: true,
  allowlist: [],
  blocklist: [],
};

/** Search pages where result badges can be shown (requested only when turned on). */
export const SEARCH_ORIGINS = [
  "https://www.google.com/*",
  "https://www.google.ae/*",
  "https://www.google.com.sa/*",
  "https://www.google.co.uk/*",
  "https://www.bing.com/*",
  "https://duckduckgo.com/*",
];

const KEY = "settings";

export async function loadSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(KEY);
  return { ...DEFAULT_SETTINGS, ...((stored[KEY] as Partial<Settings> | undefined) ?? {}) };
}

export async function saveSettings(changes: Partial<Settings>): Promise<Settings> {
  const next = { ...(await loadSettings()), ...changes };
  await chrome.storage.local.set({ [KEY]: next });
  return next;
}

/** Turns "Example.com", "https://example.com/path" or "*.example.com" into "example.com". */
export function normalizeHostEntry(entry: string): string | null {
  const trimmed = entry.trim().toLowerCase().replace(/^\*\./, "");
  if (!trimmed) return null;
  try {
    const host = new URL(trimmed.includes("://") ? trimmed : `http://${trimmed}`).hostname;
    return host.includes(".") ? host.replace(/\.$/, "") : null;
  } catch {
    return null;
  }
}
