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
  keepLocalAlerts: true,
  allowlist: [],
  blocklist: [],
};

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
