import { readFile, rename, writeFile } from "node:fs/promises";

export interface DesktopSettings {
  serverUrl: string;
  watchFolders: string[];
  watchEnabled: boolean;
  autoQuarantine: boolean;
  useClamav: boolean;
  /** Off by default: sends each scanned file's SHA-256 to the server. */
  cloudLookup: boolean;
  language: "auto" | "en" | "ar";
  /** Watch these folders for mass encryption (detection only). */
  ransomwareWatch: boolean;
  protectedFolders: string[];
}

export function defaultSettings(downloads: string, protectedFolders: string[] = []): DesktopSettings {
  return {
    serverUrl: "http://localhost:8080",
    watchFolders: [downloads],
    watchEnabled: true,
    autoQuarantine: true,
    useClamav: true,
    cloudLookup: false,
    language: "auto",
    ransomwareWatch: true,
    protectedFolders,
  };
}

export async function loadSettings(file: string, defaults: DesktopSettings): Promise<DesktopSettings> {
  try {
    return { ...defaults, ...(JSON.parse(await readFile(file, "utf8")) as Partial<DesktopSettings>) };
  } catch {
    return defaults;
  }
}

export async function saveSettings(file: string, settings: DesktopSettings): Promise<void> {
  await writeFile(`${file}.tmp`, JSON.stringify(settings, null, 2));
  await rename(`${file}.tmp`, file);
}

/** Only accepts known keys with the right types, from the interface process. */
export function sanitizeChanges(changes: unknown): Partial<DesktopSettings> {
  if (!changes || typeof changes !== "object") return {};
  const input = changes as Record<string, unknown>;
  const out: Partial<DesktopSettings> = {};
  if (typeof input.serverUrl === "string") {
    const url = new URL(input.serverUrl);
    const local = ["localhost", "127.0.0.1"].includes(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
      throw new Error("Use an https:// address, except for a server on this computer.");
    }
    out.serverUrl = url.origin;
  }
  if (Array.isArray(input.watchFolders)) out.watchFolders = input.watchFolders.filter((f): f is string => typeof f === "string").slice(0, 20);
  if (Array.isArray(input.protectedFolders)) {
    out.protectedFolders = input.protectedFolders.filter((f): f is string => typeof f === "string").slice(0, 20);
  }
  for (const key of ["watchEnabled", "autoQuarantine", "useClamav", "cloudLookup", "ransomwareWatch"] as const) {
    if (typeof input[key] === "boolean") out[key] = input[key];
  }
  if (input.language === "auto" || input.language === "en" || input.language === "ar") out.language = input.language;
  return out;
}
