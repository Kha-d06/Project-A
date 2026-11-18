import { readFile, rename, writeFile } from "node:fs/promises";

import { sanitizeExclusions } from "./protection";
import { DEFAULT_SCHEDULE, type Schedule, sanitizeSchedule } from "./schedule";

export interface DesktopSettings {
  serverUrl: string;
  watchFolders: string[];
  watchEnabled: boolean;
  autoQuarantine: boolean;
  useClamav: boolean;
  /** Off by default: sends each scanned file's SHA-256 to the server. */
  cloudLookup: boolean;
  language: "auto" | "en" | "ar";
  /** Colour theme: follow the system, or always light or dark. */
  theme: "system" | "light" | "dark";
  /** Watch these folders for mass encryption (detection only). */
  ransomwareWatch: boolean;
  protectedFolders: string[];
  /** Off until the person turns it on: scans may be started from their Qalaa account. */
  allowRemote: boolean;
  deviceName: string;
  /** Scheduled scans. `lastScheduledScan` is written only by the app itself. */
  scanSchedule: Schedule;
  scheduledScanKind: "quick" | "full";
  lastScheduledScan: string | null;
  /** Notify when an app starts using the camera or microphone. */
  privacyWatch: boolean;
  /** Startup items already seen, so new ones can be pointed out. */
  knownStartup: string[];
  /** Encrypted backups. Folders and destination are chosen through system dialogs only. */
  backupFolders: string[];
  backupDestination: string | null;
  backupSchedule: Schedule;
  backupKeep: number;
  lastBackup: { at: string; file: string; files: number; bytes: number } | null;
  lastBackupError: string | null;
  /** Download and install updates from the Qalaa server automatically. */
  autoUpdate: boolean;
  /** Files and folders never scanned (absolute paths). */
  exclusions: string[];
  /** Scan USB drives and memory cards when they are connected. */
  scanRemovable: boolean;
  /** Hidden decoy files in protected folders: any change is an early ransomware alarm. */
  ransomwareDecoys: boolean;
  /** Linux/macOS: scan programs dropped in temp and bin folders; report new startup entries. */
  watchSystemChanges: boolean;
  /** Silent mode: no pop-ups or scheduled work until this time (ISO), or null. */
  silentUntil: string | null;
}

export function defaultSettings(downloads: string, protectedFolders: string[] = [], deviceName = "This computer"): DesktopSettings {
  return {
    serverUrl: "http://localhost:8080",
    watchFolders: [downloads],
    watchEnabled: true,
    autoQuarantine: true,
    useClamav: true,
    cloudLookup: false,
    language: "auto",
    theme: "system",
    exclusions: [],
    scanRemovable: true,
    ransomwareDecoys: true,
    watchSystemChanges: true,
    silentUntil: null,
    ransomwareWatch: true,
    protectedFolders,
    allowRemote: false,
    deviceName,
    scanSchedule: { frequency: "weekly", day: 0, hour: 12 },
    scheduledScanKind: "quick",
    lastScheduledScan: null,
    privacyWatch: true,
    knownStartup: [],
    backupFolders: [],
    backupDestination: null,
    backupSchedule: { ...DEFAULT_SCHEDULE },
    backupKeep: 5,
    lastBackup: null,
    lastBackupError: null,
    autoUpdate: true,
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
  if (typeof input.deviceName === "string" && input.deviceName.trim()) out.deviceName = input.deviceName.trim().slice(0, 80);
  const scan = sanitizeSchedule(input.scanSchedule);
  if (scan) out.scanSchedule = scan;
  const backup = sanitizeSchedule(input.backupSchedule);
  if (backup) out.backupSchedule = backup;
  if (input.scheduledScanKind === "quick" || input.scheduledScanKind === "full") out.scheduledScanKind = input.scheduledScanKind;
  if (Number.isInteger(input.backupKeep) && (input.backupKeep as number) >= 1 && (input.backupKeep as number) <= 50) out.backupKeep = input.backupKeep as number;
  const exclusions = sanitizeExclusions(input.exclusions);
  if (exclusions) out.exclusions = exclusions;
  if (input.silentUntil === null || (typeof input.silentUntil === "string" && Number.isFinite(Date.parse(input.silentUntil)))) {
    // At most a day ahead: silent mode must not be left on by accident for weeks.
    out.silentUntil = input.silentUntil === null ? null : new Date(Math.min(Date.parse(input.silentUntil), Date.now() + 24 * 3_600_000)).toISOString();
  }
  for (const key of ["watchEnabled", "autoQuarantine", "useClamav", "cloudLookup", "ransomwareWatch", "allowRemote", "privacyWatch", "autoUpdate", "scanRemovable", "ransomwareDecoys", "watchSystemChanges"] as const) {
    if (typeof input[key] === "boolean") out[key] = input[key];
  }
  if (input.language === "auto" || input.language === "en" || input.language === "ar") out.language = input.language;
  if (input.theme === "system" || input.theme === "light" || input.theme === "dark") out.theme = input.theme;
  return out;
}
