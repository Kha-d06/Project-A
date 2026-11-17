/**
 * Ransomware activity watch (detection only). Encrypting malware rewrites many
 * files in a short time, makes their contents look random, often renames them
 * with a new extension and drops "how to decrypt" notes. This watches chosen
 * folders for that pattern and raises an alert so the person can disconnect the
 * computer quickly. It cannot stop the encryption.
 */
import { type FSWatcher, watch } from "node:fs";
import { open, stat } from "node:fs/promises";
import { basename, extname, join } from "node:path";

const WINDOW_MS = 60_000;
const ALERT_COOLDOWN_MS = 10 * 60_000;
export const HIGH_ENTROPY = 7.6;
export const MIN_RANDOM_FILES = 25;
export const MIN_RENAMED = 8;
const NOTE_NAME = /(readme|how|restore|decrypt|recover|instructions?)[^/\\]*(decrypt|files|recover|restore|ransom|readme)?[^/\\]*\.(txt|html?|hta|url)$/i;
const RANSOM_EXTENSIONS = /\.(locked|encrypted|enc|crypt|crypted|crypto|lockbit|ryk|conti|akira|blackcat|wncry|wcry|locky|cerber|zepto|odin|aes|rsa|pay|ransom)$/i;
// Formats that are already compressed or encrypted and look random anyway.
const NATURALLY_RANDOM = new Set([".zip", ".7z", ".rar", ".gz", ".xz", ".bz2", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".mp3", ".mp4", ".mov", ".mkv", ".avi", ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".apk", ".jar", ".gpg", ".kdbx"]);

export function entropy(buffer: Buffer): number {
  if (!buffer.length) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const byte of buffer) counts[byte]! += 1;
  let bits = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / buffer.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export interface ActivityEvent {
  path: string;
  at: number;
  /** Entropy of the file's first 64 KB after the change, when it could be read. */
  entropy?: number;
}

export interface RansomwareAlert {
  reasons: string[];
  examples: string[];
}

/** Pure, testable detector: feed it events, get an alert when the pattern appears. */
export class RansomwareDetector {
  private events: ActivityEvent[] = [];
  private lastAlert = -Infinity;

  feed(event: ActivityEvent): RansomwareAlert | null {
    this.events = [...this.events.filter((e) => event.at - e.at < WINDOW_MS && e.path !== event.path), event];
    if (event.at - this.lastAlert < ALERT_COOLDOWN_MS) return null;
    const reasons: string[] = [];
    const notes = this.events.filter((e) => NOTE_NAME.test(basename(e.path)));
    const renamed = this.events.filter((e) => RANSOM_EXTENSIONS.test(e.path));
    const random = this.events.filter((e) => (e.entropy ?? 0) >= HIGH_ENTROPY && !NATURALLY_RANDOM.has(extname(e.path).toLowerCase()));
    if (renamed.length >= MIN_RENAMED) reasons.push(`${renamed.length} files renamed with an extension used by ransomware`);
    if (random.length >= MIN_RANDOM_FILES) reasons.push(`${random.length} documents rewritten with random-looking contents within a minute`);
    if (notes.length && (renamed.length || random.length >= 5)) reasons.push(`a note that looks like a ransom demand appeared (${basename(notes[0]!.path)})`);
    if (!reasons.length) return null;
    this.lastAlert = event.at;
    return { reasons, examples: [...renamed, ...random, ...notes].slice(0, 5).map((e) => e.path) };
  }
}

export class RansomwareMonitor {
  private watchers: FSWatcher[] = [];
  private detector = new RansomwareDetector();

  constructor(private readonly onAlert: (alert: RansomwareAlert) => void) {}

  set(folders: string[]): void {
    this.close();
    for (const folder of folders) {
      try {
        const watcher = watch(folder, { recursive: true, persistent: false }, (_type, filename) => {
          if (filename) void this.observe(join(folder, String(filename)));
        });
        watcher.on("error", () => undefined);
        this.watchers.push(watcher);
      } catch {
        // folder missing; shown as not watched in the interface
      }
    }
  }

  private async observe(path: string): Promise<void> {
    let value: number | undefined;
    try {
      const info = await stat(path);
      if (!info.isFile()) return;
      const handle = await open(path, "r");
      try {
        const buffer = Buffer.alloc(Math.min(info.size, 64 * 1024));
        await handle.read(buffer, 0, buffer.length, 0);
        value = entropy(buffer);
      } finally {
        await handle.close();
      }
    } catch {
      value = undefined; // deleted or locked: still counts for renames and notes
    }
    const alert = this.detector.feed({ path, at: Date.now(), entropy: value });
    if (alert) this.onAlert(alert);
  }

  close(): void {
    for (const watcher of this.watchers) watcher.close();
    this.watchers = [];
  }
}
