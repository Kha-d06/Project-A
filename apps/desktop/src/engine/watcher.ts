/**
 * Watches folders (by default Downloads) and scans each new file once it has
 * stopped changing. Partial downloads are ignored until the browser renames
 * them to their final name.
 */
import { type FSWatcher, watch } from "node:fs";
import { stat } from "node:fs/promises";
import { join } from "node:path";

const PARTIAL = /\.(crdownload|part|partial|download|tmp|opdownload)$/i;
const SETTLE_MS = 1500;
const MAX_WAIT_MS = 10 * 60 * 1000;

export class FolderWatcher {
  private watchers = new Map<string, FSWatcher>();
  private pending = new Map<string, NodeJS.Timeout>();

  constructor(private readonly onFile: (path: string) => void, private readonly settleMs = SETTLE_MS) {}

  get folders(): string[] {
    return [...this.watchers.keys()];
  }

  set(folders: string[]): void {
    for (const [folder, watcher] of this.watchers) {
      if (!folders.includes(folder)) {
        watcher.close();
        this.watchers.delete(folder);
      }
    }
    for (const folder of folders) {
      if (this.watchers.has(folder)) continue;
      try {
        const watcher = watch(folder, { persistent: false }, (_event, filename) => {
          if (filename && !PARTIAL.test(String(filename)) && !String(filename).startsWith(".")) {
            this.schedule(join(folder, String(filename)));
          }
        });
        watcher.on("error", () => this.watchers.delete(folder));
        this.watchers.set(folder, watcher);
      } catch {
        // folder missing or not readable; reported by the interface
      }
    }
  }

  private schedule(path: string, started = Date.now(), lastSize = -1): void {
    clearTimeout(this.pending.get(path));
    this.pending.set(
      path,
      setTimeout(async () => {
        this.pending.delete(path);
        try {
          const info = await stat(path);
          if (!info.isFile()) return;
          if (info.size !== lastSize && Date.now() - started < MAX_WAIT_MS) {
            this.schedule(path, started, info.size); // still being written
            return;
          }
          this.onFile(path);
        } catch {
          // removed or renamed before it settled
        }
      }, this.settleMs),
    );
  }

  close(): void {
    for (const watcher of this.watchers.values()) watcher.close();
    for (const timer of this.pending.values()) clearTimeout(timer);
    this.watchers.clear();
    this.pending.clear();
  }
}
