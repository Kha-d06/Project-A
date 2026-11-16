/** Walks a folder for scanning: files only, no symlinks followed, bounded. */
import { lstat, readdir } from "node:fs/promises";
import { join } from "node:path";

const SKIP_DIRS = new Set(["node_modules", ".git", "$Recycle.Bin", "System Volume Information"]);

export async function* walk(root: string, limit = 50_000): AsyncGenerator<string> {
  const stack = [root];
  let count = 0;
  while (stack.length && count < limit) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(path);
      } else if (entry.isFile()) {
        count += 1;
        yield path;
        if (count >= limit) return;
      }
    }
  }
}

export async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await lstat(path)).isDirectory();
  } catch {
    return false;
  }
}
