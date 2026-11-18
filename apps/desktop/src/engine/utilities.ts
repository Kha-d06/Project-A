/**
 * Clean-up utilities: find duplicate files, find what's taking up space, and
 * list installed programs so they can be removed. Everything runs locally.
 *
 * The heavy lifting (hashing) is injected so the pure grouping logic can be
 * tested on its own.
 */

export interface FileEntry {
  path: string;
  size: number;
}

// --- Duplicate finder -------------------------------------------------------------------

/** Group files by exact size; only groups of two or more can be duplicates. */
export function groupBySize(files: FileEntry[]): FileEntry[][] {
  const bySize = new Map<number, FileEntry[]>();
  for (const file of files) {
    if (file.size <= 0) continue; // empty files aren't interesting duplicates
    bySize.set(file.size, [...(bySize.get(file.size) ?? []), file]);
  }
  return [...bySize.values()].filter((group) => group.length > 1);
}

export interface DuplicateGroup {
  hash: string;
  size: number;
  paths: string[];
  /** Space that could be freed by keeping one copy. */
  wasted: number;
}

/**
 * Find duplicate files in three stages — size, then a quick partial hash, then
 * a full hash — so only genuine candidates are read in full. `hash` returns a
 * digest for (path, bytes): pass bytes=0 for a cheap prefix hash.
 */
export async function findDuplicates(
  files: FileEntry[],
  hash: (path: string, bytes: number) => Promise<string | null>,
  partialBytes = 4096,
): Promise<DuplicateGroup[]> {
  const groups: DuplicateGroup[] = [];
  for (const sized of groupBySize(files)) {
    // Stage 2: split the same-size group by a cheap prefix hash.
    const byPartial = new Map<string, FileEntry[]>();
    for (const file of sized) {
      const key = await hash(file.path, partialBytes);
      if (key === null) continue;
      byPartial.set(key, [...(byPartial.get(key) ?? []), file]);
    }
    for (const candidates of byPartial.values()) {
      if (candidates.length < 2) continue;
      // Stage 3: confirm with a full hash.
      const byFull = new Map<string, FileEntry[]>();
      for (const file of candidates) {
        const key = await hash(file.path, 0);
        if (key === null) continue;
        byFull.set(key, [...(byFull.get(key) ?? []), file]);
      }
      for (const [digest, dupes] of byFull) {
        if (dupes.length < 2) continue;
        groups.push({ hash: digest, size: dupes[0]!.size, paths: dupes.map((d) => d.path), wasted: dupes[0]!.size * (dupes.length - 1) });
      }
    }
  }
  return groups.sort((a, b) => b.wasted - a.wasted);
}

// --- Large files and folder sizes -------------------------------------------------------

export function largestFiles(files: FileEntry[], limit = 50): FileEntry[] {
  return [...files].sort((a, b) => b.size - a.size).slice(0, limit);
}

export interface FolderSize {
  path: string;
  size: number;
}

/**
 * Roll file sizes up to their immediate-child folders of `root`, for a simple
 * "what's using space" breakdown (a treemap's top level).
 */
export function folderBreakdown(files: FileEntry[], root: string): FolderSize[] {
  const base = root.endsWith("/") ? root : `${root}/`;
  const totals = new Map<string, number>();
  for (const file of files) {
    if (!file.path.startsWith(base)) continue;
    const rest = file.path.slice(base.length);
    const slash = rest.indexOf("/");
    const child = slash === -1 ? rest : rest.slice(0, slash); // first path segment under root
    const key = `${base}${child}`;
    totals.set(key, (totals.get(key) ?? 0) + file.size);
  }
  return [...totals.entries()].map(([path, size]) => ({ path, size })).sort((a, b) => b.size - a.size);
}

// --- Installed programs (uninstaller) ---------------------------------------------------

export interface InstalledApp {
  name: string;
  version: string | null;
  /** How to remove it, shown to the person (we never uninstall silently). */
  removeHint: string;
}

/** Parse `dpkg-query -W -f='${Package}\t${Version}\n'` (Debian/Ubuntu). */
export function parseDpkg(output: string): InstalledApp[] {
  const apps: InstalledApp[] = [];
  for (const line of output.split(/\r?\n/)) {
    const [name, version] = line.split("\t");
    if (name) apps.push({ name, version: version || null, removeHint: `sudo apt remove ${name}` });
  }
  return apps.sort((a, b) => a.name.localeCompare(b.name));
}

/** Parse Windows `Get-Package | ConvertTo-Json` output. */
export function parseWindowsPackages(json: string): InstalledApp[] {
  try {
    const data = JSON.parse(json || "[]") as unknown;
    const rows = (Array.isArray(data) ? data : [data]) as Record<string, unknown>[];
    return rows
      .filter((r) => typeof r?.Name === "string" && r.Name)
      .map((r) => ({ name: String(r.Name), version: r.Version ? String(r.Version) : null, removeHint: "Settings → Apps → Installed apps" }))
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    return [];
  }
}

/** Parse the names of app bundles in /Applications (macOS `ls`). */
export function parseMacApps(output: string): InstalledApp[] {
  return output
    .split(/\r?\n/)
    .filter((n) => n.endsWith(".app"))
    .map((n) => ({ name: n.replace(/\.app$/, ""), version: null, removeHint: "Drag the app to the Trash" }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
