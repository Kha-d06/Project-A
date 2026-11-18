import { describe, expect, it } from "vitest";

import {
  type FileEntry,
  findDuplicates,
  folderBreakdown,
  groupBySize,
  largestFiles,
  parseDpkg,
  parseMacApps,
  parseWindowsPackages,
} from "../src/engine/utilities";

describe("duplicate finder", () => {
  it("groups by size and ignores empty files and singletons", () => {
    const groups = groupBySize([
      { path: "/a", size: 100 },
      { path: "/b", size: 100 },
      { path: "/c", size: 50 },
      { path: "/d", size: 0 },
      { path: "/e", size: 0 },
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.map((f) => f.path).sort()).toEqual(["/a", "/b"]);
  });

  it("confirms duplicates with partial then full hashes", async () => {
    const files: FileEntry[] = [
      { path: "/x1", size: 10 },
      { path: "/x2", size: 10 }, // identical to x1
      { path: "/y", size: 10 }, // same size, different content
      { path: "/z", size: 20 }, // unique size
    ];
    // Model contents: x1/x2 share a prefix and full hash; y differs only in full hash.
    const contents: Record<string, { prefix: string; full: string }> = {
      "/x1": { prefix: "P", full: "FULL-A" },
      "/x2": { prefix: "P", full: "FULL-A" },
      "/y": { prefix: "P", full: "FULL-B" },
      "/z": { prefix: "Q", full: "FULL-C" },
    };
    const hash = async (path: string, bytes: number) => (bytes === 0 ? contents[path]!.full : contents[path]!.prefix);
    const dupes = await findDuplicates(files, hash);
    expect(dupes).toHaveLength(1);
    expect(dupes[0]!.paths.sort()).toEqual(["/x1", "/x2"]);
    expect(dupes[0]!.wasted).toBe(10); // one redundant copy of a 10-byte file
  });
});

describe("space usage", () => {
  it("lists the largest files", () => {
    const files = [
      { path: "/a", size: 5 },
      { path: "/b", size: 100 },
      { path: "/c", size: 50 },
    ];
    expect(largestFiles(files, 2).map((f) => f.path)).toEqual(["/b", "/c"]);
  });

  it("rolls sizes up to the top-level folders under root", () => {
    const files = [
      { path: "/home/u/docs/a", size: 10 },
      { path: "/home/u/docs/sub/b", size: 20 },
      { path: "/home/u/pics/c", size: 100 },
      { path: "/elsewhere/d", size: 999 }, // outside root
    ];
    const folders = folderBreakdown(files, "/home/u");
    expect(folders).toEqual([
      { path: "/home/u/pics", size: 100 },
      { path: "/home/u/docs", size: 30 },
    ]);
  });
});

describe("installed-program parsers", () => {
  it("parses dpkg, Windows packages and macOS apps", () => {
    const deb = parseDpkg("firefox\t120.0\ncurl\t7.88\n\n");
    expect(deb).toHaveLength(2);
    expect(deb[0]).toMatchObject({ name: "curl", version: "7.88" });
    expect(deb[0]!.removeHint).toContain("apt remove curl");

    const win = parseWindowsPackages(JSON.stringify([{ Name: "7-Zip", Version: "23.01" }, { Name: "" }]));
    expect(win).toHaveLength(1);
    expect(win[0]).toMatchObject({ name: "7-Zip", version: "23.01" });

    const mac = parseMacApps("Safari.app\nNotes.app\nReadme.txt\n");
    expect(mac.map((a) => a.name)).toEqual(["Notes", "Safari"]);
  });
});
