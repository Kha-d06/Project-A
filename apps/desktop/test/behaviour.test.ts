import { describe, expect, it } from "vitest";

import { BURST_FILES, RANSOM_RENAMES, RansomwareBurst, looksEncrypted, underAny } from "../src/engine/behaviour";

describe("ransomware burst detection", () => {
  it("halts a process that opens a burst of distinct files", () => {
    const burst = new RansomwareBurst(5000, 40);
    let halt = null;
    for (let i = 0; i < BURST_FILES; i++) halt = halt ?? burst.feed({ pid: 100, path: `/home/u/doc${i}.txt`, at: 1000 + i });
    expect(halt).not.toBeNull();
    expect(halt!.pid).toBe(100);
    expect(halt!.files).toBe(BURST_FILES);
  });

  it("does not halt slow, normal activity (window expiry)", () => {
    const burst = new RansomwareBurst(5000, 40);
    let halt = null;
    for (let i = 0; i < 100; i++) halt = halt ?? burst.feed({ pid: 7, path: `/home/u/f${i}.txt`, at: i * 1000 }); // 1 file/sec
    expect(halt).toBeNull();
  });

  it("counts each file once per window", () => {
    const burst = new RansomwareBurst(5000, 40);
    let halt = null;
    for (let i = 0; i < 100; i++) halt = halt ?? burst.feed({ pid: 9, path: "/home/u/same.txt", at: 1000 + i });
    expect(halt).toBeNull(); // same file reopened many times isn't a burst
  });

  it("halts on ransom-extension writes before the file-count threshold", () => {
    const burst = new RansomwareBurst(5000, 40);
    let halt = null;
    for (let i = 0; i < RANSOM_RENAMES; i++) halt = halt ?? burst.feed({ pid: 5, path: `/home/u/photo${i}.jpg.locked`, at: 1000 + i });
    expect(halt).not.toBeNull();
    expect(halt!.reason).toMatch(/ransomware extension/);
  });

  it("only trips once per process, then stays quiet until cleared", () => {
    const burst = new RansomwareBurst(5000, 3);
    expect(burst.feed({ pid: 1, path: "/a", at: 0 })).toBeNull();
    expect(burst.feed({ pid: 1, path: "/b", at: 1 })).toBeNull();
    expect(burst.feed({ pid: 1, path: "/c", at: 2 })).not.toBeNull();
    expect(burst.feed({ pid: 1, path: "/d", at: 3 })).toBeNull(); // already halted
    expect(burst.isHalted(1)).toBe(true);
    burst.clear(1);
    expect(burst.isHalted(1)).toBe(false);
  });
});

describe("helpers", () => {
  it("underAny matches paths inside watched roots only", () => {
    expect(underAny("/home/u/docs/a.txt", ["/home/u/docs"])).toBe(true);
    expect(underAny("/home/u/docs", ["/home/u/docs"])).toBe(true);
    expect(underAny("/home/u/other/a.txt", ["/home/u/docs"])).toBe(false);
    expect(underAny("/home/u/docsmore/a", ["/home/u/docs"])).toBe(false); // prefix but not a child
  });

  it("looksEncrypted spots ransomware extensions", () => {
    expect(looksEncrypted("/x/a.txt.locked")).toBe(true);
    expect(looksEncrypted("/x/a.wncry")).toBe(true);
    expect(looksEncrypted("/x/a.txt")).toBe(false);
  });
});
