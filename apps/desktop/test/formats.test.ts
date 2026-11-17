import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { lnkFindings, parseSevenZipListing } from "../src/engine/formats";
import { EICAR } from "../src/engine/rules";
import { scanFile } from "../src/engine/scanner";
import { SignatureStore } from "../src/engine/signatures";

const SECTOR = 2048;

function dirRecord(name: Buffer, extent: number, size: number, isDir: boolean): Buffer {
  const length = 33 + name.length + (name.length % 2 === 0 ? 1 : 0);
  const record = Buffer.alloc(length);
  record[0] = length;
  record.writeUInt32LE(extent, 2);
  record.writeUInt32BE(extent, 6);
  record.writeUInt32LE(size, 10);
  record.writeUInt32BE(size, 14);
  record[25] = isDir ? 2 : 0;
  record[32] = name.length;
  name.copy(record, 33);
  return record;
}

/** A minimal but valid ISO 9660 image with the given root-level files. */
function iso(files: Record<string, Buffer>): Buffer {
  const names = Object.keys(files);
  const image = Buffer.alloc((19 + names.length) * SECTOR);
  const pvd = image.subarray(16 * SECTOR);
  pvd[0] = 1;
  pvd.write("CD001", 1, "latin1");
  pvd[6] = 1;
  dirRecord(Buffer.from([0]), 18, SECTOR, true).copy(pvd, 156);
  const terminator = image.subarray(17 * SECTOR);
  terminator[0] = 255;
  terminator.write("CD001", 1, "latin1");
  const root = image.subarray(18 * SECTOR);
  let offset = 0;
  for (const record of [dirRecord(Buffer.from([0]), 18, SECTOR, true), dirRecord(Buffer.from([1]), 18, SECTOR, true)]) {
    record.copy(root, offset);
    offset += record.length;
  }
  names.forEach((name, index) => {
    const extent = 19 + index;
    const data = files[name]!;
    const record = dirRecord(Buffer.from(`${name.toUpperCase()};1`, "latin1"), extent, data.length, false);
    record.copy(root, offset);
    offset += record.length;
    data.copy(image, extent * SECTOR);
  });
  return image;
}

async function tempFile(name: string, content: Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-formats-"));
  const path = join(dir, name);
  await writeFile(path, content);
  return path;
}

const signatures = new SignatureStore("/nonexistent/signatures.json");

describe("disk images", () => {
  it("lists and scans files inside an ISO without mounting it", async () => {
    const path = await tempFile("invoice.iso", iso({ "invoice.pdf.exe": Buffer.concat([Buffer.from("MZ"), Buffer.alloc(100)]), "eicar.com": EICAR }));
    const result = await scanFile(path, { signatures });
    const rules = result.findings.map((f) => f.rule);
    expect(rules).toEqual(expect.arrayContaining(["iso_programs", "double_extension", "eicar"]));
    expect(result.verdict).toBe("malicious");
    expect(result.findings.some((f) => f.rule === "eicar" && f.member === "EICAR.COM")).toBe(true);
  });
});

describe("shortcuts", () => {
  it("flags a .lnk that starts PowerShell", () => {
    const header = Buffer.from([0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]);
    const target = Buffer.from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -c iwr", "utf16le");
    const findings = lnkFindings(Buffer.concat([header, Buffer.alloc(68), target]));
    expect(findings[0]?.rule).toBe("lnk_interpreter");
    expect(findings[0]?.title).toContain("powershell");
    expect(lnkFindings(Buffer.concat([header, Buffer.alloc(68), Buffer.from("C:\\Users\\me\\report.docx", "utf16le")]))).toEqual([]);
  });
});

describe("7z and RAR", () => {
  it("parses 7-Zip listings", () => {
    const output = "Path = docs/readme.txt\nFolder = -\nEncrypted = -\n\nPath = invoice.pdf.exe\nFolder = -\nEncrypted = +\n\nPath = docs\nFolder = +\n";
    expect(parseSevenZipListing(output)).toEqual([
      { path: "docs/readme.txt", encrypted: false },
      { path: "invoice.pdf.exe", encrypted: true },
    ]);
  });

  it("says so when an archive could not be listed", async () => {
    const path = await tempFile("files.7z", Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), Buffer.alloc(64)]));
    const result = await scanFile(path, { signatures, sevenZip: null });
    expect(result.findings.map((f) => f.rule)).toContain("archive_not_listed");
    expect(result.verdict).toBe("no_known_threat");
  });
});
