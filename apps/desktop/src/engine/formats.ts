/**
 * Formats used to slip malware past email filters: ISO disk images, Windows
 * shortcuts (.lnk) and 7z/RAR archives. Contents are read, never extracted to
 * disk and never run.
 */
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { delimiter, join } from "node:path";

import { extensionOf, nameFindings } from "./rules";
import type { Finding } from "./types";

// --- ISO 9660 disk images -------------------------------------------------------------

const SECTOR = 2048;
const MAX_ISO_ENTRIES = 2000;
const MAX_ISO_DEPTH = 8;

export interface IsoEntry {
  path: string;
  extent: number;
  size: number;
}

export function isIso(head: Buffer): boolean {
  return head.length >= 16 * SECTOR + 6 && head[16 * SECTOR] === 1 && head.toString("latin1", 16 * SECTOR + 1, 16 * SECTOR + 6) === "CD001";
}

async function readAt(handle: FileHandle, offset: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, offset);
  return buffer.subarray(0, bytesRead);
}

/** Lists files in an ISO 9660 image (primary volume descriptor only). */
export async function listIso(handle: FileHandle): Promise<IsoEntry[]> {
  const pvd = await readAt(handle, 16 * SECTOR, SECTOR);
  const root = pvd.subarray(156, 156 + 34);
  const entries: IsoEntry[] = [];
  const queue: { extent: number; size: number; prefix: string; depth: number }[] = [
    { extent: root.readUInt32LE(2), size: root.readUInt32LE(10), prefix: "", depth: 0 },
  ];
  const seen = new Set<number>();
  while (queue.length && entries.length < MAX_ISO_ENTRIES) {
    const dir = queue.shift()!;
    if (seen.has(dir.extent) || dir.depth > MAX_ISO_DEPTH) continue;
    seen.add(dir.extent);
    const data = await readAt(handle, dir.extent * SECTOR, Math.min(dir.size, 1024 * 1024));
    let offset = 0;
    while (offset < data.length && entries.length < MAX_ISO_ENTRIES) {
      const length = data[offset] ?? 0;
      if (length === 0) {
        offset = (Math.floor(offset / SECTOR) + 1) * SECTOR; // records never span sectors
        continue;
      }
      const record = data.subarray(offset, offset + length);
      offset += length;
      if (record.length < 34) break;
      const nameLength = record[32] ?? 0;
      const rawName = record.toString("latin1", 33, 33 + nameLength);
      if (rawName === "\u0000" || rawName === "\u0001") continue; // "." and ".."
      const name = rawName.replace(/;\d+$/, "").replace(/\.$/, "");
      const extent = record.readUInt32LE(2);
      const size = record.readUInt32LE(10);
      const isDir = ((record[25] ?? 0) & 2) === 2;
      if (isDir) queue.push({ extent, size, prefix: `${dir.prefix}${name}/`, depth: dir.depth + 1 });
      else entries.push({ path: `${dir.prefix}${name}`, extent, size });
    }
  }
  return entries;
}

export async function readIsoEntry(handle: FileHandle, entry: IsoEntry, maxBytes: number): Promise<Buffer | null> {
  if (entry.size > maxBytes) return null;
  return readAt(handle, entry.extent * SECTOR, entry.size);
}

export function isoFinding(entries: IsoEntry[]): Finding[] {
  const runnable = entries.filter((entry) => ["exe", "scr", "lnk", "bat", "cmd", "js", "vbs", "hta", "msi", "dll"].includes(extensionOf(entry.path)));
  if (!runnable.length) return [];
  return [
    {
      severity: "medium",
      rule: "iso_programs",
      title: `Disk image contains programs or shortcuts (${runnable.slice(0, 3).map((e) => e.path).join(", ")})`,
      detail: "Malware is often sent inside .iso or .img files, which Windows opens with a double click and which used to bypass download warnings. Do not run anything inside unless you expected it.",
    },
  ];
}

// --- Windows shortcuts (.lnk) ----------------------------------------------------------

const LNK_MAGIC = Buffer.from([0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]);
const INTERPRETERS = /\b(powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|bitsadmin|certutil|msiexec|forfiles|conhost)\b/i;

export function isLnk(head: Buffer): boolean {
  return head.length >= 8 && head.subarray(0, 8).equals(LNK_MAGIC);
}

export function lnkFindings(content: Buffer): Finding[] {
  if (!isLnk(content)) return [];
  const text = `${content.toString("latin1")}\n${content.toString("utf16le")}`.replace(/[^\x20-\x7e\n]/g, "");
  const match = INTERPRETERS.exec(text);
  if (!match) return [];
  return [
    {
      severity: "high",
      rule: "lnk_interpreter",
      title: `Shortcut starts ${match[1]?.toLowerCase()}`,
      detail: "This shortcut does not open a document: it runs a command interpreter or script host, a common first step of malware delivered in archives and disk images. Do not open it.",
    },
  ];
}

// --- 7z and RAR ----------------------------------------------------------------------

const SEVEN_ZIP = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
const RAR = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]);

export function archiveKind(head: Buffer): "7z" | "rar" | null {
  if (head.subarray(0, 6).equals(SEVEN_ZIP)) return "7z";
  if (head.subarray(0, 6).equals(RAR)) return "rar";
  return null;
}

export async function findSevenZip(): Promise<string | null> {
  const names = process.platform === "win32" ? ["7z.exe", "7za.exe", "7zz.exe"] : ["7zz", "7z", "7za"];
  const dirs = [...(process.env.PATH ?? "").split(delimiter), "C:\\Program Files\\7-Zip", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"].filter(Boolean);
  for (const name of names) {
    for (const dir of dirs) {
      try {
        await access(join(dir, name));
        return join(dir, name);
      } catch {
        // keep looking
      }
    }
  }
  return null;
}

export interface ListedMember {
  path: string;
  encrypted: boolean;
}

/** Parses `7z l -slt -ba` output. */
export function parseSevenZipListing(stdout: string): ListedMember[] {
  return stdout
    .split(/\r?\n\r?\n/)
    .map((block) => {
      const path = /^Path = (.+)$/m.exec(block)?.[1]?.trim();
      const folder = /^Folder = \+$/m.test(block) || /^Attributes = D/m.test(block);
      return path && !folder ? { path, encrypted: /^Encrypted = \+$/m.test(block) } : null;
    })
    .filter((item): item is ListedMember => item !== null);
}

export function listWithSevenZip(binary: string, path: string): Promise<ListedMember[]> {
  return new Promise((resolve, reject) => {
    // -p- refuses to prompt for a password; listing never extracts anything.
    execFile(binary, ["l", "-slt", "-ba", "-p-", path], { timeout: 60_000, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(parseSevenZipListing(String(stdout)));
    });
  });
}

export function listedArchiveFindings(kind: string, members: ListedMember[]): Finding[] {
  const findings: Finding[] = [];
  const runnable = members.filter((m) => ["exe", "scr", "lnk", "bat", "cmd", "js", "vbs", "hta", "msi", "ps1", "iso", "img"].includes(extensionOf(m.path)));
  if (runnable.length) {
    findings.push({
      severity: "medium",
      rule: "archive_runnable_listed",
      title: `${kind.toUpperCase()} archive contains programs or scripts (${runnable.slice(0, 3).map((m) => m.path).join(", ")})`,
      detail: "Programs inside archives are a common way past email filters. Only run them if you know exactly what they are.",
    });
  }
  for (const member of members.slice(0, 500)) {
    for (const finding of nameFindings(member.path)) findings.push({ ...finding, member: member.path.slice(0, 200) });
  }
  if (members.some((m) => m.encrypted)) {
    findings.push({
      severity: "low",
      rule: "archive_encrypted",
      title: "Archive is password-protected",
      detail: "Encrypted contents cannot be checked by any scanner.",
    });
  }
  return findings;
}
