/**
 * Scans one file with every local engine:
 *  1. signatures: SHA-256 against known malware (and the same for archive members);
 *  2. heuristics: name tricks, disguised programs, droppers, risky PDFs, macros,
 *     archive contents, the EICAR test string;
 *  3. ClamAV, when installed and enabled;
 *  4. optionally, a fingerprint-only lookup on the SENTINEL server.
 * Files are read, never opened with their own program or executed.
 */
import { open, stat } from "node:fs/promises";
import { basename } from "node:path";

import { clamScan } from "./clamav";
import {
  containsEicar,
  disguiseFindings,
  executableKind,
  extensionOf,
  nameFindings,
  pdfFindings,
  scriptFindings,
} from "./rules";
import { type SignatureStore, sha256OfBuffer, sha256OfFile } from "./signatures";
import { type Finding, type ScanResult, verdictFrom } from "./types";
import { isZip, listEntries, readEntry } from "./zip";

export const MAX_CONTENT_BYTES = 64 * 1024 * 1024;
const MAX_MEMBER_BYTES = 16 * 1024 * 1024;
const MAX_MEMBERS = 300;
const MAX_ARCHIVE_TOTAL = 128 * 1024 * 1024;

export interface ScanContext {
  signatures: SignatureStore;
  clamBinary?: string | null;
  /** Fingerprint-only lookup; returns a source name when the hash is known malware. */
  cloudLookup?: (sha256: string) => Promise<string | null>;
}

function contentFindings(name: string, content: Buffer, signatures: SignatureStore, member?: string): Finding[] {
  const findings: Finding[] = [];
  const tag = (list: Finding[]) => list.map((f) => (member ? { ...f, member } : f));
  if (containsEicar(content)) {
    findings.push({
      severity: "critical",
      rule: "eicar",
      title: "EICAR antivirus test file",
      detail: "The standard, harmless test pattern for antivirus software. It is reported exactly like real malware.",
      member,
    });
  }
  if (member) {
    const hash = sha256OfBuffer(content);
    if (signatures.has(hash)) {
      findings.push({
        severity: "critical",
        rule: "known_hash_member",
        title: `A file inside this archive is known malware (${member})`,
        detail: "Its fingerprint matches a sample reported to malware databases. Delete the archive.",
        member,
      });
    }
  }
  findings.push(...tag(nameFindings(name)), ...tag(disguiseFindings(name, content.subarray(0, 8))));
  findings.push(...tag(scriptFindings(name, content)), ...tag(pdfFindings(content)));
  return findings;
}

function archiveFindings(content: Buffer, signatures: SignatureStore): Finding[] {
  const entries = listEntries(content);
  const findings: Finding[] = [];
  const names = entries.map((entry) => entry.name.toLowerCase());
  if (names.some((name) => name.endsWith("vbaproject.bin"))) {
    findings.push({
      severity: "medium",
      rule: "office_macros",
      title: "Document contains macros",
      detail: "Macros are the most common way Office files deliver malware. Do not click “Enable content” unless you expected macros from a sender you trust.",
    });
  }
  const traversal = entries.filter((entry) => entry.name.startsWith("/") || entry.name.split(/[\\/]/).includes(".."));
  if (traversal.length) {
    findings.push({
      severity: "high",
      rule: "archive_traversal",
      title: "Archive tries to write files outside its folder",
      detail: "Unpacking it with vulnerable software could overwrite other files on this computer.",
    });
  }
  const total = entries.reduce((sum, entry) => sum + entry.size, 0);
  const packed = entries.reduce((sum, entry) => sum + entry.compressedSize, 0) || 1;
  if (total > 512 * 1024 * 1024 && total / packed > 100) {
    findings.push({
      severity: "high",
      rule: "archive_bomb",
      title: "Archive expands to an extreme size",
      detail: "Built to fill the disk or crash the program that opens it.",
    });
  }
  if (entries.some((entry) => entry.encrypted)) {
    findings.push({
      severity: "low",
      rule: "archive_encrypted",
      title: "Archive is password-protected",
      detail: "Encrypted contents cannot be checked by any scanner. Malware is often sent this way with the password in the message.",
    });
  }
  let read = 0;
  for (const entry of entries.slice(0, MAX_MEMBERS)) {
    if (entry.name.endsWith("/") || read > MAX_ARCHIVE_TOTAL) continue;
    const member = readEntry(content, entry, MAX_MEMBER_BYTES);
    if (!member) continue;
    read += member.length;
    const memberName = basename(entry.name);
    findings.push(...contentFindings(memberName, member, signatures, entry.name.slice(0, 200)));
    const kind = executableKind(member.subarray(0, 8));
    if (kind && !findings.some((f) => f.member === entry.name.slice(0, 200))) {
      findings.push({
        severity: "low",
        rule: "archive_program",
        title: `Archive contains a ${kind.toLowerCase()} (${memberName})`,
        detail: "Programs inside archives are a common way past email filters. Only run it if you know exactly what it is.",
        member: entry.name.slice(0, 200),
      });
    }
  }
  return findings;
}

async function readHead(path: string, size: number): Promise<Buffer> {
  const handle = await open(path, "r");
  try {
    const length = Math.min(size, MAX_CONTENT_BYTES);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, 0);
    return buffer;
  } finally {
    await handle.close();
  }
}

export async function scanFile(path: string, context: ScanContext): Promise<ScanResult> {
  const name = basename(path);
  const base: ScanResult = {
    path,
    name,
    size: 0,
    sha256: null,
    verdict: "not_scanned",
    findings: [],
    engines: [],
    scannedAt: new Date().toISOString(),
  };
  try {
    const info = await stat(path);
    if (!info.isFile()) return { ...base, error: "Not a regular file." };
    base.size = info.size;
    const sha256 = await sha256OfFile(path);
    base.sha256 = sha256;
    const findings: Finding[] = [];
    const engines = ["signatures", "heuristics"];

    if (context.signatures.has(sha256)) {
      findings.push({
        severity: "critical",
        rule: "known_hash",
        title: "This file is known malware",
        detail: "Its fingerprint matches a sample reported to MalwareBazaar or ThreatFox. Quarantine or delete it, and do not open it.",
      });
    }
    const content = await readHead(path, info.size);
    findings.push(...contentFindings(name, content, context.signatures));
    if (isZip(content)) findings.push(...archiveFindings(content, context.signatures));
    if (info.size > MAX_CONTENT_BYTES) {
      findings.push({
        severity: "info",
        rule: "partially_read",
        title: "Only the first 64 MB were inspected",
        detail: "The whole file was fingerprinted, but content rules only looked at the beginning.",
      });
    }

    if (context.clamBinary) {
      try {
        const clam = await clamScan(context.clamBinary, path);
        engines.push("clamav");
        if (clam.infected) {
          findings.push({
            severity: "critical",
            rule: "clamav",
            title: `ClamAV identified this file as ${clam.signature}`,
            detail: "It matches a signature in the ClamAV malware database.",
          });
        }
      } catch {
        // ClamAV is optional; its absence is shown in the engine list.
      }
    }
    if (context.cloudLookup && !findings.some((f) => f.rule === "known_hash")) {
      try {
        const source = await context.cloudLookup(sha256);
        engines.push("cloud");
        if (source) {
          findings.push({
            severity: "critical",
            rule: "known_hash_cloud",
            title: `This file is listed as malware by ${source}`,
            detail: "The SENTINEL server matched its fingerprint against its threat feeds.",
          });
        }
      } catch {
        // offline: local engines still ran
      }
    }
    if (extensionOf(name) && executableKind(content.subarray(0, 8)) && !findings.some((f) => f.severity !== "info")) {
      findings.push({
        severity: "info",
        rule: "is_program",
        title: "This is a program",
        detail: "No known threat was found, but scanners cannot tell what a program will do when it runs. Only run it if you trust where it came from.",
      });
    }
    return { ...base, findings, engines, verdict: verdictFrom(findings) };
  } catch (error) {
    return { ...base, error: error instanceof Error ? error.message : String(error) };
  }
}
