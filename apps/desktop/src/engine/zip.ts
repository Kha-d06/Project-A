/**
 * A minimal, bounded reader for ZIP archives (also .docx/.xlsx/.jar/.apk).
 * It lists entries from the central directory and inflates small members in
 * memory. Nothing is ever written to disk. Limits guard against zip bombs.
 */
import { inflateRawSync } from "node:zlib";

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  encrypted: boolean;
  localHeaderOffset: number;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
export const MAX_ENTRIES = 5000;

export function isZip(buffer: Buffer): boolean {
  return buffer.length >= 4 && buffer.readUInt32LE(0) === LOCAL_SIGNATURE;
}

export function listEntries(buffer: Buffer): ZipEntry[] {
  // The end-of-central-directory record is within the last 64 KiB + 22 bytes.
  const start = Math.max(0, buffer.length - 65_557);
  let eocd = -1;
  for (let i = buffer.length - 22; i >= start; i -= 1) {
    if (buffer.readUInt32LE(i) === EOCD_SIGNATURE) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const count = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];
  for (let n = 0; n < Math.min(count, MAX_ENTRIES); n += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== CENTRAL_SIGNATURE) break;
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const size = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, Math.min(buffer.length, offset + 46 + nameLength));
    entries.push({ name, method, compressedSize, size, encrypted: (flags & 1) === 1, localHeaderOffset });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** Inflates one member, or returns null if it is encrypted, unsupported or over the limit. */
export function readEntry(buffer: Buffer, entry: ZipEntry, maxBytes: number): Buffer | null {
  if (entry.encrypted || entry.size > maxBytes) return null;
  const at = entry.localHeaderOffset;
  if (at + 30 > buffer.length || buffer.readUInt32LE(at) !== LOCAL_SIGNATURE) return null;
  const dataStart = at + 30 + buffer.readUInt16LE(at + 26) + buffer.readUInt16LE(at + 28);
  const data = buffer.subarray(dataStart, dataStart + entry.compressedSize);
  try {
    if (entry.method === 0) return data.length <= maxBytes ? Buffer.from(data) : null;
    if (entry.method === 8) {
      // maxOutputLength stops a member that lies about its size.
      return inflateRawSync(data, { maxOutputLength: maxBytes });
    }
  } catch {
    return null;
  }
  return null;
}
