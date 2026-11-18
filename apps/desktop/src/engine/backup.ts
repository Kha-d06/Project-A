/**
 * Encrypted backups of chosen folders into one file, for a USB drive, a NAS or
 * a folder that a cloud service syncs (OneDrive, iCloud Drive, Google Drive,
 * Dropbox). The cloud provider only ever sees ciphertext.
 *
 * Format (all integers big-endian):
 *   "SNTLBK01" | salt (16) | records…
 *   record = length u32 | iv (12) | tag (16) | ciphertext(length)
 * Each record is AES-256-GCM with the key from scrypt(password, salt) and the
 * record's sequence number as associated data, so records cannot be reordered,
 * dropped or mixed between backups without failing authentication. The last
 * record is an END record with the file count, so a cut-off backup is detected.
 * Record plaintext starts with a type byte:
 *   1 FILE  JSON {path, size, mtime}  (path is relative, with "/" separators)
 *   2 DATA  up to 1 MiB of the current file
 *   3 EOF   end of the current file
 *   9 END   JSON {files, bytes, created}
 */
import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb } from "node:crypto";
import { createReadStream } from "node:fs";
import { type FileHandle, lstat, mkdir, open, readdir, rename, rm, stat, utimes } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

const MAGIC = Buffer.from("SNTLBK01");
const SALT_BYTES = 16;
const CHUNK = 1024 * 1024;
const MAX_RECORD = CHUNK + 64 * 1024;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export const MIN_PASSWORD_LENGTH = 10;

export class BackupError extends Error {}

function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolvePromise, reject) =>
    scryptCb(password.normalize("NFC"), salt, 32, SCRYPT, (error, key) => (error ? reject(error) : resolvePromise(key))),
  );
}

function seqBuffer(seq: number): Buffer {
  const aad = Buffer.alloc(8);
  aad.writeBigUInt64BE(BigInt(seq));
  return aad;
}

export interface BackupProgress {
  files: number;
  bytes: number;
  current: string | null;
}

export interface BackupSummary {
  file: string;
  files: number;
  bytes: number;
  skipped: string[];
  created: string;
}

async function* filesIn(root: string, limit = 200_000): AsyncGenerator<string> {
  const stack = [root];
  let count = 0;
  while (stack.length) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      // Links are skipped: following them could leave the chosen folder or loop.
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) stack.push(path);
      else if (entry.isFile()) {
        if (++count > limit) return;
        yield path;
      }
    }
  }
}

class RecordWriter {
  private seq = 0;
  constructor(
    private readonly handle: FileHandle,
    private readonly key: Buffer,
  ) {}

  async write(type: number, body: Buffer): Promise<void> {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(seqBuffer(this.seq++));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from([type])), cipher.update(body), cipher.final()]);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(ciphertext.length);
    await this.handle.write(Buffer.concat([header, iv, cipher.getAuthTag(), ciphertext]));
  }
}

/**
 * Back up `sources` (folders) into a new file in `destinationDir`. The file is
 * written under a temporary name and renamed when complete.
 */
export async function createBackup(
  sources: string[],
  destinationDir: string,
  password: string,
  onProgress: (progress: BackupProgress) => void = () => undefined,
  now: Date = new Date(),
): Promise<BackupSummary> {
  if (password.length < MIN_PASSWORD_LENGTH) throw new BackupError(`Use a password of at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (!sources.length) throw new BackupError("Choose at least one folder to back up.");
  const destination = resolve(destinationDir);
  for (const source of sources) {
    const from = resolve(source);
    if (destination === from || destination.startsWith(from + sep)) throw new BackupError("The backup cannot be saved inside a folder it backs up.");
  }
  await mkdir(destination, { recursive: true });
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
  const file = join(destination, `Qalaa-backup-${stamp}.sbk`);
  const partial = `${file}.part`;
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveKey(password, salt);
  const handle = await open(partial, "wx", 0o600);
  const summary: BackupSummary = { file, files: 0, bytes: 0, skipped: [], created: now.toISOString() };
  try {
    await handle.write(Buffer.concat([MAGIC, salt]));
    const writer = new RecordWriter(handle, key);
    const usedNames = new Set<string>();
    for (const source of sources) {
      const root = resolve(source);
      // Each source becomes a top-level folder in the backup, named after it.
      let top = basename(root) || "folder";
      for (let n = 2; usedNames.has(top); n++) top = `${basename(root)} (${n})`;
      usedNames.add(top);
      for await (const path of filesIn(root)) {
        const info = await stat(path).catch(() => null);
        if (!info) continue;
        const rel = [top, ...relative(root, path).split(sep)].join("/");
        onProgress({ files: summary.files, bytes: summary.bytes, current: rel });
        let bytes = 0;
        try {
          await writer.write(1, Buffer.from(JSON.stringify({ path: rel, size: info.size, mtime: info.mtime.toISOString() })));
          for await (const chunk of createReadStream(path, { highWaterMark: CHUNK })) {
            await writer.write(2, chunk as Buffer);
            bytes += (chunk as Buffer).length;
          }
          await writer.write(3, Buffer.alloc(0));
          summary.files += 1;
          summary.bytes += bytes;
        } catch {
          // Locked or vanished mid-read. Its EOF is still written so the archive stays consistent.
          await writer.write(3, Buffer.from("skipped"));
          summary.skipped.push(rel);
        }
      }
    }
    await writer.write(9, Buffer.from(JSON.stringify({ files: summary.files, bytes: summary.bytes, created: summary.created })));
    await handle.sync();
  } catch (error) {
    await handle.close();
    await rm(partial, { force: true });
    throw error;
  }
  await handle.close();
  await rename(partial, file);
  return summary;
}

/** Reads records in order, verifying each one. */
async function* readRecords(file: string, password: string): AsyncGenerator<{ type: number; body: Buffer }> {
  const handle = await open(file, "r");
  try {
    const head = Buffer.alloc(MAGIC.length + SALT_BYTES);
    const { bytesRead } = await handle.read(head, 0, head.length, 0);
    if (bytesRead < head.length || !head.subarray(0, MAGIC.length).equals(MAGIC)) throw new BackupError("This is not a Qalaa backup file.");
    const key = await deriveKey(password, head.subarray(MAGIC.length));
    let position = head.length;
    let seq = 0;
    const fixed = Buffer.alloc(4 + 12 + 16);
    for (;;) {
      const got = (await handle.read(fixed, 0, fixed.length, position)).bytesRead;
      if (got === 0) throw new BackupError("The backup file is incomplete: it ends before its last record.");
      if (got < fixed.length) throw new BackupError("The backup file is damaged.");
      const length = fixed.readUInt32BE(0);
      if (length < 1 || length > MAX_RECORD) throw new BackupError("The backup file is damaged.");
      const ciphertext = Buffer.alloc(length);
      if ((await handle.read(ciphertext, 0, length, position + fixed.length)).bytesRead < length) throw new BackupError("The backup file is incomplete.");
      position += fixed.length + length;
      const decipher = createDecipheriv("aes-256-gcm", key, fixed.subarray(4, 16));
      decipher.setAAD(seqBuffer(seq));
      decipher.setAuthTag(fixed.subarray(16, 32));
      let plain: Buffer;
      try {
        plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch {
        throw new BackupError(seq === 0 ? "Wrong password, or the backup file is damaged." : "The backup file is damaged or was changed.");
      }
      seq += 1;
      yield { type: plain[0]!, body: plain.subarray(1) };
      if (plain[0] === 9) return;
    }
  } finally {
    await handle.close();
  }
}

/** Rejects absolute paths, drive letters, "..", empty and control-character segments. */
export function safeRelative(path: string): string[] | null {
  if (typeof path !== "string" || !path || path.length > 4096) return null;
  const parts = path.split("/");
  for (const part of parts) {
    if (!part || part === "." || part === ".." || /[\\:\u0000-\u001f]/.test(part)) return null;
  }
  return parts;
}

export interface RestoreSummary {
  files: number;
  bytes: number;
  created: string;
  skippedInBackup: number;
}

/**
 * Check every record of a backup, or restore it into `target` when given.
 * Restoring writes into a new folder only, so nothing existing is overwritten.
 */
export async function readBackup(
  file: string,
  password: string,
  target: string | null = null,
  onProgress: (progress: BackupProgress) => void = () => undefined,
): Promise<RestoreSummary> {
  let root: string | null = null;
  if (target) {
    root = resolve(target);
    const existing = await lstat(root).catch(() => null);
    if (existing && (!existing.isDirectory() || (await readdir(root)).length > 0)) throw new BackupError("Restore into a new or empty folder.");
    await mkdir(root, { recursive: true });
  }
  let current: { handle: FileHandle | null; path: string; final: string; mtime: Date; size: number; written: number } | null = null;
  const result: RestoreSummary = { files: 0, bytes: 0, created: "", skippedInBackup: 0 };
  try {
    for await (const { type, body } of readRecords(file, password)) {
      if (type === 1) {
        if (current) throw new BackupError("The backup file is damaged.");
        const meta = JSON.parse(body.toString("utf8")) as { path: string; size: number; mtime: string };
        const parts = safeRelative(meta.path);
        if (!parts) throw new BackupError(`The backup contains an unsafe file name: ${String(meta.path).slice(0, 100)}`);
        onProgress({ files: result.files, bytes: result.bytes, current: meta.path });
        let handle: FileHandle | null = null;
        let final = "";
        let path = "";
        if (root) {
          final = join(root, ...parts);
          if (!final.startsWith(root + sep)) throw new BackupError("The backup contains an unsafe file name.");
          await mkdir(dirname(final), { recursive: true });
          path = `${final}.sentinel-part`;
          handle = await open(path, "wx", 0o600);
        }
        current = { handle, path, final, mtime: new Date(meta.mtime), size: meta.size, written: 0 };
      } else if (type === 2) {
        if (!current) throw new BackupError("The backup file is damaged.");
        if (current.handle) await current.handle.write(body);
        current.written += body.length;
      } else if (type === 3) {
        if (!current) throw new BackupError("The backup file is damaged.");
        if (current.handle) await current.handle.close();
        if (body.length) {
          result.skippedInBackup += 1;
          if (current.path) await rm(current.path, { force: true });
        } else {
          if (current.path) {
            await rename(current.path, current.final);
            if (!Number.isNaN(current.mtime.getTime())) await utimes(current.final, current.mtime, current.mtime).catch(() => undefined);
          }
          result.files += 1;
          result.bytes += current.written;
        }
        current = null;
      } else if (type === 9) {
        if (current) throw new BackupError("The backup file is damaged.");
        const end = JSON.parse(body.toString("utf8")) as { files: number; bytes: number; created: string };
        if (end.files !== result.files || end.bytes !== result.bytes) throw new BackupError("The backup file is damaged: the totals do not match.");
        result.created = end.created;
        return result;
      } else {
        throw new BackupError("The backup file is damaged.");
      }
    }
    throw new BackupError("The backup file is incomplete.");
  } catch (error) {
    if (current?.handle) await current.handle.close().catch(() => undefined);
    if (current?.path) await rm(current.path, { force: true });
    throw error;
  }
}

/** Keep the newest `keep` backups made by Qalaa in a folder; delete older ones. */
export async function pruneBackups(destinationDir: string, keep: number): Promise<string[]> {
  const names = (await readdir(destinationDir).catch(() => [] as string[])).filter((name) => /^Qalaa-backup-\d{8}-\d{6}\.sbk$/.test(name)).sort();
  const old = names.slice(0, Math.max(0, names.length - keep));
  for (const name of old) await rm(join(destinationDir, name), { force: true });
  return old;
}
