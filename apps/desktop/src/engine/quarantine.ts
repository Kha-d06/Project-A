/**
 * Quarantine: the file is encrypted (AES-256-GCM, a random key per item) into
 * the app's private folder and the original is deleted, so it can no longer be
 * opened or run by accident. Restore decrypts it back to where it was; if a
 * file now exists there, the restored copy gets a new name instead.
 */
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";

import type { Verdict } from "./types";

export interface QuarantineItem {
  id: string;
  originalPath: string;
  name: string;
  size: number;
  sha256: string | null;
  verdict: Verdict;
  reason: string;
  quarantinedAt: string;
}

interface StoredItem extends QuarantineItem {
  key: string;
  iv: string;
  tag: string;
}

export const MAX_QUARANTINE_BYTES = 512 * 1024 * 1024;

export class Quarantine {
  constructor(private readonly folder: string) {}

  private get index(): string {
    return join(this.folder, "index.json");
  }

  private async readIndex(): Promise<StoredItem[]> {
    try {
      return JSON.parse(await readFile(this.index, "utf8")) as StoredItem[];
    } catch {
      return [];
    }
  }

  private async writeIndex(items: StoredItem[]): Promise<void> {
    await mkdir(this.folder, { recursive: true, mode: 0o700 });
    const temporary = `${this.index}.tmp`;
    await writeFile(temporary, JSON.stringify(items, null, 2), { mode: 0o600 });
    await rename(temporary, this.index);
  }

  async list(): Promise<QuarantineItem[]> {
    return (await this.readIndex()).map(({ key: _key, iv: _iv, tag: _tag, ...item }) => item);
  }

  async add(path: string, details: { sha256: string | null; verdict: Verdict; reason: string }): Promise<QuarantineItem> {
    const info = await stat(path);
    if (info.size > MAX_QUARANTINE_BYTES) throw new Error("The file is too large to quarantine; delete it instead.");
    await mkdir(this.folder, { recursive: true, mode: 0o700 });
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(await readFile(path)), cipher.final()]);
    const id = randomUUID();
    await writeFile(join(this.folder, `${id}.bin`), encrypted, { mode: 0o600 });
    await unlink(path);
    const item: StoredItem = {
      id,
      originalPath: path,
      name: basename(path),
      size: info.size,
      sha256: details.sha256,
      verdict: details.verdict,
      reason: details.reason,
      quarantinedAt: new Date().toISOString(),
      key: key.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
    await this.writeIndex([...(await this.readIndex()), item]);
    const { key: _k, iv: _i, tag: _t, ...visible } = item;
    return visible;
  }

  private async freePath(path: string): Promise<string> {
    const exists = async (candidate: string) => stat(candidate).then(() => true, () => false);
    if (!(await exists(path))) return path;
    const extension = extname(path);
    const stem = basename(path, extension);
    for (let n = 1; n < 1000; n += 1) {
      const candidate = join(dirname(path), `${stem} (restored ${n})${extension}`);
      if (!(await exists(candidate))) return candidate;
    }
    throw new Error("Could not find a free name to restore the file.");
  }

  async restore(id: string): Promise<string> {
    const items = await this.readIndex();
    const item = items.find((candidate) => candidate.id === id);
    if (!item) throw new Error("That item is no longer in quarantine.");
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(item.key, "base64"), Buffer.from(item.iv, "base64"));
    decipher.setAuthTag(Buffer.from(item.tag, "base64"));
    const plain = Buffer.concat([decipher.update(await readFile(join(this.folder, `${id}.bin`))), decipher.final()]);
    await mkdir(dirname(item.originalPath), { recursive: true });
    const target = await this.freePath(item.originalPath);
    // "wx": create only. If something appeared at that name after freePath looked
    // (a link planted to redirect the write), the restore fails instead of
    // writing through it or overwriting another file.
    await writeFile(target, plain, { flag: "wx" });
    await rm(join(this.folder, `${id}.bin`), { force: true });
    await this.writeIndex(items.filter((candidate) => candidate.id !== id));
    return target;
  }

  async remove(id: string): Promise<void> {
    const items = await this.readIndex();
    await rm(join(this.folder, `${id}.bin`), { force: true });
    await this.writeIndex(items.filter((candidate) => candidate.id !== id));
  }
}
