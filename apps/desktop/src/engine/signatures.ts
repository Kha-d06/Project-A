/**
 * Known-malware fingerprints (SHA-256), downloaded from the Qalaa server,
 * which collects them from MalwareBazaar and ThreatFox. Stored as a sorted
 * JSON list on disk and as a Set in memory. The list covers recently reported
 * samples, not every piece of malware ever seen.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, rename, writeFile } from "node:fs/promises";

export interface SignatureFile {
  version: string;
  updatedAt: string;
  sources: string[];
  sha256: string[];
}

const HEX64 = /^[a-f0-9]{64}$/;

export class SignatureStore {
  private hashes = new Set<string>();
  meta: Omit<SignatureFile, "sha256"> | null = null;

  constructor(private readonly file: string) {}

  get size(): number {
    return this.hashes.size;
  }

  has(sha256: string): boolean {
    return this.hashes.has(sha256.toLowerCase());
  }

  load(data: SignatureFile): void {
    this.hashes = new Set(data.sha256.filter((value) => HEX64.test(value)));
    this.meta = { version: data.version, updatedAt: data.updatedAt, sources: data.sources };
  }

  async open(): Promise<void> {
    try {
      this.load(JSON.parse(await readFile(this.file, "utf8")) as SignatureFile);
    } catch {
      this.hashes = new Set();
      this.meta = null;
    }
  }

  async save(data: SignatureFile): Promise<void> {
    this.load(data);
    const temporary = `${this.file}.tmp`;
    await writeFile(temporary, JSON.stringify({ ...data, sha256: [...this.hashes].sort() }));
    await rename(temporary, this.file);
  }
}

export function sha256OfBuffer(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

export function sha256OfFile(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolve(hash.digest("hex")));
  });
}
