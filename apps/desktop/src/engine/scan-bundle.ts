/**
 * Differential updates for qalaa-scan's signed rule and model bundle.
 *
 * Layout under the data folder:
 *   scan-bundle/current/    the verified bundle qalaa-scan uses
 *   scan-bundle/previous/   the one before, kept for a manual roll back
 *   scan-bundle/staging-*   a new one being assembled (removed on failure)
 *
 * 1. Fetch manifest.json and manifest.sig. The signature must be from a key
 *    pinned in qalaa-scan (`qalaa-scan keys`), and the version newer than the
 *    current one: no downgrades.
 * 2. Files whose SHA-256 is unchanged are copied from the current bundle;
 *    only changed ones are downloaded, each checked against its size and hash.
 * 3. qalaa-scan verifies the assembled folder itself; only then is it swapped
 *    in. Any failure leaves the current bundle in place.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { execFile } from "node:child_process";
import { copyFile, mkdir, readFile, rename, rm, writeFile, mkdtemp } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface ManifestFile {
  sha256: string;
  size: number;
}

export interface Manifest {
  format: number;
  version: string;
  created?: string;
  files: Record<string, ManifestFile>;
}

export interface UpdateResult {
  updated: boolean;
  version: string | null;
  downloaded: string[];
  reused: string[];
  reason?: string;
}

export interface UpdaterDeps {
  /** Folder holding current/ and previous/. */
  root: string;
  /** Base URL the bundle files are served from (ends with "/"). */
  baseUrl: string;
  /** Hex ed25519 public keys (from `qalaa-scan keys`). */
  keys: string[];
  fetchBytes?: (url: string) => Promise<Buffer>;
  /** Runs `qalaa-scan verify DIR`; resolves true when it accepts the folder. */
  verifyDir: (dir: string) => Promise<boolean>;
}

const MAX_MANIFEST = 1 << 20;
const MAX_FILE = 256 << 20;

export function safeName(name: string): boolean {
  return name.length > 0 && name.length <= 200 && !name.includes("\\") && !name.includes("\0") && name.split("/").every((p) => p !== "" && p !== "." && p !== "..") && !name.startsWith("/");
}

export function versionNewer(next: string, current: string | null): boolean {
  if (!/^\d+(\.\d+)*$/.test(next)) return false;
  if (!current) return true;
  const a = next.split(".").map(Number);
  const b = current.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return false;
}

/** ed25519 over the manifest's exact bytes, with any of the pinned keys. */
export function signatureValid(manifest: Buffer, sigBase64: string, keys: string[]): boolean {
  const sig = Buffer.from(sigBase64.trim(), "base64");
  if (sig.length !== 64) return false;
  return keys.some((hex) => {
    if (!/^[0-9a-f]{64}$/i.test(hex)) return false;
    // SPKI wrapper for a raw ed25519 public key.
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]);
    try {
      return verify(null, manifest, createPublicKey({ key: der, format: "der", type: "spki" }), sig);
    } catch {
      return false;
    }
  });
}

export function parseManifest(bytes: Buffer): Manifest {
  const m = JSON.parse(bytes.toString("utf8")) as Manifest;
  if (m.format !== 1 || typeof m.version !== "string" || !m.files || typeof m.files !== "object") throw new Error("not a bundle manifest");
  for (const [name, f] of Object.entries(m.files)) {
    if (!safeName(name)) throw new Error(`unsafe file name in the manifest: ${JSON.stringify(name)}`);
    if (!/^[0-9a-f]{64}$/i.test(f.sha256) || !Number.isInteger(f.size) || f.size < 0 || f.size > MAX_FILE) throw new Error(`bad entry for ${name}`);
  }
  return m;
}

async function defaultFetch(url: string): Promise<Buffer> {
  const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

export async function currentManifest(root: string): Promise<Manifest | null> {
  try {
    return parseManifest(await readFile(join(root, "current", "manifest.json")));
  } catch {
    return null;
  }
}

export async function updateBundle(deps: UpdaterDeps): Promise<UpdateResult> {
  const fetchBytes = deps.fetchBytes ?? defaultFetch;
  const none = (reason: string, version: string | null = null): UpdateResult => ({ updated: false, version, downloaded: [], reused: [], reason });
  if (!deps.keys.length) return none("This build has no bundle signing key, so it can't accept rule updates.");
  const current = await currentManifest(deps.root);
  const manifestBytes = await fetchBytes(`${deps.baseUrl}manifest.json`);
  if (manifestBytes.length > MAX_MANIFEST) return none("The update's manifest is too large.", current?.version ?? null);
  const sig = (await fetchBytes(`${deps.baseUrl}manifest.sig`)).toString("utf8");
  if (!signatureValid(manifestBytes, sig, deps.keys)) return none("The update isn't signed by a trusted key, so it was ignored.", current?.version ?? null);
  const next = parseManifest(manifestBytes);
  if (!versionNewer(next.version, current?.version ?? null)) return none(current?.version === next.version ? "Already up to date." : "The offered rules are older than the installed ones, so they were ignored.", current?.version ?? null);

  await mkdir(deps.root, { recursive: true });
  const staging = await mkdtemp(join(deps.root, "staging-"));
  const downloaded: string[] = [];
  const reused: string[] = [];
  try {
    for (const [name, entry] of Object.entries(next.files)) {
      const target = join(staging, ...name.split("/"));
      await mkdir(dirname(target), { recursive: true });
      const old = current?.files[name];
      if (old && old.sha256.toLowerCase() === entry.sha256.toLowerCase()) {
        const src = join(deps.root, "current", ...name.split("/"));
        const bytes = await readFile(src).catch(() => null);
        if (bytes && bytes.length === entry.size && sha256(bytes) === entry.sha256.toLowerCase()) {
          await copyFile(src, target);
          reused.push(name);
          continue;
        }
      }
      const bytes = await fetchBytes(`${deps.baseUrl}${name.split("/").map(encodeURIComponent).join("/")}`);
      if (bytes.length !== entry.size || sha256(bytes) !== entry.sha256.toLowerCase()) throw new Error(`${name} doesn't match the signed manifest`);
      await writeFile(target, bytes);
      downloaded.push(name);
    }
    await writeFile(join(staging, "manifest.json"), manifestBytes);
    await writeFile(join(staging, "manifest.sig"), sig);
    if (!(await deps.verifyDir(staging))) throw new Error("qalaa-scan refused the assembled bundle");
    await rm(join(deps.root, "previous"), { recursive: true, force: true });
    await rename(join(deps.root, "current"), join(deps.root, "previous")).catch(() => undefined);
    await rename(staging, join(deps.root, "current"));
    return { updated: true, version: next.version, downloaded, reused };
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    return none(`The update was not installed: ${error instanceof Error ? error.message : String(error)}. The current rules stay in use.`, current?.version ?? null);
  }
}

function run(binary: string, args: string[]): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve) => {
    execFile(binary, args, { timeout: 60_000, maxBuffer: 1 << 20, windowsHide: true }, (error, stdout) =>
      resolve({ code: error ? Number((error as NodeJS.ErrnoException).code ?? 1) || 1 : 0, stdout: String(stdout) }),
    );
  });
}

export async function pinnedKeys(binary: string): Promise<string[]> {
  const { stdout } = await run(binary, ["keys"]);
  try {
    const keys = (JSON.parse(stdout) as { keys?: unknown }).keys;
    return Array.isArray(keys) ? keys.filter((k): k is string => typeof k === "string") : [];
  } catch {
    return [];
  }
}

export async function verifyWith(binary: string, dir: string): Promise<boolean> {
  const { code, stdout } = await run(binary, ["verify", dir]);
  return code === 0 && stdout.includes('"ok":true');
}
