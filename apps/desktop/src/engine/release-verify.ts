/**
 * A second, independent check on desktop app updates.
 *
 * electron-updater compares the download with a SHA-512 from latest.yml, but
 * latest.yml comes from the same server as the installer: whoever controls the
 * server controls both. So before an update may install, the app also requires:
 *
 *  1. release-manifest.json and release-manifest.json.sig from the same feed;
 *  2. an ed25519 signature over the manifest's exact bytes by one of the keys
 *     pinned in this build (RELEASE_KEYS). The private key is kept offline by
 *     the release manager (tools/release-signing), never on the server or in CI;
 *  3. the manifest's version equal to the downloaded update's, and newer than
 *     the running app (no downgrades to an older, vulnerable release);
 *  4. the downloaded file's SHA-512 equal to the manifest's entry for it;
 *  5. the manifest not expired, so an old signed manifest can't be replayed
 *     forever to hold a computer back.
 *
 * A build with no pinned key doesn't install updates by itself: it reports that
 * one exists and points to the download page.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";

import { signatureValid } from "./scan-bundle";
import { isNewer } from "./updates";

/**
 * Hex ed25519 public keys allowed to sign desktop releases. Filled in by the
 * release manager (see docs/update-signing.md); more than one allows rotation.
 */
export const RELEASE_KEYS: string[] = [];

export interface ReleaseManifest {
  format: 1;
  product: "qalaa-desktop";
  version: string;
  /** ISO time after which this manifest is no longer accepted. */
  expires: string;
  files: { name: string; sha512: string; size: number }[];
}

export type ReleaseCheck = { ok: true } | { ok: false; reason: "no_keys" | "unsigned" | "malformed" | "version" | "expired" | "file" };

export function parseReleaseManifest(bytes: Buffer): ReleaseManifest | null {
  try {
    const m = JSON.parse(bytes.toString("utf8")) as Partial<ReleaseManifest>;
    if (m.format !== 1 || m.product !== "qalaa-desktop" || typeof m.version !== "string" || typeof m.expires !== "string" || !Array.isArray(m.files)) return null;
    if (Number.isNaN(Date.parse(m.expires))) return null;
    for (const f of m.files) {
      if (!f || typeof f.name !== "string" || typeof f.sha512 !== "string" || !Number.isInteger(f.size)) return null;
    }
    return m as ReleaseManifest;
  } catch {
    return null;
  }
}

export const sha512Base64 = (bytes: Buffer) => createHash("sha512").update(bytes).digest("base64");

/** The decision, from bytes already in hand (pure; tested). */
export function checkRelease(input: {
  manifest: Buffer;
  signature: string;
  keys: string[];
  updateVersion: string;
  currentVersion: string;
  file: { name: string; sha512: string; size: number };
  now?: number;
}): ReleaseCheck {
  if (!input.keys.length) return { ok: false, reason: "no_keys" };
  if (!signatureValid(input.manifest, input.signature, input.keys)) return { ok: false, reason: "unsigned" };
  const manifest = parseReleaseManifest(input.manifest);
  if (!manifest) return { ok: false, reason: "malformed" };
  if (manifest.version !== input.updateVersion || !isNewer(manifest.version, input.currentVersion)) return { ok: false, reason: "version" };
  if (Date.parse(manifest.expires) < (input.now ?? Date.now())) return { ok: false, reason: "expired" };
  const entry = manifest.files.find((f) => f.name === input.file.name);
  if (!entry || entry.size !== input.file.size || entry.sha512 !== input.file.sha512) return { ok: false, reason: "file" };
  return { ok: true };
}

/** Fetches the signed manifest and checks a downloaded update against it. */
export async function verifyDownloadedUpdate(opts: {
  feed: string;
  downloadedFile: string;
  updateVersion: string;
  currentVersion: string;
  keys?: string[];
  fetcher?: typeof fetch;
}): Promise<ReleaseCheck> {
  const keys = opts.keys ?? RELEASE_KEYS;
  if (!keys.length) return { ok: false, reason: "no_keys" };
  const fetcher = opts.fetcher ?? fetch;
  const base = opts.feed.replace(/\/$/, "");
  try {
    const [manifest, signature] = await Promise.all(
      ["release-manifest.json", "release-manifest.json.sig"].map(async (name) => {
        const response = await fetcher(`${base}/${name}`, { signal: AbortSignal.timeout(20_000) });
        if (!response.ok) throw new Error(String(response.status));
        return Buffer.from(await response.arrayBuffer());
      }),
    );
    const bytes = await readFile(opts.downloadedFile);
    return checkRelease({
      manifest: manifest!,
      signature: signature!.toString("utf8"),
      keys,
      updateVersion: opts.updateVersion,
      currentVersion: opts.currentVersion,
      file: { name: basename(opts.downloadedFile), sha512: sha512Base64(bytes), size: bytes.length },
    });
  } catch {
    return { ok: false, reason: "unsigned" };
  }
}
