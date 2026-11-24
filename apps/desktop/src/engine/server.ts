/**
 * The Qalaa server, used for three optional things:
 *  - downloading the known-malware fingerprint list (public, nothing sent);
 *  - fingerprint lookups for individual files (opt-in: sends only the first six
 *    characters of the SHA-256, and the match is made on this computer);
 *  - uploading one file for a full server-side scan, only when the user asks.
 */
import { readFile } from "node:fs/promises";
import { basename } from "node:path";

import type { SignatureFile } from "./signatures";

const TIMEOUT_MS = 20_000;

function endpoint(server: string, path: string): string {
  return `${server.replace(/\/$/, "")}/api/v1${path}`;
}

export async function fetchSignatures(server: string, fetcher: typeof fetch = fetch): Promise<SignatureFile> {
  const response = await fetcher(endpoint(server, "/intelligence/hash-list"), { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`The server answered ${response.status}`);
  const body = (await response.json()) as { version: string; sources: string[]; sha256: string[]; generated_at: string };
  return { version: body.version, sources: body.sources, sha256: body.sha256, updatedAt: body.generated_at };
}

/** Characters of the SHA-256 sent to the server. Six hex characters match about
 * 1 in 16.7 million possible hashes, so the server cannot tell which file this is. */
export const HASH_PREFIX_LENGTH = 6;

/**
 * k-anonymous reputation lookup: only the first characters of the fingerprint
 * leave this computer. The server answers with every listed hash that starts
 * with them, and the full comparison happens here.
 */
export async function lookupHash(server: string, sha256: string, fetcher: typeof fetch = fetch): Promise<string | null> {
  const full = sha256.toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(full)) throw new Error("Not a SHA-256 fingerprint");
  const prefix = full.slice(0, HASH_PREFIX_LENGTH);
  const response = await fetcher(endpoint(server, `/intelligence/hash-prefix/${prefix}`), { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`The server answered ${response.status}`);
  const body = (await response.json()) as { candidates: { sha256: string; source: string }[] };
  return body.candidates.find((candidate) => candidate.sha256.toLowerCase() === full)?.source ?? null;
}

export async function uploadForFullScan(server: string, path: string, fetcher: typeof fetch = fetch): Promise<string> {
  const form = new FormData();
  form.append("file", new Blob([await readFile(path)]), basename(path));
  const response = await fetcher(endpoint(server, "/scans/file"), { method: "POST", body: form, signal: AbortSignal.timeout(120_000) });
  if (response.status === 413) throw new Error("The file is larger than the server accepts (25 MB).");
  if (!response.ok) throw new Error(`The server answered ${response.status}`);
  const body = (await response.json()) as { id: string };
  return `${server.replace(/\/$/, "")}/scans/${body.id}`;
}
