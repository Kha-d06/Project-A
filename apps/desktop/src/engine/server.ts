/**
 * The Qalaa server, used for three optional things:
 *  - downloading the known-malware fingerprint list (public, nothing sent);
 *  - fingerprint lookups for individual files (opt-in: sends the SHA-256 only);
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

export async function lookupHash(server: string, sha256: string, fetcher: typeof fetch = fetch): Promise<string | null> {
  const response = await fetcher(endpoint(server, `/intelligence/hash/${sha256}`), { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`The server answered ${response.status}`);
  const body = (await response.json()) as { verdict: string; indicators: { source: string }[] };
  return body.verdict === "listed" ? (body.indicators[0]?.source ?? "Qalaa threat feeds") : null;
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
