import type { CheckResult } from "./types";

/**
 * Verdict cache in chrome.storage.session: survives service-worker restarts, is
 * cleared when the browser closes, and is never written to disk by design.
 * Concurrent lookups for the same key share one request.
 */
const PREFIX = "verdict:";
const MAX_ENTRIES = 500;

interface Entry {
  result: CheckResult;
  expiresAt: number;
}

const inflight = new Map<string, Promise<CheckResult>>();

export async function getCached(key: string, now = Date.now()): Promise<CheckResult | null> {
  const stored = await chrome.storage.session.get(PREFIX + key);
  const entry = stored[PREFIX + key] as Entry | undefined;
  if (!entry) return null;
  if (entry.expiresAt <= now) {
    await chrome.storage.session.remove(PREFIX + key);
    return null;
  }
  return entry.result;
}

export async function putCached(key: string, result: CheckResult, now = Date.now()): Promise<void> {
  const all = await chrome.storage.session.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith(PREFIX));
  if (keys.length >= MAX_ENTRIES) {
    const oldest = keys
      .map((k) => [k, (all[k] as Entry).expiresAt] as const)
      .sort((a, b) => a[1] - b[1])
      .slice(0, keys.length - MAX_ENTRIES + 1)
      .map(([k]) => k);
    await chrome.storage.session.remove(oldest);
  }
  const entry: Entry = { result, expiresAt: now + result.cacheSeconds * 1000 };
  await chrome.storage.session.set({ [PREFIX + key]: entry });
}

export function dedupe(key: string, work: () => Promise<CheckResult>): Promise<CheckResult> {
  const existing = inflight.get(key);
  if (existing) return existing;
  const promise = work().finally(() => inflight.delete(key));
  inflight.set(key, promise);
  return promise;
}

export async function clearCache(): Promise<void> {
  const all = await chrome.storage.session.get(null);
  await chrome.storage.session.remove(Object.keys(all).filter((k) => k.startsWith(PREFIX)));
}
