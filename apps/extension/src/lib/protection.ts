import { CheckUnavailable, checkUrl } from "./api";
import { dedupe, getCached, putCached } from "./cache";
import { localCheckDownload, localCheckUrl } from "./local-check";
import type { Settings } from "./settings";
import type { CheckResult, Verdict } from "./types";
import { checkableUrl, matchesHostList } from "./urls";

/** Upper bound on checks; beyond it, results are reported as unavailable. */
export const MAX_CHECKS_PER_MINUTE = 120;
const UNAVAILABLE_RETRY_SECONDS = 60;

let windowStart = 0;
let checksInWindow = 0;

export function resetThrottle() {
  windowStart = 0;
  checksInWindow = 0;
}

function takeThrottleSlot(now = Date.now()): boolean {
  if (now - windowStart >= 60_000) {
    windowStart = now;
    checksInWindow = 0;
  }
  checksInWindow += 1;
  return checksInWindow <= MAX_CHECKS_PER_MINUTE;
}

export function localResult(verdict: Verdict, host: string, limitation?: string): CheckResult {
  return {
    verdict,
    host,
    reasons: [],
    sources: [],
    limitations: limitation ? [limitation] : [],
    checkedAt: new Date().toISOString(),
    cacheSeconds: verdict === "unavailable" ? UNAVAILABLE_RETRY_SECONDS : 0,
  };
}

async function cachedCheck(key: string, host: string, run: () => Promise<CheckResult | null>): Promise<CheckResult> {
  const cached = await getCached(key);
  if (cached) return cached;
  return dedupe(key, async () => {
    if (!takeThrottleSlot()) {
      return localResult("unavailable", host, "Too many pages were opened at once; this one was not checked.");
    }
    try {
      const result = await run();
      if (!result) return localResult("skipped", host);
      await putCached(key, result);
      return result;
    } catch (error) {
      const reason = error instanceof CheckUnavailable ? error.reason : "The check failed unexpectedly.";
      return localResult("unavailable", host, reason);
    }
  });
}

/** The user's own lists and the family list, which need no check at all. */
function listResult(url: URL, settings: Settings): CheckResult | null {
  if (matchesHostList(url.hostname, settings.blocklist)) return localResult("blocked_by_you", url.hostname);
  if (matchesHostList(url.hostname, settings.familyBlocklist)) {
    return { ...localResult("blocked_by_family", url.hostname), sources: settings.familyGroups };
  }
  if (matchesHostList(url.hostname, settings.allowlist)) return localResult("allowed_by_you", url.hostname);
  return null;
}

/**
 * Verdict for a page or link, or null when nothing should be shown at all
 * (protection paused, or not a web address). Checked inside the browser: the
 * address isn't sent anywhere (see local-check.ts).
 */
export async function assessUrl(raw: string, settings: Settings): Promise<CheckResult | null> {
  if (settings.paused) return null;
  const url = checkableUrl(raw);
  if (!url) return null;
  const listed = listResult(url, settings);
  if (listed) return listed;
  // The raw address keeps any "user@" part, which the checks look for.
  return cachedCheck(`local:${url}`, url.hostname, () => localCheckUrl(raw.split("#")[0]!, settings.serverUrl));
}

/**
 * A full check on the Qalaa server, which sends the address. Only when the person
 * asks for it (the right-click menu), never for pages as they're opened.
 */
export async function assessUrlOnServer(raw: string, settings: Settings): Promise<CheckResult | null> {
  const url = checkableUrl(raw);
  if (!url) return null;
  const listed = listResult(url, settings);
  if (listed) return listed;
  return cachedCheck(`server:${url}`, url.hostname, () => checkUrl(settings.serverUrl, url.toString(), "full"));
}

export async function assessDownload(raw: string, filename: string, settings: Settings): Promise<CheckResult | null> {
  if (settings.paused || !settings.downloadChecks) return null;
  const url = checkableUrl(raw);
  if (!url) return null;
  if (matchesHostList(url.hostname, settings.allowlist)) return null;
  if (matchesHostList(url.hostname, settings.blocklist)) return localResult("blocked_by_you", url.hostname);
  return cachedCheck(`download:${url}:${filename}`, url.hostname, () => localCheckDownload(url.toString(), filename, settings.serverUrl));
}

// --- "Proceed anyway" allowances: per host, for this browser session only. ---

const ALLOWANCE_PREFIX = "proceed:";
const ALLOWANCE_MS = 60 * 60 * 1000;

export async function allowForSession(host: string): Promise<void> {
  await chrome.storage.session.set({ [ALLOWANCE_PREFIX + host]: Date.now() + ALLOWANCE_MS });
}

export async function isAllowedForSession(host: string): Promise<boolean> {
  const stored = await chrome.storage.session.get(ALLOWANCE_PREFIX + host);
  const until = stored[ALLOWANCE_PREFIX + host] as number | undefined;
  return typeof until === "number" && until > Date.now();
}
