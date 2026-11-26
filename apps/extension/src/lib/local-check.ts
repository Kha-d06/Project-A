/**
 * Checking pages inside the browser, so the addresses people visit never leave it.
 *
 * - Address patterns (look-alike domains, Arabic look-alike letters, brand names
 *   in the wrong place, raw IP addresses...) run here, from the same rules file
 *   the server uses (url-rules.ts).
 * - Known threats: the extension downloads the first 4 bytes of the SHA-256 of
 *   every listed address and domain (about a megabyte, every 6 hours). A page's
 *   address and host are hashed here and compared with that list. Only when a
 *   prefix matches does the extension ask the server for the full hashes with
 *   that prefix, mixed with a few random prefixes from the list, and compare
 *   them itself. The server sees a handful of 4-byte prefixes that thousands of
 *   addresses share, never the address.
 *
 * A full server check (which sends the address) runs only when the person asks
 * for one, from the right-click menu.
 */
import { CheckUnavailable, fetchThreatHashes, fetchThreatPrefixes, fetchUrlRules, type ThreatHashMatch } from "./api";
import { BUNDLED_RULES, analyzeAddress, parseAddress, validRules, type Finding, type UrlRules } from "./url-rules";
import type { CheckResult, Reason, Verdict } from "./types";

const LIST_KEY = "threatPrefixes";
const RULES_KEY = "urlRules";
export const LIST_REFRESH_MINUTES = 6 * 60;
/** A list older than this no longer counts: a miss stops meaning "not listed". */
export const LIST_STALE_HOURS = 24;
const HASH_CACHE_MS = 30 * 60 * 1000;
const DECOYS = 3;

// How long a result may be reused, as on the server (bad news is kept longer).
const CACHE_SECONDS: Record<string, number> = {
  dangerous: 6 * 3600,
  suspicious: 3600,
  caution: 3600,
  no_known_threat: 1800,
  unavailable: 300,
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const RISKY = new Set(["exe", "scr", "msi", "bat", "cmd", "com", "vbs", "js", "jse", "wsf", "hta", "ps1", "jar", "apk", "lnk", "iso", "img", "dll"]);
const DOCUMENTS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp4", "mp3", "zip"]);

export interface StoredThreatList {
  version: string;
  prefixes: string;
  count: number;
  sources: string[];
  fetchedAt: string;
}

let decoded: { version: string; bytes: Uint8Array } | null = null;
const hashCache = new Map<string, { at: number; matches: ThreatHashMatch[] }>();

export function resetLocalCheck(): void {
  decoded = null;
  hashCache.clear();
}

// --- The prefix list ----------------------------------------------------------------

export async function storedThreatList(): Promise<StoredThreatList | null> {
  const stored = await chrome.storage.local.get(LIST_KEY);
  return (stored[LIST_KEY] as StoredThreatList | undefined) ?? null;
}

function listBytes(list: StoredThreatList): Uint8Array {
  if (decoded?.version !== list.version) {
    const binary = atob(list.prefixes);
    const bytes = new Uint8Array(binary.length - (binary.length % 4));
    for (let i = 0; i < bytes.length; i++) bytes[i] = binary.charCodeAt(i);
    decoded = { version: list.version, bytes };
  }
  return decoded.bytes;
}

function prefixAt(bytes: Uint8Array, index: number): number {
  const at = index * 4;
  return ((bytes[at]! << 24) | (bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!) >>> 0;
}

/** Binary search over the sorted 4-byte prefixes. */
export function listHasPrefix(bytes: Uint8Array, prefixHex: string): boolean {
  const target = parseInt(prefixHex, 16) >>> 0;
  let low = 0;
  let high = bytes.length / 4 - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const value = prefixAt(bytes, mid);
    if (value === target) return true;
    if (value < target) low = mid + 1;
    else high = mid - 1;
  }
  return false;
}

function isFresh(list: StoredThreatList | null, now = Date.now()): list is StoredThreatList {
  return !!list && list.sources.length > 0 && now - new Date(list.fetchedAt).getTime() < LIST_STALE_HOURS * 3600_000;
}

/** Downloads the prefix list and the address rules if missing or older than 6 hours. */
export async function refreshThreatList(serverUrl: string, force = false): Promise<StoredThreatList | null> {
  const current = await storedThreatList();
  const recent = current && Date.now() - new Date(current.fetchedAt).getTime() < LIST_REFRESH_MINUTES * 60_000;
  if (recent && !force) return current;
  try {
    const response = await fetchThreatPrefixes(serverUrl);
    const next: StoredThreatList = { version: response.version, prefixes: response.prefixes, count: response.count, sources: response.sources, fetchedAt: new Date().toISOString() };
    await chrome.storage.local.set({ [LIST_KEY]: next });
    hashCache.clear();
    await refreshRules(serverUrl);
    return next;
  } catch {
    return current; // keep using the previous list
  }
}

async function refreshRules(serverUrl: string): Promise<void> {
  try {
    const rules = await fetchUrlRules(serverUrl);
    // Only a complete file at least as new as the bundled one replaces it.
    if (validRules(rules) && rules.version >= BUNDLED_RULES.version) await chrome.storage.local.set({ [RULES_KEY]: rules });
  } catch {
    // the bundled rules stay in use
  }
}

export async function currentRules(): Promise<UrlRules> {
  const stored = (await chrome.storage.local.get(RULES_KEY))[RULES_KEY];
  return validRules(stored) && stored.version >= BUNDLED_RULES.version ? stored : BUNDLED_RULES;
}

// --- Hashing and lookups --------------------------------------------------------------

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The page's address, and its host and each parent domain down to the registrable one. */
export function hostCandidates(host: string, registrable: string): string[] {
  const out = [host];
  let rest = host;
  while (rest !== registrable && rest.includes(".")) {
    rest = rest.slice(rest.indexOf(".") + 1);
    if (rest.length < registrable.length) break;
    out.push(rest);
  }
  return out;
}

function randomDecoys(bytes: Uint8Array, exclude: Set<string>): string[] {
  const total = bytes.length / 4;
  const out = new Set<string>();
  for (let tries = 0; total > exclude.size && out.size < DECOYS && tries < 20; tries++) {
    const pick = crypto.getRandomValues(new Uint32Array(1))[0]! % total;
    const hex = prefixAt(bytes, pick).toString(16).padStart(8, "0");
    if (!exclude.has(hex)) out.add(hex);
  }
  return [...out];
}

async function lookup(serverUrl: string, prefixes: string[], bytes: Uint8Array): Promise<ThreatHashMatch[]> {
  const now = Date.now();
  const missing = prefixes.filter((p) => (hashCache.get(p)?.at ?? 0) + HASH_CACHE_MS <= now);
  if (missing.length) {
    const asked = new Set(missing);
    const query = [...missing, ...randomDecoys(bytes, asked)].sort();
    const matches = await fetchThreatHashes(serverUrl, query);
    for (const prefix of query) hashCache.set(prefix, { at: now, matches: matches.filter((m) => m.digest.startsWith(prefix)) });
  }
  return prefixes.flatMap((p) => hashCache.get(p)?.matches ?? []);
}

// --- Assessment -----------------------------------------------------------------------

const threatSuffix = (threat: string | null) => (threat ? ` (${threat.replaceAll("_", " ")})` : "");

function listFindings(urlMatches: ThreatHashMatch[], hostMatches: ThreatHashMatch[]): Finding[] {
  const findings: Finding[] = [];
  const community = (subject: string, source: string): Finding => ({
    severity: "high",
    category: "community_report",
    title: `${subject} was reported by Qalaa users as a scam`,
    explanation: "People reported it to Qalaa and a moderator reviewed and confirmed the reports. Treat it as a likely scam.",
    source,
  });
  for (const match of urlMatches) {
    if (match.source === "community") {
      findings.push(community("This link", match.source_name));
      continue;
    }
    findings.push({
      severity: "critical",
      category: "threat_intelligence",
      title: `This exact link is listed by ${match.source_name}`,
      explanation: `The address was reported and catalogued as distributing malware${threatSuffix(match.threat)}. Do not open it or run anything downloaded from it.`,
      source: match.source_name,
    });
  }
  for (const match of hostMatches) {
    if (match.source === "community") {
      if (!findings.some((f) => f.category === "community_report")) findings.push(community("This website", match.source_name));
    } else if (!urlMatches.length && !findings.some((f) => f.source === match.source_name)) {
      findings.push({
        severity: match.source === "threatfox" ? "critical" : "low",
        category: "threat_intelligence",
        title: match.source === "threatfox" ? `This website is listed by ${match.source_name}` : `Other links on this host are listed by ${match.source_name}`,
        explanation:
          match.source === "threatfox"
            ? `The domain is catalogued as malicious${threatSuffix(match.threat)}. Do not sign in, pay or download anything here.`
            : "A different address on the same host was reported for distributing malware. On shared hosting and file-sharing services this says little about this page, so treat it as context rather than proof.",
        source: match.source_name,
      });
    }
  }
  return findings;
}

function verdictFor(findings: Finding[], listAvailable: boolean): Verdict {
  if (findings.some((f) => f.severity === "critical")) return "dangerous";
  if (findings.some((f) => f.severity === "high")) return "suspicious";
  if (findings.some((f) => f.severity === "medium")) return "caution";
  return listAvailable ? "no_known_threat" : "unavailable";
}

function toResult(host: string, findings: Finding[], list: StoredThreatList | null, available: boolean, limitations: string[]): CheckResult {
  const verdict = verdictFor(findings, available);
  const reasons: Reason[] = findings
    .filter((f) => f.severity !== "info")
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .map(({ severity, title, explanation, source }) => ({ severity, title, explanation, source }));
  if (verdict === "unavailable" && !limitations.length) {
    limitations.push("The list of known threats hasn't been downloaded recently, so a clean result could not be confirmed. Only address patterns were checked.");
  }
  return {
    verdict,
    host,
    reasons,
    sources: ["Qalaa address patterns (checked in this browser)", ...(available && list ? list.sources : [])],
    limitations,
    checkedAt: new Date().toISOString(),
    cacheSeconds: CACHE_SECONDS[verdict] ?? 300,
  };
}

/** Findings from the address and the threat list; only prefixes ever leave the browser. */
async function localFindings(raw: string, serverUrl: string): Promise<{ host: string; findings: Finding[]; list: StoredThreatList | null; available: boolean; limitations: string[] } | null> {
  const address = parseAddress(raw);
  if (!address) return null;
  const findings = analyzeAddress(address, await currentRules());
  const list = await storedThreatList();
  const limitations: string[] = [];
  let available = isFresh(list);
  if (list && list.count > 0) {
    const bytes = listBytes(list);
    const urlDigest = await sha256Hex(address.normalized);
    const hostDigests = await Promise.all(hostCandidates(address.host, address.registrableDomain).map(sha256Hex));
    const hits = [urlDigest, ...hostDigests].filter((d) => listHasPrefix(bytes, d.slice(0, 8)));
    if (hits.length) {
      try {
        const matches = await lookup(serverUrl, [...new Set(hits.map((d) => d.slice(0, 8)))], bytes);
        findings.push(
          ...listFindings(
            matches.filter((m) => m.kind === "url" && m.digest === urlDigest),
            matches.filter((m) => m.kind === "host" && hostDigests.includes(m.digest)),
          ),
        );
      } catch (error) {
        available = false;
        limitations.push(
          `This address may be on the list of known threats, but it couldn't be confirmed: ${error instanceof CheckUnavailable ? error.reason : "the server could not be reached."}`,
        );
      }
    }
  }
  return { host: address.host, findings, list, available, limitations };
}

export async function localCheckUrl(raw: string, serverUrl: string): Promise<CheckResult | null> {
  const found = await localFindings(raw, serverUrl);
  return found && toResult(found.host, found.findings, found.list, found.available, found.limitations);
}

/** A download's address and file name (the browser doesn't let extensions read the file). */
export async function localCheckDownload(raw: string, filename: string, serverUrl: string): Promise<CheckResult | null> {
  const found = await localFindings(raw, serverUrl);
  if (!found) return null;
  const parts = filename.toLowerCase().split("/").pop()!.split(".");
  const extension = parts.length > 1 ? parts.at(-1)! : "";
  const disguised = parts.length > 2 && DOCUMENTS.has(parts.at(-2)!);
  if (disguised && RISKY.has(extension)) {
    found.findings.push({
      severity: "high",
      category: "disguised_file",
      title: "The file name disguises a program as a document",
      explanation: `“${filename}” ends in “.${parts.at(-2)}.${extension}”. It will run code when opened, even though it looks like a document.`,
      source: "Qalaa quick check",
    });
  } else if (RISKY.has(extension)) {
    found.findings.push({ severity: "low", category: "download", title: "This download is a program or script", explanation: "Only run it if you trust where it came from.", source: "Qalaa quick check" });
  }
  found.limitations.push("The browser does not let extensions read downloaded files, so only the download's address and name were checked. Scan the file itself for a full check.");
  return toResult(found.host, found.findings, found.list, found.available, found.limitations);
}
