// Types for threat-prefix.js, so the desktop app (TypeScript) can import it.
export const LIST_REFRESH_MS: number;
export const LIST_STALE_MS: number;
export interface StoredThreatList {
  prefixes: string;
  fetchedAt: number;
  sources: string[];
}
export interface ThreatHashMatch {
  digest: string;
  kind: "url" | "host";
  source: string;
  source_name: string;
  threat: string | null;
}
export interface LinkCheck {
  findings: { severity: string; category: string; title: string; explanation: string; link: string }[];
  checked: boolean;
  limitations: string[];
}
export function normalizeUrl(raw: string): { normalized: string; bare: string; host: string } | null;
export function hostCandidates(host: string): string[];
export function sha256Hex(text: string): Promise<string>;
export function createLinkChecker(deps: {
  getList: () => Promise<StoredThreatList | null>;
  fetchHashes: (prefixes: string[]) => Promise<ThreatHashMatch[]>;
  now?: () => number;
}): (links: string[], lang?: "en" | "ar") => Promise<LinkCheck>;
