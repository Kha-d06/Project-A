/** Mirrors the API's QuickVerdict (services/api/app/schemas/extension.py). */
export type ServerVerdict =
  | "dangerous"
  | "suspicious"
  | "caution"
  | "no_known_threat"
  | "unavailable"
  | "skipped";

/** Local outcomes the server never returns. */
export type Verdict = ServerVerdict | "blocked_by_you" | "blocked_by_family" | "allowed_by_you";

export interface Reason {
  severity: string;
  title: string;
  explanation: string;
  source: string;
}

export interface CheckResult {
  verdict: Verdict;
  host: string;
  reasons: Reason[];
  sources: string[];
  limitations: string[];
  checkedAt: string;
  cacheSeconds: number;
}

export interface Alert {
  host: string;
  verdict: Verdict;
  kind: "page" | "download" | "link";
  at: string;
}

export type ProtectionState = "active" | "paused" | "not_enrolled";
