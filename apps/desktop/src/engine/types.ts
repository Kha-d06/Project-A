/** Shared shapes for the scanning engine. Wording follows SENTINEL: never "safe". */
export type Verdict = "malicious" | "suspicious" | "no_known_threat" | "not_scanned";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  /** Stable identifier, used for translation in the interface. */
  rule: string;
  title: string;
  detail: string;
  /** For findings inside an archive: the member's name. */
  member?: string;
}

export interface ScanResult {
  path: string;
  name: string;
  size: number;
  sha256: string | null;
  verdict: Verdict;
  findings: Finding[];
  /** Which engines ran: signatures, heuristics, clamav, cloud. */
  engines: string[];
  scannedAt: string;
  error?: string;
}

export function verdictFrom(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "critical")) return "malicious";
  if (findings.some((f) => f.severity === "high" || f.severity === "medium")) return "suspicious";
  return "no_known_threat";
}
