/**
 * qalaa-scan: the native static scanner (apps/desktop-native/crates/qalaa-scan).
 *
 * Runs as a separate process for each file, so a parser bug triggered by a
 * hostile file can't take the daemon down. It caps its own memory and CPU
 * (on Linux and macOS) and this side kills it after a wall-clock timeout and
 * reads at most 1 MB of its output. Rules and the model come only from a
 * signed bundle it verifies itself.
 *
 * Its verdicts feed the normal findings: YARA rules named MAL_ are "known
 * malicious", other rules and the model are "suspicious" at most.
 */
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";

import type { Finding } from "./types";

export interface NativeSignature {
  rule: string;
  namespace: string;
  level: "malicious" | "suspicious" | "info";
  description?: string | null;
  reference?: string | null;
}

export interface NativeReport {
  version: number;
  size: number;
  sha256: string;
  format: string;
  bundle_version: string | null;
  signatures: NativeSignature[];
  model: { name: string; score: number; threshold: number; suspicious: boolean; fpr: number | null } | null;
  indicators: { id: string; detail: string }[];
  limitations: string[];
  verdict: "known_malicious" | "suspicious" | "no_findings";
  error?: string;
}

export interface NativeScanner {
  binary: string;
  /** The verified bundle folder, or null to run without rules or model. */
  bundleDir: string | null;
}

const EXE = process.platform === "win32" ? "qalaa-scan.exe" : "qalaa-scan";
const MAX_OUTPUT = 1024 * 1024;

export async function findNativeScanner(env: NodeJS.ProcessEnv = process.env, execPath = process.execPath, exists = (p: string) => access(p).then(() => true, () => false)): Promise<string | null> {
  const resources = (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  const candidates = [
    env.QALAA_SCAN_BINARY,
    join(dirname(execPath), EXE),
    resources ? join(resources, "bin", EXE) : undefined,
    ...(env.PATH ?? "").split(delimiter).filter(Boolean).map((d) => join(d, EXE)),
  ];
  for (const c of candidates) if (c && (await exists(c))) return c;
  return null;
}

export function scanArgs(scanner: NativeScanner, path: string): string[] {
  return ["scan", ...(scanner.bundleDir ? ["--bundle", scanner.bundleDir] : []), "--max-mb", "128", "--memory-mb", "1024", "--cpu-seconds", "30", "--", path];
}

export function parseReport(stdout: string): NativeReport {
  const line = stdout.split("\n").find((l) => l.trim().startsWith("{"));
  if (!line) throw new Error("qalaa-scan printed no report");
  const report = JSON.parse(line) as NativeReport;
  if (report.error) throw new Error(`qalaa-scan could not read the file: ${report.error}`);
  if (report.version !== 1 || !Array.isArray(report.signatures)) throw new Error("qalaa-scan's report has an unexpected shape");
  return report;
}

export function nativeScan(scanner: NativeScanner, path: string, timeoutMs = 45_000): Promise<NativeReport> {
  return new Promise((resolve, reject) => {
    execFile(scanner.binary, scanArgs(scanner, path), { timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: MAX_OUTPUT, windowsHide: true }, (error, stdout) => {
      if (error) {
        const e = error as NodeJS.ErrnoException & { killed?: boolean; signal?: string | null };
        if (e.killed || e.signal === "SIGKILL") return reject(new Error("qalaa-scan took too long on this file and was stopped"));
        if (e.signal === "SIGXCPU") return reject(new Error("qalaa-scan hit its CPU limit on this file"));
        return reject(new Error(`qalaa-scan stopped unexpectedly (${String(e.code ?? e.signal ?? e.message)})`));
      }
      try {
        resolve(parseReport(String(stdout)));
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  });
}

const clip = (s: string | null | undefined, n = 200) => (s ?? "").slice(0, n);

/** Findings for the normal scan result. Indicators are left out: the JS heuristics already report them. */
export function nativeFindings(report: NativeReport): Finding[] {
  const out: Finding[] = [];
  for (const s of report.signatures) {
    if (s.level === "info") continue;
    const malicious = s.level === "malicious";
    out.push({
      severity: malicious ? "critical" : "high",
      rule: malicious ? "yara_malicious" : "yara_suspicious",
      title: malicious ? `Matches the malware rule ${clip(s.rule, 80)}` : `Matches the warning rule ${clip(s.rule, 80)}`,
      detail: `${clip(s.description) || "A YARA rule in Qalaa's signed rule set matched this file."}${s.reference ? ` Reference: ${clip(s.reference)}` : ""} (rule set ${report.bundle_version ?? "unknown"})`,
    });
  }
  if (report.model?.suspicious) {
    const fpr = report.model.fpr ? ` About ${(report.model.fpr * 100).toFixed(1)}% of ordinary programs also score this high.` : "";
    out.push({
      severity: "medium",
      rule: "ml_suspicious",
      title: "Qalaa's local model rates this program as suspicious",
      detail: `Its structure resembles malware the model was trained on (score ${report.model.score.toFixed(2)}). A model can be wrong: this is a reason to check the source, not proof.${fpr}`,
    });
  }
  return out;
}
