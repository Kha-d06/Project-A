/**
 * Optional ClamAV: used when `clamdscan` or `clamscan` is installed. Run with
 * execFile (no shell), one file at a time, with a timeout.
 */
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { delimiter, join } from "node:path";

export interface ClamResult {
  infected: boolean;
  signature: string | null;
}

const CANDIDATES = process.platform === "win32" ? ["clamdscan.exe", "clamscan.exe"] : ["clamdscan", "clamscan"];
const EXTRA_DIRS = process.platform === "win32" ? ["C:\\Program Files\\ClamAV"] : ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"];

export async function findClam(): Promise<string | null> {
  const dirs = [...(process.env.PATH ?? "").split(delimiter), ...EXTRA_DIRS].filter(Boolean);
  for (const name of CANDIDATES) {
    for (const dir of dirs) {
      const candidate = join(dir, name);
      try {
        await access(candidate);
        return candidate;
      } catch {
        // keep looking
      }
    }
  }
  return null;
}

/** Parses "path: Eicar-Signature FOUND". Exit code 1 means a detection. */
export function parseClamOutput(stdout: string): ClamResult {
  const match = /:\s(.+)\sFOUND\s*$/m.exec(stdout);
  return match ? { infected: true, signature: match[1] ?? null } : { infected: false, signature: null };
}

export function clamScan(binary: string, path: string, timeoutMs = 120_000): Promise<ClamResult> {
  return new Promise((resolve, reject) => {
    execFile(binary, ["--no-summary", path], { timeout: timeoutMs, windowsHide: true }, (error, stdout) => {
      const code = (error as (Error & { code?: number }) | null)?.code;
      if (!error || code === 1) resolve(parseClamOutput(String(stdout)));
      else reject(new Error(`ClamAV could not scan the file (${String(code ?? error.message)})`));
    });
  });
}
