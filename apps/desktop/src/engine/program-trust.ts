/**
 * Is a program where only the system or an administrator could have put it?
 * Used by credential guardrails so that a look-alike (a script named "ssh" in
 * a user folder) never borrows a trusted name.
 *
 * - Linux: the binary and every folder above it belong to root and aren't
 *   writable by the group or others. A process running as the person can't
 *   create or replace such a file.
 * - macOS: a system path protected by System Integrity Protection, or a valid
 *   Apple or Developer ID signature ("anchor apple generic").
 * - Windows: not checked yet (credential guardrails don't run there).
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { dirname } from "node:path";

export interface StatLike {
  uid: number;
  mode: number;
  isFile(): boolean;
}

const WRITABLE_BY_OTHERS = 0o022;

export async function linuxTrustedLocation(exe: string, statOf: (p: string) => Promise<StatLike> = stat, resolve: (p: string) => Promise<string> = realpath): Promise<boolean> {
  if (!exe.startsWith("/") || exe.endsWith(" (deleted)")) return false;
  try {
    const path = await resolve(exe);
    const file = await statOf(path);
    if (!file.isFile() || file.uid !== 0 || (file.mode & WRITABLE_BY_OTHERS) !== 0) return false;
    for (let dir = dirname(path); ; dir = dirname(dir)) {
      const info = await statOf(dir);
      if (info.uid !== 0 || (info.mode & WRITABLE_BY_OTHERS) !== 0) return false;
      if (dir === "/") return true;
    }
  } catch {
    return false;
  }
}

/** Paths sealed by System Integrity Protection. */
export const MAC_SYSTEM_PREFIXES = ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/System/"];

/** "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" → the .app bundle, which is what gets signed. */
export function macBundle(exe: string): string {
  const at = exe.indexOf(".app/Contents/");
  return at >= 0 ? exe.slice(0, at + 4) : exe;
}

export function codesignArgs(exe: string): string[] {
  // "=..." is requirement text: signed by Apple, or by a Developer ID Apple issued.
  return ["--verify", "--strict", "-R=anchor apple generic", macBundle(exe)];
}

export type Runner = (command: string, args: string[]) => Promise<boolean>;

const run: Runner = (command, args) => new Promise((resolve) => execFile(command, args, { timeout: 15_000 }, (error) => resolve(!error)));

export async function macTrustedLocation(exe: string, runner: Runner = run): Promise<boolean> {
  if (!exe.startsWith("/")) return false;
  if (MAC_SYSTEM_PREFIXES.some((p) => exe.startsWith(p))) return true;
  return runner("codesign", codesignArgs(exe));
}

export function trustedLocationFor(platform: NodeJS.Platform): (exe: string) => Promise<boolean> {
  if (platform === "linux") return (exe) => linuxTrustedLocation(exe);
  if (platform === "darwin") return (exe) => macTrustedLocation(exe);
  return async () => false;
}

/** SHA-256 of a program file, read as a stream; null when it can't be read. */
export function sha256File(path: string): Promise<string | null> {
  return new Promise((resolve) => {
    if (!path.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(path)) return resolve(null);
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => resolve(hash.digest("hex")))
      .on("error", () => resolve(null));
  });
}
