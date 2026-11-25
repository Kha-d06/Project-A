/**
 * Which programs started since the last look, with their parents: the input
 * for the behaviour rules.
 *
 * - Linux: /proc (the person's own and other users' command lines, which
 *   Linux shows to everyone; executable paths only for the person's own).
 *   The netlink process connector would see every start, but needs root; it
 *   comes with the root helper.
 * - macOS: `ps`, as the user-space fallback while Apple's Endpoint Security
 *   entitlement is pending.
 * - Windows: nothing yet (ETW needs the admin service).
 *
 * Polling sees a program only if it is still running at the next look, so
 * commands that finish within a second or two can be missed. The service
 * reports that next to the feature.
 */
import { execFile } from "node:child_process";
import { readFile, readdir, readlink } from "node:fs/promises";

import type { ProcessEvent } from "./behaviour-rules";

export interface ProcessRow {
  pid: number;
  ppid: number;
  image: string;
  commandLine: string;
  /** Identifies this run of the pid (start time on Linux, command on macOS). */
  start: string;
}

export type FeedSource = "proc_connector" | "proc_poll" | "ps_poll" | "unavailable";

export interface FeedCapability {
  source: FeedSource;
  intervalMs: number;
  /** Whether every start is seen, however short-lived. */
  seesShortLived: boolean;
  note: string;
}

export function capabilityFor(platform: NodeJS.Platform, connector = false): FeedCapability {
  if (platform === "linux" && connector) return { source: "proc_connector", intervalMs: 0, seesShortLived: true, note: "Every program start is reported by the kernel's process connector (root helper running)." };
  if (platform === "linux") return { source: "proc_poll", intervalMs: 1_000, seesShortLived: false, note: "Running programs are checked every second, so commands that finish faster can be missed. Every start will be seen once the root helper's process connector is installed." };
  if (platform === "darwin") return { source: "ps_poll", intervalMs: 2_000, seesShortLived: false, note: "Running programs are checked every 2 seconds, so commands that finish faster can be missed. Seeing every start needs Apple's Endpoint Security, which Qalaa has applied for." };
  return { source: "unavailable", intervalMs: 0, seesShortLived: false, note: "Behaviour rules aren't available on Windows yet: they need the Qalaa admin service (ETW)." };
}

/** /proc/<pid>/stat: the ppid is field 4 and the start time field 22, after the parenthesised name. */
export function parseStat(stat: string): { ppid: number; start: string } | null {
  const close = stat.lastIndexOf(")");
  if (close < 0) return null;
  const fields = stat.slice(close + 2).split(" ");
  const ppid = Number(fields[1]);
  const start = fields[19];
  return Number.isInteger(ppid) && start ? { ppid, start } : null;
}

export async function procRows(proc = "/proc"): Promise<ProcessRow[]> {
  const pids = (await readdir(proc).catch(() => [] as string[])).filter((d) => /^\d+$/.test(d));
  const rows = await Promise.all(
    pids.map(async (pid): Promise<ProcessRow | null> => {
      const stat = parseStat(await readFile(`${proc}/${pid}/stat`, "utf8").catch(() => ""));
      if (!stat) return null;
      const argv = (await readFile(`${proc}/${pid}/cmdline`, "utf8").catch(() => "")).split("\0").filter(Boolean);
      if (!argv.length) return null; // kernel threads
      const exe = (await readlink(`${proc}/${pid}/exe`).catch(() => null))?.replace(/ \(deleted\)$/, "");
      return { pid: Number(pid), ppid: stat.ppid, image: exe ?? argv[0]!, commandLine: argv.join(" "), start: stat.start };
    }),
  );
  return rows.filter((r): r is ProcessRow => r !== null);
}

/** `ps -axo pid=,ppid=,comm=` and `ps -axww -o pid=,command=`, joined by pid (comm is the full path and may hold spaces). */
export function parseMacPs(comm: string, commands: string): ProcessRow[] {
  const cmd = new Map<number, string>();
  for (const line of commands.split("\n")) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (m) cmd.set(Number(m[1]), m[2]!.trim());
  }
  const rows: ProcessRow[] = [];
  for (const line of comm.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line);
    if (!m) continue;
    const pid = Number(m[1]);
    const commandLine = cmd.get(pid) ?? m[3]!.trim();
    rows.push({ pid, ppid: Number(m[2]), image: m[3]!.trim(), commandLine, start: commandLine });
  }
  return rows;
}

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10_000, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => (error && !stdout ? reject(error) : resolve(String(stdout))));
  });
}

export function defaultRows(platform: NodeJS.Platform): (() => Promise<ProcessRow[]>) | undefined {
  if (platform === "linux") return () => procRows();
  if (platform === "darwin") return async () => {
    const [comm, commands] = await Promise.all([run("ps", ["-axo", "pid=,ppid=,comm="]), run("ps", ["-axww", "-o", "pid=,command="])]);
    return parseMacPs(comm, commands);
  };
  return undefined;
}

/** New programs since `known`; the first call (empty `known`) only records what runs. */
export class ProcessDiff {
  private known = new Set<string>();
  private seeded = false;

  next(rows: ProcessRow[], now: number): ProcessEvent[] {
    const byPid = new Map(rows.map((r) => [r.pid, r]));
    const keys = new Set(rows.map((r) => `${r.pid}:${r.start}`));
    const fresh = this.seeded ? rows.filter((r) => !this.known.has(`${r.pid}:${r.start}`)) : [];
    this.known = keys;
    this.seeded = true;
    return fresh.map((r) => {
      const parent = byPid.get(r.ppid);
      return { pid: r.pid, ppid: r.ppid, image: r.image, commandLine: r.commandLine, parentImage: parent?.image ?? "", parentCommandLine: parent?.commandLine ?? "", at: now };
    });
  }
}
