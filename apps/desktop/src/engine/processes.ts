/**
 * Running programs: which executables are running right now, and which of them
 * deserve a closer look.
 *
 * Each distinct executable is scanned with the same engine as files on disk
 * (signatures, ClamAV when installed, file-type checks); results are cached by
 * path, size and modification time so repeated checks are cheap. On top of that,
 * simple location rules flag programs running from places legitimate software
 * rarely runs from (temporary folders, Downloads, a deleted file on Linux).
 *
 * Read-only: nothing is stopped or changed. Commands run through execFile (no
 * shell) with timeouts; anything that cannot be read is reported, not guessed.
 */
import { execFile } from "node:child_process";
import { readFile, readdir, readlink } from "node:fs/promises";
import { homedir } from "node:os";
import { basename } from "node:path";

export interface RunningProcess {
  pid: number;
  name: string;
  /** Full path of the executable, when the system tells us. */
  path: string | null;
  /** Linux: the executable was deleted or replaced after it started. */
  deleted?: boolean;
}

export type ProcessConcern = "temp_folder" | "downloads_folder" | "deleted_executable" | "memory_only" | "hidden_folder";

function run(command: string, args: string[], timeout = 15_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(String(stdout));
    });
  });
}

// --- Parsing (pure, tested) ------------------------------------------------------------

/** PowerShell: Get-CimInstance Win32_Process | Select ProcessId,Name,ExecutablePath | ConvertTo-Json */
export function parseWindowsProcesses(json: string): RunningProcess[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json || "[]");
  } catch {
    return [];
  }
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows
    .filter((row): row is { ProcessId: number; Name: string; ExecutablePath?: string | null } => typeof row === "object" && row !== null && "ProcessId" in row)
    .map((row) => ({ pid: Number(row.ProcessId), name: String(row.Name ?? ""), path: row.ExecutablePath ? String(row.ExecutablePath) : null }));
}

/** `ps -axo pid=,comm=` on macOS (comm is the full executable path). */
export function parsePs(stdout: string): RunningProcess[] {
  return stdout
    .split("\n")
    .map((line) => line.trim().match(/^(\d+)\s+(.+)$/))
    .filter((m): m is RegExpMatchArray => m !== null)
    .map((m) => {
      const command = m[2]!;
      return { pid: Number(m[1]), name: basename(command), path: command.startsWith("/") ? command : null };
    });
}

/** Linux /proc/<pid>/exe target, which ends in " (deleted)" when the file is gone. */
export function parseProcExe(target: string): { path: string; deleted: boolean } {
  const deleted = target.endsWith(" (deleted)");
  return { path: deleted ? target.slice(0, -" (deleted)".length) : target, deleted };
}

const TEMP_PATTERNS = [/[\\/]AppData[\\/]Local[\\/]Temp[\\/]/i, /^\/tmp\//, /^\/var\/tmp\//, /^\/dev\/shm\//, /^\/private\/(var\/folders|tmp)\//, /[\\/]Windows[\\/]Temp[\\/]/i];

// Hidden folders where developer tools and app runtimes normally live.
const KNOWN_HIDDEN_FOLDERS = new Set([
  ".local", ".cache", ".var", ".npm", ".nvm", ".cargo", ".rustup", ".vscode", ".vscode-server",
  ".cursor", ".pyenv", ".sdkman", ".bun", ".deno", ".volta", ".steam", ".rbenv", ".asdf", ".dotnet", ".gradle",
]);

export function concernsFor(process: RunningProcess, home = homedir()): ProcessConcern[] {
  const concerns: ProcessConcern[] = [];
  const path = process.path;
  // Linux: a program loaded straight into memory (memfd) has no file on disk at all,
  // a technique used by "fileless" malware.
  if (path?.startsWith("/memfd:")) return ["memory_only"];
  if (process.deleted) concerns.push("deleted_executable");
  if (!path) return concerns;
  if (TEMP_PATTERNS.some((pattern) => pattern.test(path))) concerns.push("temp_folder");
  const downloads = `${home}${home.includes("\\") ? "\\" : "/"}Downloads`;
  if (path.toLowerCase().startsWith(downloads.toLowerCase())) concerns.push("downloads_folder");
  // A program inside a hidden folder in the home directory (Linux/macOS), outside
  // well-known app locations that are hidden by convention.
  if (path.startsWith(`${home}/.`)) {
    const folder = path.slice(home.length + 1).split("/")[0]!;
    if (!KNOWN_HIDDEN_FOLDERS.has(folder)) concerns.push("hidden_folder");
  }
  return concerns;
}

/** One entry per executable, with every PID running it. */
export function groupByExecutable(processes: RunningProcess[]): { path: string; name: string; pids: number[]; deleted: boolean }[] {
  const groups = new Map<string, { path: string; name: string; pids: number[]; deleted: boolean }>();
  for (const process of processes) {
    if (!process.path) continue;
    const group = groups.get(process.path) ?? { path: process.path, name: process.name || basename(process.path), pids: [], deleted: false };
    group.pids.push(process.pid);
    group.deleted ||= Boolean(process.deleted);
    groups.set(process.path, group);
  }
  return [...groups.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// --- Listing --------------------------------------------------------------------------

async function linuxProcesses(): Promise<RunningProcess[]> {
  const pids = (await readdir("/proc")).filter((entry) => /^\d+$/.test(entry));
  const processes: RunningProcess[] = [];
  for (const pid of pids) {
    try {
      const { path, deleted } = parseProcExe(await readlink(`/proc/${pid}/exe`));
      const name = (await readFile(`/proc/${pid}/comm`, "utf8")).trim();
      processes.push({ pid: Number(pid), name, path, deleted });
    } catch {
      // Another user's process (no permission) or one that just ended.
    }
  }
  return processes;
}

export async function listProcesses(platform = process.platform): Promise<RunningProcess[] | null> {
  try {
    if (platform === "linux") return await linuxProcesses();
    if (platform === "darwin") return parsePs(await run("ps", ["-axo", "pid=,comm="]));
    if (platform === "win32") {
      return parseWindowsProcesses(
        await run("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress",
        ]),
      );
    }
    return null;
  } catch {
    return null;
  }
}
