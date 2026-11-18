/**
 * Process explorer: every process with its parent (for a tree), threads,
 * handles (Windows) or open files (Linux), memory, command line and executable;
 * on request, the executable's SHA-256 and who signed it; and end, suspend and
 * resume.
 *
 * Signatures: Windows Authenticode (Get-AuthenticodeSignature), macOS code
 * signing (codesign), and on Linux the package that installed the file
 * (dpkg/rpm), verified by the package manager. Anything not readable is null.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, readdir, readlink } from "node:fs/promises";
import os from "node:os";

export interface ProcessInfo {
  pid: number;
  ppid: number | null;
  name: string;
  path: string | null;
  commandLine: string | null;
  user: string | null;
  threads: number | null;
  handles: number | null;
  memoryBytes: number | null;
  state: string | null;
}

export interface SignatureInfo {
  status: "signed" | "unsigned" | "invalid" | "package" | "unknown";
  signer: string | null;
  detail: string | null;
}

function run(command: string, args: string[], timeout = 15_000): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 32 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && !stdout && !stderr) reject(error);
      else resolve({ stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

// --- Parsers (pure, tested) -------------------------------------------------------------

/** /proc/<pid>/stat: the name is in parentheses and may contain spaces or ")". */
export function parseProcStat(text: string): { name: string; state: string; ppid: number; threads: number; rssPages: number } | null {
  const open = text.indexOf("(");
  const close = text.lastIndexOf(")");
  if (open < 0 || close < open) return null;
  const rest = text.slice(close + 2).split(" ");
  // rest[0]=state, [1]=ppid, ... [17]=num_threads, [21]=rss
  return { name: text.slice(open + 1, close), state: rest[0] ?? "?", ppid: Number(rest[1]), threads: Number(rest[17]), rssPages: Number(rest[21]) };
}

/** Uid line of /proc/<pid>/status. */
export function parseUid(status: string): number | null {
  const match = /^Uid:\s+(\d+)/m.exec(status);
  return match ? Number(match[1]) : null;
}

/** /etc/passwd → uid to name. */
export function parsePasswd(text: string): Map<number, string> {
  const users = new Map<number, string>();
  for (const line of text.split("\n")) {
    const [name, , uid] = line.split(":");
    if (name && uid && /^\d+$/.test(uid)) users.set(Number(uid), name);
  }
  return users;
}

/** Win32_Process rows from PowerShell (ConvertTo-Json). */
export function parseWindowsProcessDetails(json: string): ProcessInfo[] {
  let data: unknown;
  try {
    data = JSON.parse(json || "[]");
  } catch {
    return [];
  }
  const rows = (Array.isArray(data) ? data : [data]) as Record<string, unknown>[];
  return rows
    .filter((r) => r && typeof r.ProcessId === "number")
    .map((r) => ({
      pid: r.ProcessId as number,
      ppid: typeof r.ParentProcessId === "number" ? (r.ParentProcessId as number) : null,
      name: String(r.Name ?? ""),
      path: r.ExecutablePath ? String(r.ExecutablePath) : null,
      commandLine: r.CommandLine ? String(r.CommandLine) : null,
      user: r.User ? String(r.User) : null,
      threads: typeof r.ThreadCount === "number" ? (r.ThreadCount as number) : null,
      handles: typeof r.HandleCount === "number" ? (r.HandleCount as number) : null,
      memoryBytes: typeof r.WorkingSetSize === "number" ? (r.WorkingSetSize as number) : r.WorkingSetSize ? Number(r.WorkingSetSize) : null,
      state: null,
    }));
}

/** `ps -axo pid=,ppid=,rss=,user=,state=,comm=` then args from `ps -axo pid=,args=` (macOS). */
export function parsePsDetails(table: string, args: string): ProcessInfo[] {
  const commands = new Map<number, string>();
  for (const line of args.split("\n")) {
    const match = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (match) commands.set(Number(match[1]), match[2]!);
  }
  const rows: ProcessInfo[] = [];
  for (const line of table.split("\n")) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/.exec(line);
    if (!match) continue;
    const comm = match[6]!.trim();
    rows.push({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      name: comm.split("/").pop() ?? comm,
      path: comm.startsWith("/") ? comm : null,
      commandLine: commands.get(Number(match[1])) ?? null,
      user: match[4]!,
      threads: null,
      handles: null,
      memoryBytes: Number(match[3]) * 1024,
      state: match[5]!,
    });
  }
  return rows;
}

/** Get-AuthenticodeSignature → {Status, Signer}. */
export function parseAuthenticode(json: string): SignatureInfo {
  try {
    const data = JSON.parse(json) as { Status?: string | number; Signer?: string | null };
    const status = String(data.Status ?? "");
    const signer = data.Signer ? String(data.Signer).replace(/^CN=([^,]+).*$/, "$1") : null;
    if (status === "Valid" || status === "0") return { status: "signed", signer, detail: "Authenticode signature is valid." };
    if (status === "NotSigned" || status === "2") return { status: "unsigned", signer: null, detail: "The file has no digital signature." };
    if (status) return { status: "invalid", signer, detail: `Signature problem: ${status}.` };
  } catch {
    // fall through
  }
  return { status: "unknown", signer: null, detail: null };
}

/** `codesign -dv --verbose=2 <path>` writes to stderr. */
export function parseCodesign(stderr: string, exitOk: boolean): SignatureInfo {
  if (/code object is not signed/i.test(stderr)) return { status: "unsigned", signer: null, detail: "The program is not code-signed." };
  const authority = /^Authority=(.+)$/m.exec(stderr)?.[1] ?? null;
  const team = /^TeamIdentifier=(.+)$/m.exec(stderr)?.[1];
  if (exitOk && authority) return { status: "signed", signer: authority, detail: team && team !== "not set" ? `Team ${team}` : null };
  if (/invalid|modified|failed/i.test(stderr)) return { status: "invalid", signer: authority, detail: "The signature does not match the program." };
  return { status: "unknown", signer: null, detail: null };
}

/** `dpkg -S <path>` → "coreutils: /usr/bin/ls"; `rpm -qf` → "coreutils-9.1-1.fc39.x86_64". */
export function parsePackageOwner(stdout: string, tool: "dpkg" | "rpm"): string | null {
  const line = stdout.trim().split("\n")[0] ?? "";
  if (!line || /not owned|no path found|not found/i.test(line)) return null;
  return tool === "dpkg" ? (line.split(":")[0]?.trim() || null) : line.trim();
}

// --- Listing -----------------------------------------------------------------------------

async function linuxProcesses(): Promise<ProcessInfo[]> {
  const users = parsePasswd(await readFile("/etc/passwd", "utf8").catch(() => ""));
  const page = 4096;
  const rows: ProcessInfo[] = [];
  for (const pid of (await readdir("/proc")).filter((d) => /^\d+$/.test(d))) {
    try {
      const [stat, status, cmdline] = await Promise.all([
        readFile(`/proc/${pid}/stat`, "utf8"),
        readFile(`/proc/${pid}/status`, "utf8"),
        readFile(`/proc/${pid}/cmdline`, "utf8").catch(() => ""),
      ]);
      const parsed = parseProcStat(stat);
      if (!parsed) continue;
      const exe = await readlink(`/proc/${pid}/exe`).catch(() => null);
      const fds = await readdir(`/proc/${pid}/fd`).then((list) => list.length).catch(() => null);
      const uid = parseUid(status);
      rows.push({
        pid: Number(pid),
        ppid: parsed.ppid || null,
        name: parsed.name,
        path: exe ? exe.replace(/ \(deleted\)$/, "") : null,
        commandLine: cmdline ? cmdline.split("\0").filter(Boolean).join(" ").slice(0, 2000) : null,
        user: uid === null ? null : (users.get(uid) ?? String(uid)),
        threads: parsed.threads || null,
        handles: fds,
        memoryBytes: parsed.rssPages * page,
        state: parsed.state,
      });
    } catch {
      // process ended while reading
    }
  }
  return rows;
}

export async function processDetails(platform = process.platform): Promise<ProcessInfo[] | null> {
  try {
    if (platform === "linux") return await linuxProcesses();
    if (platform === "darwin") {
      const [table, args] = await Promise.all([run("ps", ["-axo", "pid=,ppid=,rss=,user=,state=,comm="]), run("ps", ["-axo", "pid=,args="])]);
      return parsePsDetails(table.stdout, args.stdout);
    }
    if (platform === "win32") {
      const { stdout } = await run(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,ThreadCount,HandleCount,WorkingSetSize | ConvertTo-Json -Compress",
        ],
        30_000,
      );
      return parseWindowsProcessDetails(stdout);
    }
    return null;
  } catch {
    return null;
  }
}

// --- Inspection --------------------------------------------------------------------------

export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path).on("data", (chunk) => hash.update(chunk)).on("error", reject).on("end", () => resolve(hash.digest("hex")));
  });
}

export async function signature(path: string, platform = process.platform): Promise<SignatureInfo> {
  try {
    if (platform === "win32") {
      const quoted = path.replace(/'/g, "''");
      const { stdout } = await run("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `$s = Get-AuthenticodeSignature -LiteralPath '${quoted}'; @{ Status = "$($s.Status)"; Signer = $s.SignerCertificate.Subject } | ConvertTo-Json -Compress`,
      ]);
      return parseAuthenticode(stdout);
    }
    if (platform === "darwin") {
      const result = await new Promise<{ stderr: string; ok: boolean }>((resolve) =>
        execFile("codesign", ["-dv", "--verbose=2", path], { timeout: 15_000 }, (error, _stdout, stderr) => resolve({ stderr: String(stderr), ok: !error })),
      );
      return parseCodesign(result.stderr, result.ok);
    }
    if (platform === "linux") {
      for (const [tool, args] of [["dpkg", ["-S", path]], ["rpm", ["-qf", path]]] as const) {
        const owner = await run(tool, [...args]).then((r) => parsePackageOwner(r.stdout, tool)).catch(() => null);
        if (owner) return { status: "package", signer: owner, detail: `Installed by the ${owner} package (${tool}).` };
      }
      return { status: "unsigned", signer: null, detail: "Not installed by the system's package manager." };
    }
  } catch {
    // fall through
  }
  return { status: "unknown", signer: null, detail: null };
}

// --- Actions -----------------------------------------------------------------------------

export type ProcessAction = "end" | "suspend" | "resume";

/** End, suspend or resume a process. The PID must be a positive integer and never this app. */
export async function controlProcess(pid: number, action: ProcessAction, platform = process.platform): Promise<void> {
  if (!Number.isInteger(pid) || pid <= 4) throw new Error("That process cannot be changed.");
  if (pid === process.pid || pid === process.ppid) throw new Error("Qalaa cannot stop itself here.");
  if (platform === "win32") {
    if (action !== "end") throw new Error("Suspending processes is not supported on Windows.");
    await run("taskkill", ["/PID", String(pid), "/T", "/F"]);
    return;
  }
  const signal = action === "end" ? "SIGTERM" : action === "suspend" ? "SIGSTOP" : "SIGCONT";
  process.kill(pid, signal);
}

export function systemSummary() {
  return { hostname: os.hostname(), platform: os.platform(), release: os.release(), arch: os.arch(), cpus: os.cpus().length };
}
