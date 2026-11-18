/**
 * System monitor: live CPU (per core, clock, temperature), memory, GPU, disk
 * throughput and IOPS, network bandwidth; network connections with the process
 * that owns each one; services; and recent system log events.
 *
 * Everything is read locally with execFile (no shell) or from /proc and /sys,
 * with timeouts. Nothing is sent anywhere. A value the system will not give us
 * is reported as null ("unavailable"), never guessed.
 */
import { execFile, spawn } from "node:child_process";
import { readFile, readdir, statfs } from "node:fs/promises";
import os from "node:os";

import { decodeProcAddress, socketOwners } from "./security";

function run(command: string, args: string[], timeout = 10_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(String(stdout));
    });
  });
}

const powershell = (script: string, timeout?: number) =>
  run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], timeout);

// --- CPU -------------------------------------------------------------------------------

export interface CoreTimes {
  idle: number;
  total: number;
}

export function coreTimes(cpus = os.cpus()): CoreTimes[] {
  return cpus.map((cpu) => {
    const t = cpu.times;
    return { idle: t.idle, total: t.user + t.nice + t.sys + t.idle + t.irq };
  });
}

/** Busy percentage per core between two samples. */
export function coreUsage(before: CoreTimes[], after: CoreTimes[]): number[] {
  return after.map((now, i) => {
    const prev = before[i];
    if (!prev) return 0;
    const total = now.total - prev.total;
    const idle = now.idle - prev.idle;
    return total > 0 ? Math.max(0, Math.min(100, Math.round(((total - idle) / total) * 1000) / 10)) : 0;
  });
}

/** Linux thermal zones / hwmon: the hottest CPU-ish sensor, in °C. */
export function pickCpuTemperature(sensors: { type: string; celsius: number }[]): number | null {
  const valid = sensors.filter((s) => s.celsius > 0 && s.celsius < 130);
  const cpu = valid.filter((s) => /cpu|x86_pkg|coretemp|k10temp|zenpower|soc|package/i.test(s.type));
  const pool = cpu.length ? cpu : valid;
  return pool.length ? Math.round(Math.max(...pool.map((s) => s.celsius))) : null;
}

async function linuxTemperature(): Promise<number | null> {
  const sensors: { type: string; celsius: number }[] = [];
  for (const zone of await readdir("/sys/class/thermal").catch(() => [] as string[])) {
    if (!zone.startsWith("thermal_zone")) continue;
    const [type, temp] = await Promise.all([
      readFile(`/sys/class/thermal/${zone}/type`, "utf8").catch(() => ""),
      readFile(`/sys/class/thermal/${zone}/temp`, "utf8").catch(() => ""),
    ]);
    if (temp) sensors.push({ type: type.trim(), celsius: Number(temp) / 1000 });
  }
  for (const hw of await readdir("/sys/class/hwmon").catch(() => [] as string[])) {
    const name = (await readFile(`/sys/class/hwmon/${hw}/name`, "utf8").catch(() => "")).trim();
    const temp = await readFile(`/sys/class/hwmon/${hw}/temp1_input`, "utf8").catch(() => "");
    if (temp) sensors.push({ type: name, celsius: Number(temp) / 1000 });
  }
  return pickCpuTemperature(sensors);
}

// --- Memory -------------------------------------------------------------------------------

/** /proc/meminfo "MemAvailable" is what programs can really use (free + reclaimable cache). */
export function parseMeminfo(text: string): { total: number; available: number } | null {
  const value = (key: string) => {
    const match = new RegExp(`^${key}:\\s+(\\d+) kB`, "m").exec(text);
    return match ? Number(match[1]) * 1024 : null;
  };
  const total = value("MemTotal");
  const available = value("MemAvailable");
  return total && available !== null ? { total, available } : null;
}

// --- Disk and network counters ------------------------------------------------------------

export interface IoCounters {
  readBytes: number;
  writeBytes: number;
  reads: number;
  writes: number;
}

/** /proc/diskstats: whole disks only (no partitions, loop or ram devices). Sectors are 512 bytes. */
export function parseDiskstats(text: string): IoCounters {
  const totals = { readBytes: 0, writeBytes: 0, reads: 0, writes: 0 };
  for (const line of text.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const name = f[2]!;
    if (/^(loop|ram|zram|dm-|md|sr|fd)/.test(name)) continue;
    if (/^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+)\d+$/.test(name) || /^(nvme\d+n\d+|mmcblk\d+)p\d+$/.test(name)) continue;
    totals.reads += Number(f[3]);
    totals.readBytes += Number(f[5]) * 512;
    totals.writes += Number(f[7]);
    totals.writeBytes += Number(f[9]) * 512;
  }
  return totals;
}

export interface NetCounters {
  rxBytes: number;
  txBytes: number;
}

/** /proc/net/dev, without the loopback interface. */
export function parseNetDev(text: string): NetCounters {
  let rxBytes = 0;
  let txBytes = 0;
  for (const line of text.split("\n").slice(2)) {
    const [name, rest] = line.split(":");
    if (!rest || name!.trim() === "lo") continue;
    const f = rest.trim().split(/\s+/);
    rxBytes += Number(f[0]);
    txBytes += Number(f[8]);
  }
  return { rxBytes, txBytes };
}

/** `netstat -ib` (macOS): per-interface Ibytes/Obytes, counted once per interface. */
export function parseNetstatIb(stdout: string): NetCounters {
  const lines = stdout.split("\n");
  const header = lines[0]?.trim().split(/\s+/) ?? [];
  const ib = header.indexOf("Ibytes");
  const ob = header.indexOf("Obytes");
  const seen = new Set<string>();
  let rxBytes = 0;
  let txBytes = 0;
  for (const line of lines.slice(1)) {
    const f = line.trim().split(/\s+/);
    if (!f[0] || f[0].startsWith("lo") || seen.has(f[0]) || !/<Link#/.test(line)) continue;
    seen.add(f[0]);
    // Rows without an address have one column fewer; count from the end.
    const shift = f.length - header.length;
    rxBytes += Number(f[ib + shift]) || 0;
    txBytes += Number(f[ob + shift]) || 0;
  }
  return { rxBytes, txBytes };
}

/** Per-second rate between two counter samples; counters that went backwards (reset) give 0. */
export function rate(before: number, after: number, seconds: number): number {
  return seconds > 0 && after >= before ? Math.round((after - before) / seconds) : 0;
}

// --- GPU -------------------------------------------------------------------------------------

export interface GpuStats {
  name: string;
  utilization: number | null;
  memoryUsed: number | null;
  memoryTotal: number | null;
  temperature: number | null;
}

/** `nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits` */
export function parseNvidiaSmi(stdout: string): GpuStats[] {
  return stdout
    .split("\n")
    .map((line) => line.split(",").map((part) => part.trim()))
    .filter((f) => f.length >= 5 && f[0])
    .map((f) => {
      const num = (v: string | undefined) => (v && /^\d+(\.\d+)?$/.test(v) ? Number(v) : null);
      const mib = (v: string | undefined) => (num(v) === null ? null : num(v)! * 1024 * 1024);
      return { name: f[0]!, utilization: num(f[1]), memoryUsed: mib(f[2]), memoryTotal: mib(f[3]), temperature: num(f[4]) };
    });
}

/** Windows performance counters: sum of the 3D engines' utilisation, and dedicated memory in use. */
export function parseWindowsGpu(json: string): { utilization: number | null; memoryUsed: number | null } {
  try {
    const data = JSON.parse(json) as { util?: number | null; mem?: number | null };
    return {
      utilization: typeof data.util === "number" ? Math.min(100, Math.round(data.util * 10) / 10) : null,
      memoryUsed: typeof data.mem === "number" ? Math.round(data.mem) : null,
    };
  } catch {
    return { utilization: null, memoryUsed: null };
  }
}

async function gpuStats(platform: string): Promise<GpuStats[]> {
  // NVIDIA on any system, when its tools are installed.
  const nvidia = await run("nvidia-smi", ["--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits"], 5000)
    .then(parseNvidiaSmi)
    .catch(() => [] as GpuStats[]);
  if (nvidia.length) return nvidia;
  if (platform === "linux") {
    const gpus: GpuStats[] = [];
    for (const card of await readdir("/sys/class/drm").catch(() => [] as string[])) {
      if (!/^card\d+$/.test(card)) continue;
      const base = `/sys/class/drm/${card}/device`;
      const busy = await readFile(`${base}/gpu_busy_percent`, "utf8").catch(() => null);
      if (busy === null) continue;
      const [used, total] = await Promise.all([
        readFile(`${base}/mem_info_vram_used`, "utf8").catch(() => null),
        readFile(`${base}/mem_info_vram_total`, "utf8").catch(() => null),
      ]);
      gpus.push({ name: card, utilization: Number(busy), memoryUsed: used ? Number(used) : null, memoryTotal: total ? Number(total) : null, temperature: null });
    }
    return gpus;
  }
  if (platform === "win32") {
    const stats = await powershell(
      "$u=(Get-Counter '\\GPU Engine(*engtype_3D)\\Utilization Percentage' -ErrorAction SilentlyContinue).CounterSamples | Measure-Object CookedValue -Sum;" +
        "$m=(Get-Counter '\\GPU Adapter Memory(*)\\Dedicated Usage' -ErrorAction SilentlyContinue).CounterSamples | Measure-Object CookedValue -Sum;" +
        "@{util=$u.Sum;mem=$m.Sum} | ConvertTo-Json -Compress",
      8000,
    )
      .then(parseWindowsGpu)
      .catch(() => ({ utilization: null, memoryUsed: null }));
    if (stats.utilization === null && stats.memoryUsed === null) return [];
    return [{ name: "GPU", utilization: stats.utilization, memoryUsed: stats.memoryUsed, memoryTotal: null, temperature: null }];
  }
  if (platform === "darwin") {
    const out = await run("ioreg", ["-r", "-d", "1", "-w", "0", "-c", "IOAccelerator"], 5000).catch(() => "");
    const util = /"Device Utilization %"=(\d+)/.exec(out);
    const used = /"In use system memory"=(\d+)/.exec(out);
    if (!util) return [];
    return [{ name: "GPU", utilization: Number(util[1]), memoryUsed: used ? Number(used[1]) : null, memoryTotal: null, temperature: null }];
  }
  return [];
}

// --- Sampling ------------------------------------------------------------------------------

export interface Snapshot {
  at: string;
  cpu: { total: number; cores: number[]; speedMhz: number[]; model: string; temperature: number | null };
  memory: { total: number; used: number };
  swap: { total: number; used: number } | null;
  disk: { readPerSec: number; writePerSec: number; iops: number; used: number | null; size: number | null } | null;
  network: { rxPerSec: number; txPerSec: number } | null;
  gpus: GpuStats[];
  load: number[] | null;
  uptimeSeconds: number;
}

export class Sampler {
  private cpu = coreTimes();
  private io: { at: number; disk: IoCounters | null; net: NetCounters | null } | null = null;

  constructor(private readonly platform = process.platform) {}

  private async diskCounters(): Promise<IoCounters | null> {
    if (this.platform === "linux") return readFile("/proc/diskstats", "utf8").then(parseDiskstats).catch(() => null);
    return null;
  }

  private async netCounters(): Promise<NetCounters | null> {
    if (this.platform === "linux") return readFile("/proc/net/dev", "utf8").then(parseNetDev).catch(() => null);
    if (this.platform === "darwin") return run("netstat", ["-ib"]).then(parseNetstatIb).catch(() => null);
    return null;
  }

  /** Windows exposes rates directly through performance counters. */
  private async windowsRates(): Promise<{ disk: Snapshot["disk"]; network: Snapshot["network"] } | null> {
    const json = await powershell(
      "$c=(Get-Counter '\\PhysicalDisk(_Total)\\Disk Read Bytes/sec','\\PhysicalDisk(_Total)\\Disk Write Bytes/sec','\\PhysicalDisk(_Total)\\Disk Transfers/sec','\\Network Interface(*)\\Bytes Received/sec','\\Network Interface(*)\\Bytes Sent/sec' -ErrorAction SilentlyContinue).CounterSamples;" +
        "@{r=($c|?{$_.Path -like '*read bytes*'}|Measure CookedValue -Sum).Sum;w=($c|?{$_.Path -like '*write bytes*'}|Measure CookedValue -Sum).Sum;t=($c|?{$_.Path -like '*transfers*'}|Measure CookedValue -Sum).Sum;rx=($c|?{$_.Path -like '*received*'}|Measure CookedValue -Sum).Sum;tx=($c|?{$_.Path -like '*bytes sent*'}|Measure CookedValue -Sum).Sum}|ConvertTo-Json -Compress",
      8000,
    ).catch(() => null);
    if (!json) return null;
    try {
      const v = JSON.parse(json) as Record<string, number | null>;
      return {
        disk: { readPerSec: Math.round(v.r ?? 0), writePerSec: Math.round(v.w ?? 0), iops: Math.round(v.t ?? 0), used: null, size: null },
        network: { rxPerSec: Math.round(v.rx ?? 0), txPerSec: Math.round(v.tx ?? 0) },
      };
    } catch {
      return null;
    }
  }

  async sample(withGpu = true): Promise<Snapshot> {
    const cpus = os.cpus();
    const now = coreTimes(cpus);
    const cores = coreUsage(this.cpu, now);
    this.cpu = now;

    let memory = { total: os.totalmem(), used: os.totalmem() - os.freemem() };
    let swap: Snapshot["swap"] = null;
    if (this.platform === "linux") {
      const text = await readFile("/proc/meminfo", "utf8").catch(() => "");
      const info = parseMeminfo(text);
      if (info) memory = { total: info.total, used: info.total - info.available };
      const swapTotal = /^SwapTotal:\s+(\d+)/m.exec(text);
      const swapFree = /^SwapFree:\s+(\d+)/m.exec(text);
      if (swapTotal && swapFree && Number(swapTotal[1]) > 0) swap = { total: Number(swapTotal[1]) * 1024, used: (Number(swapTotal[1]) - Number(swapFree[1])) * 1024 };
    }

    let disk: Snapshot["disk"] = null;
    let network: Snapshot["network"] = null;
    if (this.platform === "win32") {
      const rates = await this.windowsRates();
      disk = rates?.disk ?? null;
      network = rates?.network ?? null;
    } else {
      const at = Date.now();
      const [diskNow, netNow] = await Promise.all([this.diskCounters(), this.netCounters()]);
      if (this.io) {
        const seconds = (at - this.io.at) / 1000;
        if (diskNow && this.io.disk) {
          disk = {
            readPerSec: rate(this.io.disk.readBytes, diskNow.readBytes, seconds),
            writePerSec: rate(this.io.disk.writeBytes, diskNow.writeBytes, seconds),
            iops: rate(this.io.disk.reads + this.io.disk.writes, diskNow.reads + diskNow.writes, seconds),
            used: null,
            size: null,
          };
        }
        if (netNow && this.io.net) network = { rxPerSec: rate(this.io.net.rxBytes, netNow.rxBytes, seconds), txPerSec: rate(this.io.net.txBytes, netNow.txBytes, seconds) };
      } else {
        // First reading: the counters work, rates need a second sample.
        if (diskNow) disk = { readPerSec: 0, writePerSec: 0, iops: 0, used: null, size: null };
        if (netNow) network = { rxPerSec: 0, txPerSec: 0 };
      }
      this.io = { at, disk: diskNow, net: netNow };
    }
    const root = this.platform === "win32" ? `${process.env.SystemDrive ?? "C:"}\\` : "/";
    const fs = await statfs(root).catch(() => null);
    if (fs) {
      const size = fs.blocks * fs.bsize;
      disk = { ...(disk ?? { readPerSec: 0, writePerSec: 0, iops: 0 }), size, used: size - fs.bfree * fs.bsize };
    }

    return {
      at: new Date().toISOString(),
      cpu: {
        total: cores.length ? Math.round((cores.reduce((a, b) => a + b, 0) / cores.length) * 10) / 10 : 0,
        cores,
        speedMhz: cpus.map((c) => c.speed),
        model: cpus[0]?.model.trim() ?? "",
        temperature: this.platform === "linux" ? await linuxTemperature() : null,
      },
      memory,
      swap,
      disk,
      network,
      gpus: withGpu ? await gpuStats(this.platform) : [],
      load: this.platform === "win32" ? null : os.loadavg().map((v) => Math.round(v * 100) / 100),
      uptimeSeconds: Math.round(os.uptime()),
    };
  }
}

// --- Connections ---------------------------------------------------------------------------

export interface Connection {
  protocol: "tcp" | "udp";
  local: string;
  remote: string | null;
  state: string;
  process: string | null;
  pid: number | null;
}

const TCP_STATES: Record<string, string> = {
  "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
  "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
};

function endpoint(address: string, port: number): string {
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

/** /proc/net/{tcp,tcp6,udp,udp6} rows, with owners from socket inodes. */
export function parseProcConnections(text: string, protocol: "tcp" | "udp", owners: Map<string, { name: string; pid: number }>): Connection[] {
  const rows: Connection[] = [];
  for (const line of text.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const [la, lp] = f[1]!.split(":");
    const [ra, rp] = f[2]!.split(":");
    if (!la || !lp || !ra || !rp) continue;
    const remotePort = Number.parseInt(rp, 16);
    const remoteAddress = decodeProcAddress(ra);
    const owner = owners.get(f[9]!);
    rows.push({
      protocol,
      local: endpoint(decodeProcAddress(la), Number.parseInt(lp, 16)),
      remote: remotePort === 0 && /^(0\.0\.0\.0|::)$/.test(remoteAddress) ? null : endpoint(remoteAddress, remotePort),
      state: protocol === "udp" ? (f[3] === "07" ? "OPEN" : "CONNECTED") : (TCP_STATES[f[3]!] ?? f[3]!),
      process: owner?.name ?? null,
      pid: owner?.pid ?? null,
    });
  }
  return rows;
}

/** `lsof -nP -i` (macOS). */
export function parseLsofConnections(stdout: string): Connection[] {
  const rows: Connection[] = [];
  for (const line of stdout.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 9) continue;
    const proto = f[7]?.toLowerCase();
    if (proto !== "tcp" && proto !== "udp") continue;
    const name = f.slice(8).join(" ");
    const state = /\(([A-Z_]+)\)/.exec(name)?.[1] ?? (proto === "udp" ? "OPEN" : "");
    const [local, remote] = name.replace(/\s*\([A-Z_]+\)$/, "").split("->");
    rows.push({ protocol: proto, local: local!, remote: remote ?? null, state, process: f[0]!.replace(/\\x20/g, " "), pid: Number(f[1]) || null });
  }
  return rows;
}

/** PowerShell Get-NetTCPConnection / Get-NetUDPEndpoint rows joined with process names. */
export function parseWindowsConnections(json: string): Connection[] {
  let data: unknown;
  try {
    data = JSON.parse(json || "[]");
  } catch {
    return [];
  }
  const rows = (Array.isArray(data) ? data : [data]) as { p: string; la: string; lp: number; ra?: string | null; rp?: number | null; s?: string | null; pid?: number; n?: string | null }[];
  return rows
    .filter((r) => r && r.la !== undefined)
    .map((r) => ({
      protocol: r.p === "udp" ? "udp" : "tcp",
      local: endpoint(r.la, r.lp),
      remote: r.ra && r.rp ? endpoint(r.ra, r.rp) : null,
      state: r.p === "udp" ? "OPEN" : String(r.s ?? "").toUpperCase(),
      process: r.n ?? null,
      pid: r.pid ?? null,
    }));
}

export async function connections(platform = process.platform): Promise<Connection[] | null> {
  try {
    if (platform === "linux") {
      const owners = await socketOwners();
      const tables = await Promise.all(
        (["tcp", "tcp6", "udp", "udp6"] as const).map(async (name) => ({ name, text: await readFile(`/proc/net/${name}`, "utf8").catch(() => "") })),
      );
      return tables.flatMap(({ name, text }) => parseProcConnections(text, name.startsWith("tcp") ? "tcp" : "udp", owners));
    }
    if (platform === "darwin") return parseLsofConnections(await run("lsof", ["-nP", "-i"]));
    if (platform === "win32") {
      return parseWindowsConnections(
        await powershell(
          "$n=@{};Get-Process|%{$n[$_.Id]=$_.ProcessName};" +
            "$t=Get-NetTCPConnection|%{@{p='tcp';la=$_.LocalAddress;lp=$_.LocalPort;ra=$_.RemoteAddress;rp=$_.RemotePort;s=\"$($_.State)\";pid=$_.OwningProcess;n=$n[[int]$_.OwningProcess]}};" +
            "$u=Get-NetUDPEndpoint|%{@{p='udp';la=$_.LocalAddress;lp=$_.LocalPort;pid=$_.OwningProcess;n=$n[[int]$_.OwningProcess]}};" +
            "@($t)+@($u)|ConvertTo-Json -Compress",
          15_000,
        ),
      );
    }
    return null;
  } catch {
    return null;
  }
}

// --- Services --------------------------------------------------------------------------------

export interface Service {
  name: string;
  description: string;
  state: "running" | "stopped" | "failed" | "other";
  startup: string | null;
}

/** `systemctl list-units --type=service --all --no-pager --plain --no-legend` */
export function parseSystemctl(stdout: string): Service[] {
  return stdout
    .split("\n")
    .map((line) => line.trim().split(/\s+/))
    .filter((f) => f.length >= 4 && f[0]!.endsWith(".service"))
    .map((f) => ({
      name: f[0]!,
      description: f.slice(4).join(" "),
      state: f[2] === "failed" ? "failed" : f[3] === "running" ? "running" : f[2] === "inactive" ? "stopped" : "other",
      startup: null,
    }));
}

/** Get-Service | Select Name,DisplayName,Status,StartType | ConvertTo-Json (Status/StartType as text). */
export function parseWindowsServices(json: string): Service[] {
  let data: unknown;
  try {
    data = JSON.parse(json || "[]");
  } catch {
    return [];
  }
  const rows = (Array.isArray(data) ? data : [data]) as { Name: string; DisplayName?: string; Status?: string; StartType?: string }[];
  return rows
    .filter((r) => r?.Name)
    .map((r) => ({
      name: r.Name,
      description: r.DisplayName ?? "",
      state: r.Status === "Running" ? "running" : r.Status === "Stopped" ? "stopped" : "other",
      startup: r.StartType ?? null,
    }));
}

/** `launchctl list` (macOS): PID, last exit status, label. */
export function parseLaunchctl(stdout: string): Service[] {
  return stdout
    .split("\n")
    .slice(1)
    .map((line) => line.trim().split(/\t|\s+/))
    .filter((f) => f.length >= 3 && f[2])
    .map((f) => ({
      name: f[2]!,
      description: "",
      state: f[0] !== "-" ? "running" : f[1] !== "0" && f[1] !== "-" ? "failed" : "stopped",
      startup: null,
    }));
}

export async function services(platform = process.platform): Promise<Service[] | null> {
  try {
    if (platform === "linux") return parseSystemctl(await run("systemctl", ["list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"]));
    if (platform === "win32") {
      return parseWindowsServices(
        await powershell("Get-Service | Select-Object Name,DisplayName,@{n='Status';e={\"$($_.Status)\"}},@{n='StartType';e={\"$($_.StartType)\"}} | ConvertTo-Json -Compress", 15_000),
      );
    }
    if (platform === "darwin") return parseLaunchctl(await run("launchctl", ["list"]));
    return null;
  } catch {
    return null;
  }
}

const SERVICE_NAME = /^[A-Za-z0-9@._:-]{1,128}$/;

/**
 * Start, stop or restart a service. Needs administrator rights, which the system
 * asks for itself (polkit on Linux, UAC on Windows). The name is checked strictly
 * and passed as an argument, never through a shell.
 */
export async function controlService(name: string, action: "start" | "stop" | "restart", platform = process.platform): Promise<void> {
  if (!SERVICE_NAME.test(name)) throw new Error("That is not a valid service name.");
  if (platform === "linux") {
    await run("pkexec", ["systemctl", action, name], 120_000);
    return;
  }
  if (platform === "win32") {
    const verb = { start: "Start-Service", stop: "Stop-Service", restart: "Restart-Service" }[action];
    // The service name has been validated above, so it cannot break out of the quotes.
    await powershell(
      `Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','${verb} -Name ''${name}'' -Force'`,
      120_000,
    );
    return;
  }
  throw new Error("Managing services from Qalaa is not supported on this system.");
}

// --- System log -------------------------------------------------------------------------------

export interface LogEvent {
  at: string;
  level: "error" | "warning" | "info";
  source: string;
  message: string;
  security: boolean;
}

const SECURITY_HINTS = /failed password|authentication failure|invalid user|sudo:.*incorrect|failed login|logon failure|account (was )?locked|4625|4740|firewall|denied|audit/i;

function level(priority: number): LogEvent["level"] {
  return priority <= 3 ? "error" : priority === 4 ? "warning" : "info";
}

/** `journalctl -o json` lines. */
export function parseJournal(stdout: string): LogEvent[] {
  const events: LogEvent[] = [];
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line) as Record<string, unknown>;
      const message = Array.isArray(e.MESSAGE) ? "(binary message)" : String(e.MESSAGE ?? "");
      const micros = Number(e.__REALTIME_TIMESTAMP ?? 0);
      events.push({
        at: new Date(micros / 1000).toISOString(),
        level: level(Number(e.PRIORITY ?? 6)),
        source: String(e.SYSLOG_IDENTIFIER ?? e._COMM ?? "system"),
        message: message.slice(0, 500),
        security: SECURITY_HINTS.test(message),
      });
    } catch {
      // skip a malformed line
    }
  }
  return events;
}

/** Get-WinEvent rows: LevelDisplayName / Level 1-2 error, 3 warning. */
export function parseWindowsEvents(json: string): LogEvent[] {
  let data: unknown;
  try {
    data = JSON.parse(json || "[]");
  } catch {
    return [];
  }
  const rows = (Array.isArray(data) ? data : [data]) as { t: string; l: number; s: string; m: string | null; id: number }[];
  return rows
    .filter((r) => r?.t)
    .map((r) => ({
      at: new Date(r.t).toISOString(),
      level: r.l <= 2 ? "error" : r.l === 3 ? "warning" : "info",
      source: r.s,
      message: `${r.id}: ${(r.m ?? "").split("\n")[0]}`.slice(0, 500),
      security: SECURITY_HINTS.test(`${r.id} ${r.m ?? ""}`),
    }));
}

/** `log show --style ndjson` (macOS). */
export function parseMacLog(stdout: string): LogEvent[] {
  const events: LogEvent[] = [];
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    try {
      const e = JSON.parse(line) as { timestamp?: string; messageType?: string; processImagePath?: string; eventMessage?: string };
      const message = String(e.eventMessage ?? "");
      events.push({
        at: new Date((e.timestamp ?? "").replace(" ", "T")).toISOString(),
        level: e.messageType === "Fault" || e.messageType === "Error" ? "error" : e.messageType === "Default" ? "info" : "warning",
        source: (e.processImagePath ?? "system").split("/").pop()!,
        message: message.slice(0, 500),
        security: SECURITY_HINTS.test(message),
      });
    } catch {
      // skip
    }
  }
  return events;
}

/** Recent warnings and errors (and security-related lines) from the system log. */
export async function recentEvents(minutes = 30, platform = process.platform): Promise<LogEvent[] | null> {
  try {
    if (platform === "linux") {
      return parseJournal(await run("journalctl", ["-o", "json", "--no-pager", "-p", "warning", "--since", `-${minutes}min`, "-n", "300"], 15_000)).reverse();
    }
    if (platform === "win32") {
      return parseWindowsEvents(
        await powershell(
          `Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2,3;StartTime=(Get-Date).AddMinutes(-${Math.round(minutes)})} -MaxEvents 300 -ErrorAction SilentlyContinue | Select-Object @{n='t';e={$_.TimeCreated.ToString('o')}},@{n='l';e={$_.Level}},@{n='s';e={$_.ProviderName}},@{n='m';e={$_.Message}},@{n='id';e={$_.Id}} | ConvertTo-Json -Compress`,
          20_000,
        ),
      );
    }
    if (platform === "darwin") {
      return parseMacLog(await run("log", ["show", "--style", "ndjson", "--last", `${Math.round(minutes)}m`, "--predicate", "messageType == error OR messageType == fault"], 30_000)).slice(-300).reverse();
    }
    return null;
  } catch {
    return null;
  }
}

/** Follows the Linux journal live, calling back with each new warning or error. */
export function followJournal(onEvent: (event: LogEvent) => void): () => void {
  if (process.platform !== "linux") return () => undefined;
  const child = spawn("journalctl", ["-o", "json", "-f", "-n", "0", "-p", "warning", "--no-pager"], { stdio: ["ignore", "pipe", "ignore"] });
  let buffer = "";
  child.stdout.on("data", (chunk: Buffer) => {
    buffer += chunk.toString();
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const event of parseJournal(lines.join("\n"))) onEvent(event);
  });
  child.on("error", () => undefined);
  return () => child.kill();
}
