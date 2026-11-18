/**
 * Storage inspector: physical disks with their health (S.M.A.R.T. where the
 * system reports it), and volumes with file system, capacity and use.
 *
 * - Linux: lsblk (no root needed); health from smartctl when installed and allowed.
 * - Windows: Get-PhysicalDisk (health without administrator rights) and Get-Volume.
 * - macOS: diskutil (SMART Status) and df.
 */
import { execFile } from "node:child_process";

export interface PhysicalDisk {
  name: string;
  model: string | null;
  kind: "ssd" | "hdd" | "unknown";
  sizeBytes: number | null;
  health: "ok" | "warning" | "failing" | "unknown";
  healthDetail: string | null;
}

export interface Volume {
  mount: string;
  device: string | null;
  fileSystem: string | null;
  sizeBytes: number;
  usedBytes: number;
  label: string | null;
}

export interface StorageReport {
  disks: PhysicalDisk[];
  volumes: Volume[];
}

function run(command: string, args: string[], timeout = 15_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(String(stdout));
    });
  });
}

interface LsblkNode {
  name: string;
  type: string;
  size?: number | string | null;
  model?: string | null;
  rota?: boolean | string | null;
  fstype?: string | null;
  fssize?: number | string | null;
  fsused?: number | string | null;
  label?: string | null;
  mountpoints?: (string | null)[];
  mountpoint?: string | null;
  children?: LsblkNode[];
}

const num = (v: unknown) => (v === null || v === undefined || v === "" ? null : Number(v));

/** `lsblk -J -b -o NAME,TYPE,SIZE,MODEL,ROTA,FSTYPE,FSSIZE,FSUSED,LABEL,MOUNTPOINTS` */
export function parseLsblkStorage(json: string): StorageReport {
  let roots: LsblkNode[] = [];
  try {
    roots = (JSON.parse(json) as { blockdevices?: LsblkNode[] }).blockdevices ?? [];
  } catch {
    return { disks: [], volumes: [] };
  }
  const disks: PhysicalDisk[] = [];
  const volumes: Volume[] = [];
  const walk = (node: LsblkNode) => {
    if (node.type === "disk" && !/^(loop|ram|zram)/.test(node.name)) {
      const rota = node.rota === true || node.rota === "1";
      disks.push({
        name: node.name,
        model: node.model?.trim() || null,
        kind: node.rota === undefined || node.rota === null ? "unknown" : rota ? "hdd" : "ssd",
        sizeBytes: num(node.size),
        health: "unknown",
        healthDetail: null,
      });
    }
    const mounts = [...(node.mountpoints ?? []), node.mountpoint ?? null].filter((m): m is string => Boolean(m) && m !== "[SWAP]");
    const size = num(node.fssize);
    if (mounts.length && size) {
      volumes.push({ mount: mounts[0]!, device: `/dev/${node.name}`, fileSystem: node.fstype ?? null, sizeBytes: size, usedBytes: num(node.fsused) ?? 0, label: node.label ?? null });
    }
    for (const child of node.children ?? []) walk(child);
  };
  roots.forEach(walk);
  return { disks, volumes };
}

/** `smartctl -H -j /dev/x` */
export function parseSmartctl(json: string): Pick<PhysicalDisk, "health" | "healthDetail"> {
  try {
    const data = JSON.parse(json) as { smart_status?: { passed?: boolean }; temperature?: { current?: number }; power_on_time?: { hours?: number } };
    if (data.smart_status?.passed === undefined) return { health: "unknown", healthDetail: null };
    const extras = [data.temperature?.current ? `${data.temperature.current} °C` : null, data.power_on_time?.hours ? `${data.power_on_time.hours} h powered on` : null].filter(Boolean).join(" · ");
    return data.smart_status.passed
      ? { health: "ok", healthDetail: `S.M.A.R.T. passed${extras ? ` · ${extras}` : ""}` }
      : { health: "failing", healthDetail: "S.M.A.R.T. reports the disk is failing. Back up now." };
  } catch {
    return { health: "unknown", healthDetail: null };
  }
}

/** Get-PhysicalDisk and Get-Volume rows (Windows). */
export function parseWindowsStorage(json: string): StorageReport {
  try {
    const data = JSON.parse(json) as { d?: unknown; v?: unknown };
    const list = <T>(x: unknown) => (Array.isArray(x) ? x : x ? [x] : []) as T[];
    const disks = list<{ FriendlyName?: string; MediaType?: string; Size?: number; HealthStatus?: string; OperationalStatus?: string }>(data.d).map((d, i) => ({
      name: `Disk ${i}`,
      model: d.FriendlyName ?? null,
      kind: (d.MediaType === "SSD" ? "ssd" : d.MediaType === "HDD" ? "hdd" : "unknown") as PhysicalDisk["kind"],
      sizeBytes: d.Size ?? null,
      health: (d.HealthStatus === "Healthy" ? "ok" : d.HealthStatus === "Warning" ? "warning" : d.HealthStatus === "Unhealthy" ? "failing" : "unknown") as PhysicalDisk["health"],
      healthDetail: d.HealthStatus ? `${d.HealthStatus}${d.OperationalStatus ? ` · ${d.OperationalStatus}` : ""}` : null,
    }));
    const volumes = list<{ DriveLetter?: string; FileSystem?: string; FileSystemLabel?: string; Size?: number; SizeRemaining?: number }>(data.v)
      .filter((v) => v.Size)
      .map((v) => ({
        mount: v.DriveLetter ? `${v.DriveLetter}:\\` : "(no letter)",
        device: null,
        fileSystem: v.FileSystem || null,
        sizeBytes: v.Size!,
        usedBytes: v.Size! - (v.SizeRemaining ?? 0),
        label: v.FileSystemLabel || null,
      }));
    return { disks, volumes };
  } catch {
    return { disks: [], volumes: [] };
  }
}

/** `df -kP` (macOS/Linux fallback): real volumes only. */
export function parseDf(stdout: string): Volume[] {
  return stdout
    .split("\n")
    .slice(1)
    .map((line) => line.trim().split(/\s+/))
    .filter((f) => f.length >= 6 && f[0]!.startsWith("/dev/"))
    .map((f) => ({ mount: f.slice(5).join(" "), device: f[0]!, fileSystem: null, sizeBytes: Number(f[1]) * 1024, usedBytes: Number(f[2]) * 1024, label: null }));
}

/** `diskutil info <disk>` text. */
export function parseDiskutil(stdout: string, name: string): PhysicalDisk {
  const field = (key: string) => new RegExp(`^\\s*${key}:\\s+(.+)$`, "m").exec(stdout)?.[1]?.trim() ?? null;
  const smart = field("SMART Status");
  const size = /\((\d+) Bytes\)/.exec(field("Disk Size") ?? "")?.[1];
  return {
    name,
    model: field("Device / Media Name"),
    kind: field("Solid State") === "Yes" ? "ssd" : field("Solid State") === "No" ? "hdd" : "unknown",
    sizeBytes: size ? Number(size) : null,
    health: smart === "Verified" ? "ok" : smart === "Failing" ? "failing" : "unknown",
    healthDetail: smart ? `S.M.A.R.T. ${smart}` : null,
  };
}

export async function storage(platform = process.platform): Promise<StorageReport | null> {
  try {
    if (platform === "linux") {
      const report = parseLsblkStorage(await run("lsblk", ["-J", "-b", "-o", "NAME,TYPE,SIZE,MODEL,ROTA,FSTYPE,FSSIZE,FSUSED,LABEL,MOUNTPOINTS"]));
      for (const disk of report.disks) {
        const health = await run("smartctl", ["-H", "-A", "-j", `/dev/${disk.name}`], 10_000).then(parseSmartctl).catch(() => null);
        if (health) Object.assign(disk, health);
        if (disk.health === "unknown") disk.healthDetail = "Install smartmontools and run Qalaa with permission to read disk health.";
      }
      return report;
    }
    if (platform === "win32") {
      return parseWindowsStorage(
        await run(
          "powershell.exe",
          ["-NoProfile", "-NonInteractive", "-Command", "@{ d = @(Get-PhysicalDisk | Select-Object FriendlyName,@{n='MediaType';e={\"$($_.MediaType)\"}},Size,@{n='HealthStatus';e={\"$($_.HealthStatus)\"}},@{n='OperationalStatus';e={\"$($_.OperationalStatus)\"}}); v = @(Get-Volume | Select-Object DriveLetter,FileSystem,FileSystemLabel,Size,SizeRemaining) } | ConvertTo-Json -Depth 4 -Compress"],
          30_000,
        ),
      );
    }
    if (platform === "darwin") {
      const volumes = parseDf(await run("df", ["-kP"]));
      const list = await run("diskutil", ["list", "-plist", "physical"]).catch(() => "");
      const names = [...new Set([...list.matchAll(/<string>(disk\d+)<\/string>/g)].map((m) => m[1]!))];
      const disks = await Promise.all(names.map(async (name) => parseDiskutil(await run("diskutil", ["info", name]), name)));
      return { disks, volumes };
    }
    return null;
  } catch {
    return null;
  }
}
