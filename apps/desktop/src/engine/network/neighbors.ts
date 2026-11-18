/**
 * Reading the system's neighbour (ARP) table. After a host sweep fills it, this
 * tells us which addresses answered and their hardware addresses. Pure parsers,
 * one per platform, so they can be tested against saved command output.
 */
import { readFile } from "node:fs/promises";

import { classifyIp } from "../nettools";

export interface Neighbor {
  ip: string;
  mac: string | null;
}

const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function normMac(value: string | undefined): string | null {
  if (!value) return null;
  const mac = value.toLowerCase().replace(/-/g, ":");
  if (!MAC.test(mac)) return null;
  // Incomplete entries show as all-zero; treat them as unknown.
  return mac === "00:00:00:00:00:00" ? null : mac;
}

/** Linux /proc/net/arp. Columns: IP, HW type, Flags, HW address, Mask, Device. */
export function parseProcArp(text: string): Neighbor[] {
  const out: Neighbor[] = [];
  for (const line of text.split(/\r?\n/).slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4 || classifyIp(cols[0]!) === null) continue;
    // Flags 0x0 means the entry is incomplete (no reply).
    if (cols[2] === "0x0") continue;
    out.push({ ip: cols[0]!, mac: normMac(cols[3]) });
  }
  return out;
}

/** `ip -j neigh` JSON output (iproute2). */
export function parseIpNeigh(json: string): Neighbor[] {
  try {
    const rows = JSON.parse(json) as { dst?: string; lladdr?: string; state?: string[] }[];
    return rows
      .filter((r) => r.dst && classifyIp(r.dst) !== null && !(r.state ?? []).includes("FAILED"))
      .map((r) => ({ ip: r.dst!, mac: normMac(r.lladdr) }));
  } catch {
    return [];
  }
}

/** Windows `arp -a` or macOS `arp -an`. Lines like "? (192.168.1.1) at aa-bb-... ". */
export function parseArpDashA(text: string): Neighbor[] {
  const out: Neighbor[] = [];
  for (const line of text.split(/\r?\n/)) {
    // Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
    const win = /^\s*([\d.]+)\s+([0-9a-f-]{17})\s+\w+/i.exec(line);
    if (win && classifyIp(win[1]!)) {
      out.push({ ip: win[1]!, mac: normMac(win[2]) });
      continue;
    }
    // macOS/BSD: "host (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    const bsd = /\(([\d.]+)\)\s+at\s+([0-9a-f:]+)/i.exec(line);
    if (bsd && classifyIp(bsd[1]!)) out.push({ ip: bsd[1]!, mac: normMac(bsd[2]) });
  }
  return out;
}

export async function neighbors(platform = process.platform, run = execCmd): Promise<Neighbor[]> {
  try {
    if (platform === "linux") {
      const viaIp = parseIpNeigh(await run("ip", ["-j", "neigh"]).catch(() => ""));
      if (viaIp.length) return viaIp;
      return parseProcArp(await readFile("/proc/net/arp", "utf8"));
    }
    if (platform === "win32") return parseArpDashA(await run("arp", ["-a"]));
    return parseArpDashA(await run("arp", ["-an"]));
  } catch {
    return [];
  }
}

type Runner = (cmd: string, args: string[]) => Promise<string>;
const execCmd: Runner = (cmd, args) =>
  new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile(cmd, args, { timeout: 15_000, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (error, stdout) => {
        if (error && !stdout) reject(error);
        else resolve(String(stdout));
      });
    });
  });
