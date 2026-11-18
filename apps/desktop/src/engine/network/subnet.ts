/**
 * Working out which network to scan, and refusing anything that isn't a small
 * home network the computer is directly attached to.
 *
 * The guard is deliberately strict: only RFC 1918 / link-local IPv4 ranges, at
 * most 1024 addresses, and never a public or carrier-grade-NAT address. A scan
 * of someone else's network is never what the person wants, and we won't do it.
 */
import { readFile } from "node:fs/promises";

import { classifyIp } from "../nettools";

const MAX_HOSTS = 1024;

export interface LocalNet {
  interface: string;
  /** The computer's own address on this network. */
  address: string;
  prefix: number;
  /** Network address, e.g. "192.168.1.0". */
  network: string;
  cidr: string;
  /** Every host address to probe (excludes network and broadcast). */
  hosts: string[];
}

function toInt(ip: string): number {
  return ip.split(".").reduce((acc, part) => (acc << 8) + (Number(part) & 255), 0) >>> 0;
}

function toIp(value: number): string {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

/** Netmask like "255.255.255.0" → prefix length 24. Returns null if not contiguous. */
export function prefixFromMask(mask: string): number | null {
  if (classifyIp(mask) === null) return null;
  const bits = toInt(mask).toString(2).padStart(32, "0");
  const m = /^(1*)(0*)$/.exec(bits);
  return m ? m[1]!.length : null;
}

/**
 * Builds the list of hosts for an interface's IPv4 address and prefix, or null
 * when the range must not be scanned (too large, or not a private range).
 */
export function hostsFor(name: string, address: string, prefix: number): LocalNet | null {
  if (classifyIp(address) !== "private" && classifyIp(address) !== "link-local") return null;
  if (prefix < 8 || prefix > 31) return null;
  const size = 2 ** (32 - prefix);
  if (size > MAX_HOSTS + 2) return null;
  const base = toInt(address) & (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);
  const network = toIp(base);
  const hosts: string[] = [];
  // Skip the network address itself and the broadcast address.
  for (let i = 1; i < size - 1; i++) {
    const ip = toIp(base + i);
    if (ip !== address) hosts.push(ip);
  }
  return { interface: name, address, prefix, network, cidr: `${network}/${prefix}`, hosts };
}

/** Parse the default-route gateway from Linux /proc/net/route. */
export function parseProcRoute(text: string): { interface: string; gateway: string } | null {
  for (const line of text.split(/\r?\n/).slice(1)) {
    const cols = line.split(/\t+/);
    if (cols.length < 4) continue;
    const [iface, destination, gateway, flags] = cols;
    // Default route: destination 0.0.0.0 with the gateway flag set.
    if (destination === "00000000" && (Number.parseInt(flags ?? "0", 16) & 2) !== 0) {
      const hex = gateway!.match(/../g);
      if (!hex || hex.length !== 4) continue;
      // Little-endian hex, so read the bytes back to front.
      return { interface: iface!, gateway: hex.reverse().map((b) => Number.parseInt(b, 16)).join(".") };
    }
  }
  return null;
}

/** Windows `route print -4` → default gateway address. */
export function parseWindowsRoute(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    // "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"
    if (parts[0] === "0.0.0.0" && parts[1] === "0.0.0.0" && classifyIp(parts[2] ?? "") === "private") return parts[2]!;
  }
  return null;
}

/** macOS `route -n get default` → "gateway: 192.168.1.1". */
export function parseMacRoute(text: string): string | null {
  const m = /^\s*gateway:\s*([\d.]+)/m.exec(text);
  return m && classifyIp(m[1]!) ? m[1]! : null;
}

export async function defaultGateway(platform = process.platform, run = execCmd): Promise<string | null> {
  try {
    if (platform === "linux") return parseProcRoute(await readFile("/proc/net/route", "utf8"))?.gateway ?? null;
    if (platform === "win32") return parseWindowsRoute(await run("route", ["print", "-4"]));
    if (platform === "darwin") return parseMacRoute(await run("route", ["-n", "get", "default"]));
  } catch {
    return null;
  }
  return null;
}

type Runner = (cmd: string, args: string[]) => Promise<string>;

const execCmd: Runner = (cmd, args) =>
  new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile(cmd, args, { timeout: 15_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (error, stdout) => {
        if (error && !stdout) reject(error);
        else resolve(String(stdout));
      });
    });
  });

export { MAX_HOSTS };
