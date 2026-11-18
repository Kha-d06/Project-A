/**
 * Network tools: DNS lookup, classification of an IP address (private, public,
 * loopback...), and per-interface traffic and error counters.
 */
import { execFile } from "node:child_process";
import { promises as dns } from "node:dns";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import os from "node:os";

export type IpClass = "loopback" | "private" | "link-local" | "carrier-nat" | "multicast" | "reserved" | "documentation" | "public" | "unspecified";

function v4(ip: string): number[] {
  return ip.split(".").map(Number);
}

/** What kind of address this is, so a connection can be read at a glance. */
export function classifyIp(input: string): IpClass | null {
  const ip = input.replace(/^\[|\]$/g, "").replace(/^::ffff:(?=\d+\.)/i, "");
  const kind = isIP(ip);
  if (kind === 4) {
    const [a, b, c] = v4(ip) as [number, number, number, number];
    if (a === 0) return "unspecified";
    if (a === 127) return "loopback";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
    if (a === 169 && b === 254) return "link-local";
    if (a === 100 && b >= 64 && b <= 127) return "carrier-nat";
    if (a >= 224 && a <= 239) return "multicast";
    if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return "documentation";
    if (a >= 240) return "reserved";
    return "public";
  }
  if (kind === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::") return "unspecified";
    if (lower === "::1") return "loopback";
    if (/^fe[89ab]/.test(lower)) return "link-local";
    if (/^f[cd]/.test(lower)) return "private";
    if (/^ff/.test(lower)) return "multicast";
    if (/^2001:db8:/.test(lower)) return "documentation";
    return "public";
  }
  return null;
}

export interface DnsAnswer {
  query: string;
  addresses: { address: string; family: 4 | 6; class: IpClass | null }[];
  reverse: string[];
  mx: { exchange: string; priority: number }[];
  txt: string[];
  error: string | null;
}

const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i;

/** Look up a host name (A, AAAA, MX, TXT) or an IP address (reverse lookup). */
export async function lookup(query: string, resolver: Pick<typeof dns, "resolve4" | "resolve6" | "resolveMx" | "resolveTxt" | "reverse"> = dns): Promise<DnsAnswer> {
  const q = query.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  const answer: DnsAnswer = { query: q, addresses: [], reverse: [], mx: [], txt: [], error: null };
  if (isIP(q)) {
    answer.addresses.push({ address: q, family: isIP(q) as 4 | 6, class: classifyIp(q) });
    answer.reverse = await resolver.reverse(q).catch(() => []);
    return answer;
  }
  if (!HOST.test(q)) {
    answer.error = "That is not a host name or an IP address.";
    return answer;
  }
  const [a, aaaa, mx, txt] = await Promise.all([
    resolver.resolve4(q).catch(() => [] as string[]),
    resolver.resolve6(q).catch(() => [] as string[]),
    resolver.resolveMx(q).catch(() => [] as { exchange: string; priority: number }[]),
    resolver.resolveTxt(q).catch(() => [] as string[][]),
  ]);
  answer.addresses = [...a.map((x) => ({ address: x, family: 4 as const, class: classifyIp(x) })), ...aaaa.map((x) => ({ address: x, family: 6 as const, class: classifyIp(x) }))];
  answer.mx = mx.sort((x, y) => x.priority - y.priority);
  answer.txt = txt.map((parts) => parts.join("")).slice(0, 20);
  if (!answer.addresses.length && !answer.mx.length && !answer.txt.length) answer.error = "No records found for that name.";
  return answer;
}

export interface InterfaceStats {
  name: string;
  addresses: string[];
  mac: string | null;
  rxBytes: number | null;
  txBytes: number | null;
  rxPackets: number | null;
  txPackets: number | null;
  errors: number | null;
  drops: number | null;
}

/** /proc/net/dev with packets, errors and drops per interface. */
export function parseNetDevDetail(text: string): Map<string, Omit<InterfaceStats, "name" | "addresses" | "mac">> {
  const map = new Map<string, Omit<InterfaceStats, "name" | "addresses" | "mac">>();
  for (const line of text.split("\n").slice(2)) {
    const [name, rest] = line.split(":");
    if (!rest) continue;
    const f = rest.trim().split(/\s+/).map(Number);
    map.set(name!.trim(), { rxBytes: f[0]!, rxPackets: f[1]!, errors: f[2]! + f[10]!, drops: f[3]! + f[11]!, txBytes: f[8]!, txPackets: f[9]! });
  }
  return map;
}

/** Get-NetAdapterStatistics rows (Windows). */
export function parseWindowsAdapterStats(json: string): Map<string, Omit<InterfaceStats, "name" | "addresses" | "mac">> {
  const map = new Map<string, Omit<InterfaceStats, "name" | "addresses" | "mac">>();
  try {
    const data = JSON.parse(json || "[]") as unknown;
    const rows = (Array.isArray(data) ? data : [data]) as Record<string, number | string>[];
    for (const r of rows) {
      if (!r?.Name) continue;
      map.set(String(r.Name), {
        rxBytes: Number(r.ReceivedBytes ?? 0),
        txBytes: Number(r.SentBytes ?? 0),
        rxPackets: Number(r.ReceivedUnicastPackets ?? 0),
        txPackets: Number(r.SentUnicastPackets ?? 0),
        errors: Number(r.ReceivedPacketErrors ?? 0) + Number(r.OutboundPacketErrors ?? 0),
        drops: Number(r.ReceivedDiscardedPackets ?? 0) + Number(r.OutboundDiscardedPackets ?? 0),
      });
    }
  } catch {
    // empty
  }
  return map;
}

export async function interfaces(platform = process.platform): Promise<InterfaceStats[]> {
  let counters = new Map<string, Omit<InterfaceStats, "name" | "addresses" | "mac">>();
  if (platform === "linux") counters = parseNetDevDetail(await readFile("/proc/net/dev", "utf8").catch(() => ""));
  if (platform === "win32") {
    counters = await new Promise((resolve) =>
      execFile(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets,ReceivedPacketErrors,OutboundPacketErrors,ReceivedDiscardedPackets,OutboundDiscardedPackets | ConvertTo-Json -Compress"],
        { timeout: 15_000, windowsHide: true },
        (_error, stdout) => resolve(parseWindowsAdapterStats(String(stdout))),
      ),
    );
  }
  const result: InterfaceStats[] = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    if (!list) continue;
    const mac = list.find((a) => a.mac && a.mac !== "00:00:00:00:00:00")?.mac ?? null;
    const stats = counters.get(name) ?? { rxBytes: null, txBytes: null, rxPackets: null, txPackets: null, errors: null, drops: null };
    result.push({ name, addresses: list.map((a) => `${a.address}/${a.cidr?.split("/")[1] ?? ""}`.replace(/\/$/, "")), mac, ...stats });
  }
  return result.sort((a, b) => Number(a.name === "lo" || a.name.startsWith("Loopback")) - Number(b.name === "lo" || b.name.startsWith("Loopback")) || a.name.localeCompare(b.name));
}
