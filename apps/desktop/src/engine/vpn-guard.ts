/**
 * VPN safety features that sit on top of the WireGuard tunnel:
 *
 *  - Kill switch: a small nftables ruleset that drops all traffic except
 *    through the VPN interface (plus the tunnel's own endpoint and, optionally,
 *    the local network), so nothing leaks if the tunnel drops.
 *  - Split tunnelling: compute the WireGuard AllowedIPs so chosen networks go
 *    straight out (bypass the VPN) while everything else is tunnelled.
 *  - Auto-connect on untrusted Wi-Fi: decide, from the current network and the
 *    user's list of trusted ones, whether the VPN should come up by itself.
 *
 * The decision and address computations here are pure and tested. Enforcing the kill switch
 * needs root, so that goes through pkexec (injectable for tests). Linux-only;
 * elsewhere the capability check reports it unavailable (guardrail 3).
 */
import type { WifiStatus } from "./system";

const KILL_TABLE = "qalaa_vpn";

// --- IPv4 helpers ----------------------------------------------------------------------

function toInt(ip: string): number {
  return ip.split(".").reduce((acc, part) => (acc << 8) + (Number(part) & 255), 0) >>> 0;
}

function toIp(value: number): string {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

interface Range {
  start: number;
  end: number;
}

function cidrToRange(cidr: string): Range | null {
  const [ip, prefixStr] = cidr.split("/");
  if (!ip || ip.includes(":")) return null; // IPv4 only here
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const base = toInt(ip) & (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);
  return { start: base >>> 0, end: (base + 2 ** (32 - prefix) - 1) >>> 0 };
}

/** Express an integer range [start, end] as the minimal set of CIDR blocks. */
function rangeToCidrs(start: number, end: number): string[] {
  const out: string[] = [];
  let cur = start;
  while (cur <= end) {
    const remaining = end - cur + 1;
    // Block size is limited both by the alignment of `cur` (its trailing zero
    // bits) and by how much of the range is left.
    const alignBits = cur === 0 ? 32 : Math.log2((cur & -cur) >>> 0);
    const hostBits = Math.min(alignBits, Math.floor(Math.log2(remaining)));
    out.push(`${toIp(cur)}/${32 - hostBits}`);
    cur += 2 ** hostBits;
  }
  return out;
}

/**
 * The AllowedIPs list that tunnels everything except the excluded networks.
 * This is the standard WireGuard trick for "send all traffic through the VPN
 * but let my local network / these ranges go direct".
 */
export function excludeFromFullTunnel(excluded: string[]): string[] {
  const ranges = excluded.map(cidrToRange).filter((r): r is Range => r !== null).sort((a, b) => a.start - b.start);
  const covered: string[] = [];
  let cursor = 0; // 0.0.0.0
  for (const range of ranges) {
    if (range.start > cursor) covered.push(...rangeToCidrs(cursor, range.start - 1));
    cursor = Math.max(cursor, range.end + 1);
  }
  if (cursor <= 0xffffffff) covered.push(...rangeToCidrs(cursor, 0xffffffff));
  return covered;
}

export type SplitMode = "full" | "exclude" | "only";

/** Compute the AllowedIPs string for a split-tunnel configuration. */
export function allowedIpsFor(mode: SplitMode, cidrs: string[]): string {
  if (mode === "only") {
    const valid = cidrs.filter((c) => cidrToRange(c) !== null);
    return valid.length ? valid.join(", ") : "0.0.0.0/32"; // nothing: tunnel effectively carries no IPv4
  }
  if (mode === "exclude" && cidrs.length) {
    return [...excludeFromFullTunnel(cidrs), "::/0"].join(", ");
  }
  return "0.0.0.0/0, ::/0"; // full tunnel
}

/** Replace the AllowedIPs line in a WireGuard config with a split-tunnel value. */
export function applySplitTunnel(config: string, mode: SplitMode, cidrs: string[]): string {
  const value = allowedIpsFor(mode, cidrs);
  if (/^AllowedIPs\s*=.*$/m.test(config)) return config.replace(/^AllowedIPs\s*=.*$/m, `AllowedIPs = ${value}`);
  return config.replace(/^(\[Peer\]\s*\n)/m, `$1AllowedIPs = ${value}\n`);
}

// --- Kill switch (nftables) ------------------------------------------------------------

const ENDPOINT_HOST = /^[A-Za-z0-9.\-:]+$/;

/**
 * An nftables ruleset that blocks all traffic except: loopback, the VPN
 * interface, DHCP, the tunnel endpoint, and (optionally) the local network.
 * Pure string builder so it can be inspected and tested.
 */
export function killSwitchRules(wgInterface: string, endpointHost: string, allowLan: boolean): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(wgInterface)) throw new Error("Invalid interface name.");
  if (!ENDPOINT_HOST.test(endpointHost)) throw new Error("Invalid endpoint.");
  const lan = allowLan
    ? [
        "        ip daddr 10.0.0.0/8 accept",
        "        ip daddr 172.16.0.0/12 accept",
        "        ip daddr 192.168.0.0/16 accept",
        "        ip daddr 169.254.0.0/16 accept",
      ].join("\n")
    : "";
  return [
    `table inet ${KILL_TABLE} {`,
    "    chain output {",
    "        type filter hook output priority 0; policy drop;",
    "        ct state established,related accept",
    "        oifname \"lo\" accept",
    `        oifname "${wgInterface}" accept`,
    "        udp dport 67 accept", // DHCP
    "        udp sport 68 accept",
    `        ip daddr ${endpointHost.includes(":") ? endpointHost.split(":")[0] : endpointHost} accept`,
    lan,
    "    }",
    "}",
    "",
  ].filter((line) => line !== "").join("\n");
}

/** The root script that installs the kill switch. */
export function killSwitchScript(rules: string): string {
  return ["#!/bin/sh", "set -e", `cat <<'QALAA_NFT' | nft -f -\n${rules}QALAA_NFT`, ""].join("\n");
}

export function removeKillSwitchScript(): string {
  return ["#!/bin/sh", `nft delete table inet ${KILL_TABLE} 2>/dev/null || true`, ""].join("\n");
}

// --- Auto-connect on untrusted Wi-Fi ---------------------------------------------------

export interface AutoConnectPolicy {
  enabled: boolean;
  /** SSIDs the user marked as trusted (home, work…). */
  trusted: string[];
}

/**
 * Should the VPN come up automatically right now? Yes when auto-connect is on
 * and the current network is one we should not trust: any open/weak Wi-Fi, or
 * any network whose SSID the user hasn't trusted. A wired or unknown network is
 * left alone (returns false) to avoid surprising the user.
 */
export function shouldAutoConnect(wifi: WifiStatus, policy: AutoConnectPolicy): boolean {
  if (!policy.enabled) return false;
  if (wifi.risk === "none" || wifi.risk === "unknown") return false; // not on Wi-Fi, or can't tell
  if (wifi.risk === "open" || wifi.risk === "weak") return true; // always protect on weak Wi-Fi
  if (!wifi.ssid) return false;
  return !policy.trusted.includes(wifi.ssid); // a secure but unfamiliar network
}

/** The kill switch needs nftables, so it is Linux-only. */
export function killSwitchCapable(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "linux";
}

export { KILL_TABLE };
