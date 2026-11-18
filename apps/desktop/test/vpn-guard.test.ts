import { describe, expect, it } from "vitest";

import {
  KILL_TABLE,
  type SplitMode,
  allowedIpsFor,
  applySplitTunnel,
  excludeFromFullTunnel,
  killSwitchCapable,
  killSwitchRules,
  killSwitchScript,
  removeKillSwitchScript,
  shouldAutoConnect,
} from "../src/engine/vpn-guard";
import type { WifiStatus } from "../src/engine/system";

/** Turn a CIDR list back into the set of covered addresses for exhaustive checks. */
function covers(cidrs: string[]): (ip: string) => boolean {
  const ranges = cidrs.map((c) => {
    const [ip, p] = c.split("/");
    const prefix = Number(p);
    const base = ip!.split(".").reduce((a, x) => (a << 8) + Number(x), 0) >>> 0;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { net: (base & mask) >>> 0, mask };
  });
  return (ip: string) => {
    const value = ip.split(".").reduce((a, x) => (a << 8) + Number(x), 0) >>> 0;
    return ranges.some((r) => (value & r.mask) >>> 0 === r.net);
  };
}

describe("split-tunnel AllowedIPs", () => {
  it("full tunnel sends everything through the VPN", () => {
    expect(allowedIpsFor("full", [])).toBe("0.0.0.0/0, ::/0");
  });

  it("only-mode tunnels just the listed networks", () => {
    expect(allowedIpsFor("only", ["10.8.0.0/24", "192.168.5.0/24"])).toBe("10.8.0.0/24, 192.168.5.0/24");
    expect(allowedIpsFor("only", [])).toBe("0.0.0.0/32");
  });

  it("exclude-mode covers everything except the excluded range", () => {
    const value = allowedIpsFor("exclude", ["192.168.1.0/24"]);
    const v4 = value.split(", ").filter((c) => !c.includes(":"));
    const covered = covers(v4);
    expect(covered("8.8.8.8")).toBe(true); // internet → tunnelled
    expect(covered("192.168.1.50")).toBe(false); // LAN → direct
    expect(covered("192.168.2.1")).toBe(true); // neighbouring subnet still tunnelled
    expect(value.endsWith("::/0")).toBe(true); // IPv6 still fully tunnelled
  });

  it("the exclude complement is exact at the range edges", () => {
    const cidrs = excludeFromFullTunnel(["10.0.0.0/8"]);
    const covered = covers(cidrs);
    expect(covered("9.255.255.255")).toBe(true);
    expect(covered("10.0.0.0")).toBe(false);
    expect(covered("10.255.255.255")).toBe(false);
    expect(covered("11.0.0.0")).toBe(true);
    expect(covered("0.0.0.0")).toBe(true);
    expect(covered("255.255.255.255")).toBe(true);
  });

  it("rewrites the AllowedIPs line in a config", () => {
    const config = "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = h:51820\n";
    const out = applySplitTunnel(config, "only", ["10.8.0.0/24"]);
    expect(out).toContain("AllowedIPs = 10.8.0.0/24");
    expect(out).not.toContain("0.0.0.0/0");
    // Adds the line if a peer has none.
    const bare = applySplitTunnel("[Peer]\nPublicKey = y\n", "full", []);
    expect(bare).toContain("AllowedIPs = 0.0.0.0/0, ::/0");
  });
});

describe("kill switch ruleset", () => {
  it("drops by default and allows the VPN interface and endpoint", () => {
    const rules = killSwitchRules("qalaa-vpn", "vpn.example.org:51820", false);
    expect(rules).toContain(`table inet ${KILL_TABLE}`);
    expect(rules).toContain("policy drop");
    expect(rules).toContain('oifname "qalaa-vpn" accept');
    expect(rules).toContain("ip daddr vpn.example.org accept");
    expect(rules).not.toContain("192.168.0.0/16"); // LAN not allowed when allowLan is false
  });

  it("optionally allows the local network", () => {
    expect(killSwitchRules("wg0", "1.2.3.4", true)).toContain("ip daddr 192.168.0.0/16 accept");
  });

  it("rejects unsafe interface and endpoint values", () => {
    expect(() => killSwitchRules("wg0; rm -rf /", "1.2.3.4", false)).toThrow();
    expect(() => killSwitchRules("wg0", "evil$(whoami)", false)).toThrow();
  });

  it("wraps the rules in install and remove scripts", () => {
    expect(killSwitchScript(killSwitchRules("wg0", "1.2.3.4", false))).toContain("nft -f -");
    expect(removeKillSwitchScript()).toContain(`nft delete table inet ${KILL_TABLE}`);
  });
});

describe("auto-connect decision", () => {
  const wifi = (risk: WifiStatus["risk"], ssid: string | null): WifiStatus => ({ ssid, security: null, risk });

  it("protects on open and weak Wi-Fi", () => {
    const policy = { enabled: true, trusted: ["Home"] };
    expect(shouldAutoConnect(wifi("open", "Cafe"), policy)).toBe(true);
    expect(shouldAutoConnect(wifi("weak", "Old"), policy)).toBe(true);
  });

  it("connects on a secure but unfamiliar network, not a trusted one", () => {
    const policy = { enabled: true, trusted: ["Home"] };
    expect(shouldAutoConnect(wifi("ok", "Hotel"), policy)).toBe(true);
    expect(shouldAutoConnect(wifi("ok", "Home"), policy)).toBe(false);
  });

  it("leaves wired or unknown connections alone, and does nothing when disabled", () => {
    expect(shouldAutoConnect(wifi("none", null), { enabled: true, trusted: [] })).toBe(false);
    expect(shouldAutoConnect(wifi("unknown", null), { enabled: true, trusted: [] })).toBe(false);
    expect(shouldAutoConnect(wifi("open", "Cafe"), { enabled: false, trusted: [] })).toBe(false);
  });
});

describe("capability", () => {
  it("is Linux-only", () => {
    expect(killSwitchCapable("linux")).toBe(true);
    expect(killSwitchCapable("darwin")).toBe(false);
  });
});
