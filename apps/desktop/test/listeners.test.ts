import { describe, expect, it } from "vitest";

import { EMPTY_BASELINE, describeBlock, diffListeners, listenerKey, netshPortArgs, nftRuleset, pfAnchorRules, setBlocked, trust, validPort } from "../src/engine/listeners";
import type { ListeningPort } from "../src/engine/security";

const port = (p: number, process: string | null, exposed = true): ListeningPort => ({ port: p, address: exposed ? "0.0.0.0" : "127.0.0.1", process, pid: 100 + p, exposed, risk: null });

describe("new listening-port alerts", () => {
  it("seeds silently, then reports new listeners reachable from the network, once", () => {
    const first = diffListeners(EMPTY_BASELINE, [port(22, "sshd"), port(631, "cupsd", false)]);
    expect(first.fresh).toEqual([]);
    expect(first.baseline.seeded).toBe(true);

    const second = diffListeners(first.baseline, [port(22, "sshd"), port(4444, "nc"), port(4444, "nc"), port(5000, "devserver", false)]);
    expect(second.fresh.map((l) => l.key)).toEqual(["nc|4444|net"]);
    // A loopback-only service is noted but never alerted on.
    expect(second.baseline.known).toContain("devserver|5000|local");
    // Reported until trusted.
    expect(diffListeners(second.baseline, [port(4444, "nc")]).fresh).toHaveLength(1);
    const trusted = trust(second.baseline, "nc|4444|net");
    expect(diffListeners(trusted, [port(4444, "nc")]).fresh).toEqual([]);
  });

  it("the same port from a different program is new", () => {
    const base = diffListeners(EMPTY_BASELINE, [port(8080, "java")]).baseline;
    expect(diffListeners(base, [port(8080, "python3")]).fresh.map((l) => l.process)).toEqual(["python3"]);
    expect(listenerKey(port(8080, null))).toBe("unknown|8080|net");
  });

  it("blocked ports are not reported again", () => {
    const base = setBlocked(diffListeners(EMPTY_BASELINE, []).baseline, 4444, true);
    expect(diffListeners(base, [port(4444, "nc")]).fresh).toEqual([]);
    expect(setBlocked(setBlocked(base, 80, true), 4444, false).blockedPorts).toEqual([80]);
    expect(validPort(443) && !validPort(0) && !validPort(70000) && !validPort("22")).toBe(true);
  });
});

describe("block rules", () => {
  it("nftables: the whole table, rebuilt from the list; empty removes it", () => {
    expect(nftRuleset([4444, 8080])).toBe(
      [
        "table inet qalaa_ports",
        "delete table inet qalaa_ports",
        "table inet qalaa_ports {",
        "  set blocked { type inet_service; elements = { 4444, 8080 } }",
        "  chain input {",
        "    type filter hook input priority filter; policy accept;",
        '    iifname "lo" accept',
        "    tcp dport @blocked drop",
        "    udp dport @blocked drop",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    expect(nftRuleset([])).toBe("table inet qalaa_ports\ndelete table inet qalaa_ports\n");
  });

  it("Windows: named inbound rules for TCP and UDP, removed by name", () => {
    expect(netshPortArgs(4444, true)).toEqual([
      ["advfirewall", "firewall", "add", "rule", "name=Qalaa block port 4444", "dir=in", "action=block", "protocol=TCP", "localport=4444", "enable=yes"],
      ["advfirewall", "firewall", "add", "rule", "name=Qalaa block port 4444", "dir=in", "action=block", "protocol=UDP", "localport=4444", "enable=yes"],
    ]);
    expect(netshPortArgs(4444, false)).toEqual([["advfirewall", "firewall", "delete", "rule", "name=Qalaa block port 4444"]]);
  });

  it("macOS: a pf anchor rule that skips loopback", () => {
    expect(pfAnchorRules([22, 4444])).toBe("block drop in quick on ! lo0 proto { tcp udp } from any to any port { 22 4444 }\n");
    expect(pfAnchorRules([])).toBe("");
    expect(describeBlock("linux", 4444, true)).toMatch(/Block incoming connections from other machines to port 4444, using nftables/);
  });
});

describe("elevated commands", () => {
  it("Linux runs the rebuilt ruleset through pkexec and nft", async () => {
    const { blockCommand } = await import("../src/engine/listeners");
    const cmd = blockCommand("linux", [4444], 4444, true);
    expect(cmd.command).toBe("pkexec");
    expect(cmd.args[0]).toBe("sh");
    expect(cmd.args[2]).toBe(`nft -f - <<'QALAA'\n${nftRuleset([4444])}QALAA`);
  });

  it("Windows asks UAC once for the changed port", async () => {
    const { blockCommand } = await import("../src/engine/listeners");
    const cmd = blockCommand("win32", [80, 4444], 4444, true);
    expect(cmd.command).toBe("powershell.exe");
    expect(cmd.args.at(-1)).toBe(
      "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','netsh advfirewall firewall add rule \"name=Qalaa block port 4444\" dir=in action=block protocol=TCP localport=4444 enable=yes && netsh advfirewall firewall add rule \"name=Qalaa block port 4444\" dir=in action=block protocol=UDP localport=4444 enable=yes' -Verb RunAs -Wait -WindowStyle Hidden",
    );
  });

  it("macOS loads or flushes the pf anchor with an administrator prompt", async () => {
    const { blockCommand } = await import("../src/engine/listeners");
    expect(blockCommand("darwin", [4444], 4444, true).args[1]).toBe(
      "do shell script \"echo 'block drop in quick on ! lo0 proto { tcp udp } from any to any port { 4444 }' | /sbin/pfctl -a com.apple/250.QalaaPorts -f - && /sbin/pfctl -E\" with administrator privileges",
    );
    expect(blockCommand("darwin", [], 4444, false).args[1]).toBe('do shell script "/sbin/pfctl -a com.apple/250.QalaaPorts -F rules" with administrator privileges');
  });
});
