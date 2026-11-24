import { createSocket } from "node:dgram";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { buildHome } from "../src/core/home";
import { SafeDnsService } from "../src/core/safe-dns-service";
import { describeSwitch, parseNetworkServices, parseResolvConf, parseScutilDns, parseWindowsServers, proxyPort, resolvedDropin, switchCommand } from "../src/engine/dns-system";
import { TYPE, buildQuery, parseQuery, replyWithCode, responseCode } from "../src/engine/dns-wire";
import { CAPTIVE_CHECKS, SafeDnsProxy, isListed } from "../src/engine/safe-dns";
import type { ElevatedCommand } from "../src/engine/listeners";

/** A fake upstream answer: the query with QR set and NOERROR. */
const answer = (query: Uint8Array) => {
  const a = new Uint8Array(query);
  a[2] = 0x81;
  a[3] = 0x80;
  return a;
};

function ask(port: number, name: string, id = 0x1234): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const socket = createSocket("udp4");
    socket.once("message", (m) => {
      socket.close();
      resolve(new Uint8Array(m));
    });
    socket.once("error", reject);
    socket.send(buildQuery(id, name, TYPE.A), port, "127.0.0.1");
  });
}

describe("DNS wire format", () => {
  it("reads a query and builds refusals", () => {
    const query = buildQuery(0xbeef, "Evil.Example.COM", TYPE.AAAA);
    const q = parseQuery(query);
    expect(q).toMatchObject({ id: 0xbeef, name: "evil.example.com", type: TYPE.AAAA });
    const refused = replyWithCode(query, q!, 3);
    expect(responseCode(refused)).toBe(3);
    expect(refused[0]).toBe(0xbe);
    expect(refused[2]! & 0x80).toBe(0x80); // a response
    expect(parseQuery(refused)).toBeNull(); // responses aren't queries
    expect(parseQuery(new Uint8Array([1, 2, 3]))).toBeNull();
    const truncated = query.subarray(0, 20);
    expect(parseQuery(truncated)).toBeNull();
  });

  it("matches listed domains and their subdomains only", () => {
    const list = new Set(["evil.example"]);
    expect(isListed("evil.example", list)).toBe(true);
    expect(isListed("a.b.evil.example.", list)).toBe(true);
    expect(isListed("notevil.example", list)).toBe(false);
  });
});

describe("Safe DNS proxy", () => {
  it("blocks listed names, sends the rest over DoH, and keeps captive portals on the network's DNS", async () => {
    const viaDoh: string[] = [];
    const viaNetwork: string[] = [];
    const blocked: string[] = [];
    const proxy = new SafeDnsProxy({
      blocklist: () => new Set(["evil.example"]),
      upstream: "https://doh.test/dns-query",
      fallback: () => ["192.0.2.53"],
      doh: async (url, query) => {
        expect(url).toBe("https://doh.test/dns-query");
        expect(query[0]).toBe(0); // DoH queries use id 0 for caching
        viaDoh.push(parseQuery(query)!.name);
        return answer(query);
      },
      udp: async (server, query) => {
        viaNetwork.push(`${server} ${parseQuery(query)!.name}`);
        return answer(query);
      },
      onBlocked: (name) => blocked.push(name),
    });
    const port = await proxy.start(0);
    try {
      const refused = await ask(port, "login.evil.example");
      expect(responseCode(refused)).toBe(3);
      expect(blocked).toEqual(["login.evil.example"]);

      const fine = await ask(port, "example.org", 0x4242);
      expect(responseCode(fine)).toBe(0);
      expect((fine[0]! << 8) | fine[1]!).toBe(0x4242); // id restored
      expect(viaDoh).toEqual(["example.org"]);

      await ask(port, CAPTIVE_CHECKS[0]!);
      expect(viaNetwork).toEqual(["192.0.2.53 captive.apple.com"]);
      expect(proxy.stats).toMatchObject({ queries: 3, blocked: 1, viaDoh: 1, viaFallback: 1, failed: 0 });
    } finally {
      await proxy.stop();
    }
  });

  it("falls back to the network's DNS when DoH can't be reached, and says SERVFAIL when nothing answers", async () => {
    let networkUp = true;
    const proxy = new SafeDnsProxy({
      blocklist: () => new Set(),
      upstream: "https://doh.test/dns-query",
      fallback: () => ["192.0.2.1", "192.0.2.2"],
      doh: async () => {
        throw new Error("blocked by a login page");
      },
      udp: async (server, query) => {
        if (!networkUp || server === "192.0.2.1") throw new Error("down");
        return answer(query);
      },
    });
    expect(responseCode((await proxy.resolve(buildQuery(1, "hotel-login.example", TYPE.A)))!)).toBe(0);
    networkUp = false;
    expect(responseCode((await proxy.resolve(buildQuery(2, "anything.example", TYPE.A)))!)).toBe(2);
    expect(proxy.stats).toMatchObject({ viaFallback: 1, failed: 1 });
    expect(await proxy.resolve(new Uint8Array([0, 1]))).toBeNull();
  });
});

describe("system switch", () => {
  it("parses each system's DNS servers, skipping loopback", () => {
    expect(parseResolvConf("# generated\nnameserver 192.168.1.1\nnameserver 127.0.0.53\nnameserver 2001:db8::1\n")).toEqual(["192.168.1.1", "2001:db8::1"]);
    expect(parseWindowsServers("192.168.1.1\r\n127.0.0.1\r\nfe80::1\r\n192.168.1.1\r\n")).toEqual(["192.168.1.1", "fe80::1"]);
    expect(parseScutilDns("resolver #1\n  nameserver[0] : 10.0.0.1\n  nameserver[1] : 127.0.0.1\nresolver #2\n  nameserver[0] : 10.0.0.1\n")).toEqual(["10.0.0.1"]);
    expect(parseNetworkServices("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100/1000 LAN\nThunderbolt Bridge\n")).toEqual(["Wi-Fi", "Thunderbolt Bridge"]);
  });

  it("Linux: a resolved drop-in with the network's servers second; removing it undoes", () => {
    expect(proxyPort("linux")).toBe(5354);
    expect(resolvedDropin(5354, ["192.168.1.1"])).toBe("# Written by Qalaa Safe DNS. Delete this file to undo.\n[Resolve]\nDNS=127.0.0.1:5354 192.168.1.1\nDomains=~.\n");
    const on = switchCommand("linux", true, ["192.168.1.1", "bad; rm -rf /"]);
    expect(on.command).toBe("pkexec");
    expect(on.args[2]).toBe(
      "mkdir -p /etc/systemd/resolved.conf.d && cat > /etc/systemd/resolved.conf.d/qalaa-safe-dns.conf <<'QALAA'\n# Written by Qalaa Safe DNS. Delete this file to undo.\n[Resolve]\nDNS=127.0.0.1:5354 192.168.1.1\nDomains=~.\nQALAA\nsystemctl restart systemd-resolved",
    );
    expect(switchCommand("linux", false).args[2]).toBe("rm -f /etc/systemd/resolved.conf.d/qalaa-safe-dns.conf && systemctl restart systemd-resolved");
  });

  it("Windows and macOS: loopback first, network second; off resets to automatic", () => {
    expect(switchCommand("win32", true, ["192.168.1.1"]).args.at(-1)).toBe(
      "Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-Command','Get-NetAdapter -Physical | Where-Object Status -eq ''Up'' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ''127.0.0.1'',''192.168.1.1'' }; Clear-DnsClientCache' -Verb RunAs -Wait -WindowStyle Hidden",
    );
    expect(switchCommand("win32", false).args.at(-1)).toContain("-ResetServerAddresses");
    expect(switchCommand("darwin", true, ["10.0.0.1"], ["Wi-Fi", "Ethernet"]).args[1]).toBe(
      "do shell script \"/usr/sbin/networksetup -setdnsservers 'Wi-Fi' 127.0.0.1 10.0.0.1 && /usr/sbin/networksetup -setdnsservers 'Ethernet' 127.0.0.1 10.0.0.1 && /usr/bin/dscacheutil -flushcache\" with administrator privileges",
    );
    expect(switchCommand("darwin", false, [], ["Wi-Fi"]).args[1]).toContain("-setdnsservers 'Wi-Fi' Empty");
    expect(describeSwitch("win32", true, "Quad9")).toMatch(/encrypted to Quad9.*Login pages on public Wi-Fi keep working/);
  });
});

describe("Safe DNS service", () => {
  it("turns on and off through the consent prompt, as a Home toggle", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-dns-"));
    const ran: ElevatedCommand[] = [];
    const service = new SafeDnsService(join(dir, "dns.json"), () => "http://127.0.0.1:9", {
      platform: "linux",
      port: 0,
      available: async () => true,
      currentServers: async () => ["192.168.1.1"],
      fetchDomains: async () => ["evil.example", "BAD host"],
      exec: async (c) => void ran.push(c),
    });
    await service.load();
    const base = { now: new Date(), platform: "linux" as const, watchEnabled: true, onAccessScan: false, ransomwareWatch: true, networkWatch: true, cloudLookup: false, signatures: { count: 1, updatedAt: new Date().toISOString(), error: null }, lastScanAt: new Date().toISOString(), lastNetworkScanAt: new Date().toISOString(), lastBackupAt: new Date().toISOString(), lastBackupError: null, backupConfigured: true, quarantineCount: 0, recentThreats: 0, ransomwareAlertAt: null, updateAvailable: null, silentUntil: null };
    const host = { version: "t", homeInput: async () => ({ ...base, safeDns: { on: service.isOn(), available: service.isSupported() } }), updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, safeDns: service };
    const handlers = createHandlers(host, () => {});

    const home = (await handlers["settings.set"]?.({ safeDns: true })) as ReturnType<typeof buildHome>;
    expect(home.toggles.find((t) => t.key === "safeDns")).toEqual({ key: "safeDns", on: true, available: true });
    expect(ran[0]?.args[2]).toContain("DNS=127.0.0.1:5354 192.168.1.1");
    const status = (await handlers["safedns.get"]?.(undefined)) as ReturnType<SafeDnsService["status"]>;
    expect(status).toMatchObject({ enabled: true, running: true, fallback: ["192.168.1.1"] });
    await service.refreshDomains(true);
    expect(service.status().domains).toBe(1);

    await handlers["settings.set"]?.({ safeDns: false });
    expect(ran[1]?.args[2]).toContain("rm -f");
    expect(service.status()).toMatchObject({ enabled: false, running: false });
    await service.stop();
  });

  it("a declined prompt leaves everything off", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-dns-"));
    const service = new SafeDnsService(join(dir, "dns.json"), () => "http://127.0.0.1:9", {
      platform: "win32",
      port: 0,
      available: async () => true,
      currentServers: async () => [],
      fetchDomains: async () => [],
      exec: async () => {
        throw new Error("The operation was canceled by the user.");
      },
    });
    await service.load();
    await expect(service.setEnabled(true)).rejects.toThrow(/canceled/);
    expect(service.status()).toMatchObject({ enabled: false, running: false });
  });

  it("unsupported systems say so", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-dns-"));
    const service = new SafeDnsService(join(dir, "dns.json"), () => "", { platform: "linux", available: async () => false });
    await service.load();
    await expect(service.setEnabled(true)).rejects.toThrow(/systemd-resolved/);
  });
});
