import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { parseAuthenticode, parseCodesign, parsePackageOwner, parsePasswd, parseProcStat, parsePsDetails, parseUid, parseWindowsProcessDetails, controlProcess, processDetails } from "../src/engine/explorer";
import { IntegrityMonitor, compare, fileState } from "../src/engine/integrity";
import { exportEvents, parseSystemctlShow, parseWindowsServiceDetails, serviceDetails, setServiceStartup } from "../src/engine/monitor";
import { classifyIp, lookup, parseNetDevDetail, parseWindowsAdapterStats } from "../src/engine/nettools";
import { defenderChecks, scoreChecks, sshChecks, uacCheck, unquotedServicePaths } from "../src/engine/posture";
import { toCsv, toHtml } from "../src/engine/reports";
import { parseDf, parseDiskutil, parseLsblkStorage, parseSmartctl, parseWindowsStorage } from "../src/engine/storage";
import { Telemetry } from "../src/engine/telemetry";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});
async function temp() {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-ws-"));
  folders.push(dir);
  return dir;
}

describe("process explorer", () => {
  it("parses /proc stat even when the name has spaces and brackets", () => {
    const stat = "1234 (Web Content (x)) S 1000 1234 1234 0 -1 4194560 0 0 0 0 10 5 0 0 20 0 27 0 100 2000000 512 18446744073709551615";
    expect(parseProcStat(stat)).toEqual({ name: "Web Content (x)", state: "S", ppid: 1000, threads: 27, rssPages: 512 });
    expect(parseUid("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n")).toBe(1000);
    expect(parsePasswd("root:x:0:0:root:/root:/bin/bash\nme:x:1000:1000::/home/me:/bin/zsh\n").get(1000)).toBe("me");
  });

  it("parses Windows and macOS process lists", () => {
    const win = parseWindowsProcessDetails('[{"ProcessId":88,"ParentProcessId":4,"Name":"svc.exe","ExecutablePath":"C:\\\\svc.exe","CommandLine":"svc.exe -k","ThreadCount":12,"HandleCount":340,"WorkingSetSize":"1048576"}]');
    expect(win[0]).toMatchObject({ pid: 88, ppid: 4, threads: 12, handles: 340, memoryBytes: 1048576, commandLine: "svc.exe -k" });
    const mac = parsePsDetails("  1     0  9000 root     Ss   /sbin/launchd\n 420     1 51200 me       S    /Applications/Safari.app/Contents/MacOS/Safari\n", "  1 /sbin/launchd\n 420 /Applications/Safari.app/Contents/MacOS/Safari -psn\n");
    expect(mac[1]).toMatchObject({ pid: 420, ppid: 1, name: "Safari", user: "me", memoryBytes: 51200 * 1024, commandLine: expect.stringContaining("-psn") });
  });

  it("reads signature answers from each system", () => {
    expect(parseAuthenticode('{"Status":"Valid","Signer":"CN=Microsoft Windows, O=Microsoft Corporation"}')).toEqual({ status: "signed", signer: "Microsoft Windows", detail: expect.any(String) });
    expect(parseAuthenticode('{"Status":"NotSigned","Signer":null}').status).toBe("unsigned");
    expect(parseAuthenticode('{"Status":"HashMismatch","Signer":"CN=X"}').status).toBe("invalid");
    expect(parseCodesign("Executable=/x\nAuthority=Developer ID Application: Example (ABC)\nTeamIdentifier=ABC\n", true)).toMatchObject({ status: "signed", signer: "Developer ID Application: Example (ABC)" });
    expect(parseCodesign("/x: code object is not signed at all\n", false).status).toBe("unsigned");
    expect(parsePackageOwner("coreutils: /usr/bin/ls\n", "dpkg")).toBe("coreutils");
    expect(parsePackageOwner("file /opt/x is not owned by any package\n", "rpm")).toBeNull();
  });

  it("refuses to touch system processes or itself", async () => {
    await expect(controlProcess(1, "end", "linux")).rejects.toThrow();
    await expect(controlProcess(process.pid, "end", "linux")).rejects.toThrow("cannot stop itself");
    await expect(controlProcess(5000, "suspend", "win32")).rejects.toThrow("not supported");
  });

  it.runIf(process.platform === "linux")("lists real processes with parents, threads and memory", async () => {
    const list = await processDetails("linux");
    const me = list?.find((p) => p.pid === process.pid);
    expect(me).toMatchObject({ ppid: process.ppid });
    expect(me!.threads).toBeGreaterThan(0);
    expect(me!.memoryBytes).toBeGreaterThan(0);
  });
});

describe("storage", () => {
  it("reads disks and volumes on each system", () => {
    const lsblk = JSON.stringify({ blockdevices: [
      { name: "nvme0n1", type: "disk", size: 512110190592, model: "Samsung SSD 980 ", rota: false, children: [
        { name: "nvme0n1p1", type: "part", size: 536870912, fstype: "vfat", fssize: 536608768, fsused: 6291456, mountpoints: ["/boot/efi"] },
        { name: "nvme0n1p2", type: "part", size: 511571132416, fstype: "ext4", fssize: 502000000000, fsused: 120000000000, label: "root", mountpoints: ["/"] },
      ] },
      { name: "loop0", type: "loop", size: 1000 },
    ] });
    const report = parseLsblkStorage(lsblk);
    expect(report.disks).toEqual([{ name: "nvme0n1", model: "Samsung SSD 980", kind: "ssd", sizeBytes: 512110190592, health: "unknown", healthDetail: null }]);
    expect(report.volumes.map((v) => [v.mount, v.fileSystem])).toEqual([["/boot/efi", "vfat"], ["/", "ext4"]]);
    expect(parseSmartctl('{"smart_status":{"passed":true},"temperature":{"current":38},"power_on_time":{"hours":1200}}')).toEqual({ health: "ok", healthDetail: "S.M.A.R.T. passed · 38 °C · 1200 h powered on" });
    expect(parseSmartctl('{"smart_status":{"passed":false}}').health).toBe("failing");
    const win = parseWindowsStorage('{"d":{"FriendlyName":"WD Blue","MediaType":"SSD","Size":1000,"HealthStatus":"Healthy","OperationalStatus":"OK"},"v":[{"DriveLetter":"C","FileSystem":"NTFS","Size":900,"SizeRemaining":300}]}');
    expect(win.disks[0]).toMatchObject({ model: "WD Blue", kind: "ssd", health: "ok" });
    expect(win.volumes[0]).toMatchObject({ mount: "C:\\", fileSystem: "NTFS", usedBytes: 600 });
    expect(parseDf("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s1 494384776 20000000 300000000 7% /\nmap auto_home 0 0 0 100% /System/Volumes/Data/home\n")).toHaveLength(1);
    expect(parseDiskutil("   Device / Media Name:      APPLE SSD AP0512Q\n   Disk Size:                500.3 GB (500277792768 Bytes) (exactly 977105064 512-Byte-Units)\n   SMART Status:             Verified\n   Solid State:              Yes\n", "disk0")).toMatchObject({ kind: "ssd", health: "ok", sizeBytes: 500277792768 });
  });
});

describe("network tools", () => {
  it("classifies addresses", () => {
    expect(classifyIp("10.1.2.3")).toBe("private");
    expect(classifyIp("172.20.0.1")).toBe("private");
    expect(classifyIp("100.64.1.1")).toBe("carrier-nat");
    expect(classifyIp("169.254.0.5")).toBe("link-local");
    expect(classifyIp("8.8.8.8")).toBe("public");
    expect(classifyIp("203.0.113.9")).toBe("documentation");
    expect(classifyIp("[::1]")).toBe("loopback");
    expect(classifyIp("fd00::1")).toBe("private");
    expect(classifyIp("::ffff:192.168.1.4")).toBe("private");
    expect(classifyIp("not-an-ip")).toBeNull();
  });

  it("looks up names and addresses with a resolver", async () => {
    const resolver = {
      resolve4: async () => ["93.184.216.34"],
      resolve6: async () => [],
      resolveMx: async () => [{ exchange: "mx2.example.com", priority: 20 }, { exchange: "mx1.example.com", priority: 10 }],
      resolveTxt: async () => [["v=spf1 ", "-all"]],
      reverse: async () => ["host.example.net"],
    } as unknown as Parameters<typeof lookup>[1];
    const answer = await lookup("https://example.com/path", resolver);
    expect(answer.query).toBe("example.com");
    expect(answer.addresses).toEqual([{ address: "93.184.216.34", family: 4, class: "public" }]);
    expect(answer.mx.map((m) => m.exchange)).toEqual(["mx1.example.com", "mx2.example.com"]);
    expect(answer.txt).toEqual(["v=spf1 -all"]);
    expect((await lookup("8.8.8.8", resolver)).reverse).toEqual(["host.example.net"]);
    expect((await lookup("bad name;rm", resolver)).error).toMatch(/not a host name/);
  });

  it("reads interface counters", () => {
    const linux = parseNetDevDetail("h1\nh2\n  eth0: 5000 10 1 2 0 0 0 0 3000 8 3 4 0 0 0 0\n");
    expect(linux.get("eth0")).toEqual({ rxBytes: 5000, rxPackets: 10, errors: 4, drops: 6, txBytes: 3000, txPackets: 8 });
    expect(parseWindowsAdapterStats('{"Name":"Ethernet","ReceivedBytes":10,"SentBytes":20,"ReceivedUnicastPackets":1,"SentUnicastPackets":2,"ReceivedPacketErrors":0,"OutboundPacketErrors":1,"ReceivedDiscardedPackets":0,"OutboundDiscardedPackets":0}').get("Ethernet")).toMatchObject({ rxBytes: 10, txBytes: 20, errors: 1 });
  });
});

describe("security posture", () => {
  it("scores checks, leaving unknown ones out", () => {
    const check = (status: "pass" | "fail" | "warn" | "unknown", weight = 10) => ({ id: status, title: "", status, detail: null, fix: null, weight });
    expect(scoreChecks([check("pass"), check("fail")])).toBe(50);
    expect(scoreChecks([check("pass"), check("warn"), check("unknown", 100)])).toBe(75);
    expect(scoreChecks([check("unknown")])).toBeNull();
  });

  it("reads Defender, UAC, services and SSH settings", () => {
    expect(defenderChecks('{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":1}').map((c) => c.status)).toEqual(["pass", "pass"]);
    expect(defenderChecks('{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":12}').map((c) => c.status)).toEqual(["fail", "fail"]);
    expect(uacCheck("    EnableLUA    REG_DWORD    0x1\n    ConsentPromptBehaviorAdmin    REG_DWORD    0x5\n").status).toBe("pass");
    expect(uacCheck("    EnableLUA    REG_DWORD    0x0\n").status).toBe("fail");
    expect(uacCheck("    EnableLUA    REG_DWORD    0x1\n    ConsentPromptBehaviorAdmin    REG_DWORD    0x0\n").status).toBe("warn");
    expect(
      unquotedServicePaths([
        { Name: "Bad", PathName: "C:\\Program Files\\Vendor App\\svc.exe -k run" },
        { Name: "Quoted", PathName: '"C:\\Program Files\\Vendor\\svc.exe"' },
        { Name: "NoSpace", PathName: "C:\\Tools\\svc.exe" },
        { Name: "System", PathName: "C:\\Windows\\system32\\svchost.exe -k netsvcs" },
      ]),
    ).toEqual(["Bad"]);
    expect(sshChecks("# comment\nPermitRootLogin yes\nPasswordAuthentication no\n").map((c) => c.status)).toEqual(["fail", "pass"]);
    expect(sshChecks("").map((c) => c.status)).toEqual(["pass", "warn"]);
  });
});

describe("services", () => {
  it("reads service details on Linux and Windows", () => {
    const show = "Description=OpenBSD Secure Shell server\nUser=\nExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no }\nUnitFileState=enabled\nRequires=system.slice\nWants=network-online.target\nRequiredBy=\nWantedBy=multi-user.target\n";
    expect(parseSystemctlShow("ssh.service", show)).toEqual({
      name: "ssh.service", description: "OpenBSD Secure Shell server", account: "root", command: "/usr/sbin/sshd -D $SSHD_OPTS", startup: "enabled", dependsOn: ["system.slice", "network-online.target"], requiredBy: ["multi-user.target"],
    });
    expect(parseWindowsServiceDetails("Spooler", '{"DisplayName":"Print Spooler","StartName":"LocalSystem","PathName":"C:\\\\Windows\\\\System32\\\\spoolsv.exe","StartMode":"Auto","DependsOn":["RPCSS","http"],"Dependents":"Fax"}')).toMatchObject({ account: "LocalSystem", dependsOn: ["RPCSS", "http"], requiredBy: ["Fax"] });
  });

  it("validates names before running anything", async () => {
    await expect(serviceDetails("x'; calc", "win32")).rejects.toThrow("not a valid service name");
    await expect(setServiceStartup("x; rm", true, "linux")).rejects.toThrow("not a valid service name");
  });

  it("exports events safely", () => {
    const csv = exportEvents([{ at: "2026-11-18T10:00:00.000Z", level: "warning", source: "sshd", message: '=HYPERLINK("x") "quoted"', security: true }], "csv");
    expect(csv).toContain(`"'=HYPERLINK(""x"") ""quoted"""`);
    expect(JSON.parse(exportEvents([], "json"))).toEqual([]);
  });
});

describe("file integrity monitoring", () => {
  it("detects modified, deleted and created files, and accepts changes", async () => {
    const dir = await temp();
    const a = join(dir, "hosts");
    const b = join(dir, "authorized_keys");
    const c = join(dir, "ld.so.preload");
    await writeFile(a, "127.0.0.1 localhost\n");
    await writeFile(b, "ssh-ed25519 AAAA me\n");
    const seen: string[] = [];
    const monitor = new IntegrityMonitor(join(dir, "integrity.json"), (changes) => seen.push(...changes.map((x) => `${x.kind}:${x.path}`)));
    await monitor.load();
    await monitor.rebaseline([a, b, c]);
    await writeFile(a, "127.0.0.1 localhost\n203.0.113.9 bank.example\n");
    await rm(b);
    await writeFile(c, "/tmp/evil.so\n");
    const changes = await monitor.check();
    expect(changes.map((x) => x.kind).sort()).toEqual(["created", "deleted", "modified"]);
    expect(seen).toHaveLength(3);
    expect(await monitor.check()).toEqual([]); // reported once
    const accepted = await monitor.accept(a);
    expect(accepted.changes.map((x) => x.path).sort()).toEqual([b, c].sort());
    expect(compare(accepted.baseline, [await fileState(a)])).toEqual([]);
  });
});

describe("history and reports", () => {
  it("stores minute samples and security events in SQLite", async () => {
    const telemetry = await Telemetry.open(join(await temp(), "telemetry.db"));
    const now = Date.UTC(2026, 10, 18, 12, 0, 0);
    for (let i = 0; i < 120; i++) telemetry.record({ cpu: i % 2 ? 20 : 40, memory: 50, rx: 1000, tx: 500, read: 0, write: 0 }, now - i * 60_000);
    const day = telemetry.history(24, 144, now + 1);
    expect(day.length).toBeGreaterThan(5);
    expect(day.every((p) => p.cpu >= 20 && p.cpu <= 40)).toBe(true);
    telemetry.log("integrity", "alert", "hosts changed", now);
    expect(telemetry.events(10)[0]).toMatchObject({ kind: "integrity", level: "alert", message: "hosts changed" });
    telemetry.prune(now + 8 * 86_400_000);
    expect(telemetry.history(24 * 30, 144, now + 8 * 86_400_000)).toEqual([]);
    telemetry.close();
  });

  it("renders reports as CSV and self-contained HTML", () => {
    const report = { kind: "security" as const, title: "Security audit", generatedAt: "2026-11-18T10:00:00.000Z", computer: "PC <1>", sections: [{ title: "Checks", facts: [["Firewall", "on"]] as [string, string][], table: { columns: ["Check", "Status"], rows: [["=cmd", "fail"]] } }] };
    const csv = toCsv(report);
    expect(csv).toContain("Firewall,on");
    expect(csv).toContain(`"'=cmd",fail`);
    const html = toHtml(report);
    expect(html).toContain("PC &lt;1&gt;");
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain("default-src 'none'");
  });
});
