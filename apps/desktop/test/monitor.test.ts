import { describe, expect, it } from "vitest";

import {
  Sampler,
  connections,
  coreUsage,
  parseDiskstats,
  parseJournal,
  parseLaunchctl,
  parseLsofConnections,
  parseMeminfo,
  parseNetDev,
  parseNetstatIb,
  parseNvidiaSmi,
  parseProcConnections,
  parseSystemctl,
  parseWindowsConnections,
  parseWindowsEvents,
  parseWindowsGpu,
  parseWindowsServices,
  pickCpuTemperature,
  rate,
  controlService,
} from "../src/engine/monitor";

describe("CPU, memory, disk, network", () => {
  it("computes per-core usage between samples", () => {
    expect(coreUsage([{ idle: 100, total: 200 }, { idle: 0, total: 0 }], [{ idle: 150, total: 400 }, { idle: 0, total: 0 }])).toEqual([75, 0]);
  });

  it("picks the CPU temperature sensor and ignores nonsense", () => {
    expect(pickCpuTemperature([{ type: "acpitz", celsius: 30 }, { type: "x86_pkg_temp", celsius: 61.5 }, { type: "bogus", celsius: 900 }])).toBe(62);
    expect(pickCpuTemperature([])).toBeNull();
  });

  it("reads /proc/meminfo, /proc/diskstats and /proc/net/dev", () => {
    expect(parseMeminfo("MemTotal:       16000000 kB\nMemFree:  100 kB\nMemAvailable:    8000000 kB\n")).toEqual({ total: 16000000 * 1024, available: 8000000 * 1024 });
    const disks = parseDiskstats(
      "   8       0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n   8       1 sda1 99 0 1999 0 49 0 3999 0 0 0 0\n   7       0 loop0 5 0 10 0 0 0 0 0 0 0 0\n 259 0 nvme0n1 10 0 100 0 5 0 50 0 0 0 0\n 259 1 nvme0n1p1 9 0 99 0 4 0 49 0 0 0 0\n",
    );
    expect(disks).toEqual({ reads: 110, writes: 55, readBytes: 2100 * 512, writeBytes: 4050 * 512 });
    const net = parseNetDev(
      "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0 3000 8 0 0 0 0 0 0\n",
    );
    expect(net).toEqual({ rxBytes: 5000, txBytes: 3000 });
    expect(rate(1000, 3000, 2)).toBe(1000);
    expect(rate(3000, 1000, 2)).toBe(0); // counter reset
  });

  it("reads macOS interface counters once per interface", () => {
    const out = [
      "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll",
      "lo0        16384 <Link#1>                          100     0      9000      100     0       9000     0",
      "en0        1500  <Link#6>      aa:bb:cc:dd:ee:ff   500     0     70000      400     0      30000     0",
      "en0        1500  192.168.1     192.168.1.5         500     -     70000      400     -      30000     -",
    ].join("\n");
    expect(parseNetstatIb(out)).toEqual({ rxBytes: 70000, txBytes: 30000 });
  });

  it("reads GPU numbers from nvidia-smi and Windows counters", () => {
    expect(parseNvidiaSmi("NVIDIA GeForce RTX 4070, 37, 2048, 12282, 55\n")).toEqual([
      { name: "NVIDIA GeForce RTX 4070", utilization: 37, memoryUsed: 2048 * 1048576, memoryTotal: 12282 * 1048576, temperature: 55 },
    ]);
    expect(parseNvidiaSmi("GPU, [N/A], 1, 2, [N/A]")[0]!.utilization).toBeNull();
    expect(parseWindowsGpu('{"util":12.345,"mem":1048576}')).toEqual({ utilization: 12.3, memoryUsed: 1048576 });
    expect(parseWindowsGpu("oops")).toEqual({ utilization: null, memoryUsed: null });
  });
});

describe("connections", () => {
  it("decodes /proc/net tables with owning processes", () => {
    const tcp = [
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
      "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1",
      "   1: 0501A8C0:D2F0 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 222 1",
    ].join("\n");
    const rows = parseProcConnections(tcp, "tcp", new Map([["222", { name: "firefox", pid: 42 }]]));
    expect(rows[0]).toMatchObject({ local: "127.0.0.1:8080", remote: null, state: "LISTEN", process: null });
    expect(rows[1]).toMatchObject({ local: "192.168.1.5:54000", remote: "93.184.216.34:443", state: "ESTABLISHED", process: "firefox", pid: 42 });
  });

  it("parses lsof and PowerShell connection lists", () => {
    const lsof = [
      "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
      "Safari    321 me    12u  IPv4 0x1      0t0  TCP 192.168.1.5:50000->93.184.216.34:443 (ESTABLISHED)",
      "mDNSResp  100 me    5u   IPv4 0x2      0t0  UDP *:5353",
    ].join("\n");
    expect(parseLsofConnections(lsof)).toEqual([
      { protocol: "tcp", local: "192.168.1.5:50000", remote: "93.184.216.34:443", state: "ESTABLISHED", process: "Safari", pid: 321 },
      { protocol: "udp", local: "*:5353", remote: null, state: "OPEN", process: "mDNSResp", pid: 100 },
    ]);
    const win = parseWindowsConnections('[{"p":"tcp","la":"10.0.0.2","lp":50100,"ra":"8.8.8.8","rp":443,"s":"Established","pid":9,"n":"chrome"},{"p":"udp","la":"0.0.0.0","lp":5353,"pid":4,"n":"svchost"}]');
    expect(win).toEqual([
      { protocol: "tcp", local: "10.0.0.2:50100", remote: "8.8.8.8:443", state: "ESTABLISHED", process: "chrome", pid: 9 },
      { protocol: "udp", local: "0.0.0.0:5353", remote: null, state: "OPEN", process: "svchost", pid: 4 },
    ]);
  });
});

describe("services and logs", () => {
  it("parses service lists on each system", () => {
    expect(parseSystemctl("ssh.service loaded active running OpenBSD Secure Shell server\ncups.service loaded failed failed CUPS\nfoo.service loaded inactive dead Foo\n")).toEqual([
      { name: "ssh.service", description: "OpenBSD Secure Shell server", state: "running", startup: null },
      { name: "cups.service", description: "CUPS", state: "failed", startup: null },
      { name: "foo.service", description: "Foo", state: "stopped", startup: null },
    ]);
    expect(parseWindowsServices('[{"Name":"WinDefend","DisplayName":"Microsoft Defender","Status":"Running","StartType":"Automatic"}]')[0]).toEqual({
      name: "WinDefend", description: "Microsoft Defender", state: "running", startup: "Automatic",
    });
    expect(parseLaunchctl("PID\tStatus\tLabel\n123\t0\tcom.apple.Finder\n-\t78\tcom.example.broken\n-\t0\tcom.example.idle\n").map((s) => s.state)).toEqual(["running", "failed", "stopped"]);
  });

  it("parses journal and Windows events and flags security-related ones", () => {
    const journal = parseJournal(
      '{"__REALTIME_TIMESTAMP":"1763400000000000","PRIORITY":"4","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid user admin from 203.0.113.5"}\n{"__REALTIME_TIMESTAMP":"1763400000000000","PRIORITY":"3","_COMM":"kernel","MESSAGE":"usb error"}\nnot json\n',
    );
    expect(journal.map((e) => [e.source, e.level, e.security])).toEqual([["sshd", "warning", true], ["kernel", "error", false]]);
    const win = parseWindowsEvents('{"t":"2026-11-18T10:00:00Z","l":2,"s":"Service Control Manager","m":"The X service terminated unexpectedly.\\nmore","id":7034}');
    expect(win[0]).toMatchObject({ level: "error", source: "Service Control Manager", message: "7034: The X service terminated unexpectedly.", security: false });
  });

  it("refuses unsafe service names before running anything", async () => {
    await expect(controlService("ssh; rm -rf /", "stop", "linux")).rejects.toThrow("not a valid service name");
    await expect(controlService("x' ; calc '", "stop", "win32")).rejects.toThrow("not a valid service name");
    await expect(controlService("ssh.service", "stop", "darwin")).rejects.toThrow("not supported");
  });
});

describe.runIf(process.platform === "linux")("on this Linux machine", () => {
  it("samples real numbers and lists real connections", async () => {
    const sampler = new Sampler("linux");
    await sampler.sample(false);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const snapshot = await sampler.sample(false);
    expect(snapshot.cpu.cores.length).toBeGreaterThan(0);
    expect(snapshot.memory.used).toBeGreaterThan(0);
    expect(snapshot.memory.used).toBeLessThanOrEqual(snapshot.memory.total);
    expect(snapshot.network).not.toBeNull();
    expect(snapshot.disk?.size).toBeGreaterThan(0);
    const list = await connections("linux");
    expect(Array.isArray(list)).toBe(true);
  });
});
