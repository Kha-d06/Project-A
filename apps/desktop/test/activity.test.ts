import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterAll, describe, expect, it } from "vitest";

import { parseBitLocker, parseFdesetup, parseLsblk } from "../src/engine/encryption";
import { checkHistory, chromiumTime, findHistoryFiles, matchVisits, normaliseUrl } from "../src/engine/history";
import { concernsFor, groupByExecutable, parsePs, parseProcExe, parseWindowsProcesses } from "../src/engine/processes";
import { buildConfig, generateKeyPair, parseConnections } from "../src/engine/vpn";

const folders: string[] = [];
afterAll(async () => {
  for (const folder of folders) await rm(folder, { recursive: true, force: true });
});

describe("running programs", () => {
  it("parses each platform's process list", () => {
    expect(parseWindowsProcesses('[{"ProcessId":4,"Name":"System","ExecutablePath":null},{"ProcessId":88,"Name":"evil.exe","ExecutablePath":"C:\\\\Users\\\\a\\\\AppData\\\\Local\\\\Temp\\\\evil.exe"}]')).toEqual([
      { pid: 4, name: "System", path: null },
      { pid: 88, name: "evil.exe", path: "C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe" },
    ]);
    expect(parseWindowsProcesses('{"ProcessId":5,"Name":"one.exe","ExecutablePath":"C:\\\\one.exe"}')).toHaveLength(1);
    expect(parseWindowsProcesses("not json")).toEqual([]);
    expect(parsePs("  1 /sbin/launchd\n 420 /Applications/Safari.app/Contents/MacOS/Safari\n 77 kernel_task\n")).toEqual([
      { pid: 1, name: "launchd", path: "/sbin/launchd" },
      { pid: 420, name: "Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari" },
      { pid: 77, name: "kernel_task", path: null },
    ]);
    expect(parseProcExe("/tmp/x (deleted)")).toEqual({ path: "/tmp/x", deleted: true });
  });

  it("flags programs running from unusual places", () => {
    const home = "/home/me";
    expect(concernsFor({ pid: 1, name: "a", path: "/tmp/.x/miner" }, home)).toEqual(["temp_folder"]);
    expect(concernsFor({ pid: 1, name: "a", path: "/dev/shm/kworker" }, home)).toEqual(["temp_folder"]);
    expect(concernsFor({ pid: 1, name: "a", path: "/home/me/Downloads/setup" }, home)).toEqual(["downloads_folder"]);
    expect(concernsFor({ pid: 1, name: "a", path: "/home/me/.hidden/agent" }, home)).toEqual(["hidden_folder"]);
    expect(concernsFor({ pid: 1, name: "a", path: "/home/me/.local/bin/tool" }, home)).toEqual([]);
    expect(concernsFor({ pid: 1, name: "a", path: "/usr/bin/bash", deleted: true }, home)).toEqual(["deleted_executable"]);
    expect(concernsFor({ pid: 1, name: "a", path: "/memfd:payload", deleted: true }, home)).toEqual(["memory_only"]);
    expect(concernsFor({ pid: 1, name: "a", path: "C:\\Users\\me\\AppData\\Local\\Temp\\x.exe" }, "C:\\Users\\me")).toEqual(["temp_folder"]);
    expect(concernsFor({ pid: 1, name: "a", path: "C:\\Users\\me\\Downloads\\x.exe" }, "C:\\Users\\me")).toEqual(["downloads_folder"]);
    expect(concernsFor({ pid: 1, name: "a", path: "/usr/lib/firefox/firefox" }, home)).toEqual([]);
  });

  it("groups processes by executable", () => {
    const groups = groupByExecutable([
      { pid: 2, name: "chrome", path: "/opt/chrome" },
      { pid: 3, name: "chrome", path: "/opt/chrome" },
      { pid: 4, name: "x", path: null },
    ]);
    expect(groups).toEqual([{ path: "/opt/chrome", name: "chrome", pids: [2, 3], deleted: false }]);
  });
});

describe("browser history check", () => {
  const list = { hosts: ["evil.example", "c2.example.net"], urls: ["https://shared.example.org/login/bank"] };

  it("matches listed domains (and their subdomains) and exact listed URLs only", () => {
    const visits = [
      { url: "https://login.evil.example/account", visitedAt: new Date("2026-11-10T10:00:00Z") },
      { url: "https://evil.example/other", visitedAt: null }, // same domain, reported once
      { url: "https://SHARED.example.org/login/bank#top", visitedAt: null },
      { url: "https://shared.example.org/blog", visitedAt: null }, // shared host itself is fine
      { url: "https://notevil.example/", visitedAt: null },
      { url: "chrome://settings", visitedAt: null },
    ];
    const matches = matchVisits(visits, list, { browser: "Chrome", profile: "Default" });
    expect(matches.map((m) => [m.host, m.reason])).toEqual([
      ["login.evil.example", "domain"],
      ["evil.example", "domain"],
      ["shared.example.org", "url"],
    ]);
  });

  it("normalises URLs like the server does", () => {
    expect(normaliseUrl("HTTPS://Example.COM")).toBe("https://example.com/");
    expect(normaliseUrl("http://a.example:8080/p?q=1#f")).toBe("http://a.example:8080/p?q=1");
    expect(normaliseUrl("https://a.example:443/")).toBe("https://a.example/");
    expect(normaliseUrl("file:///etc/passwd")).toBeNull();
  });

  it("converts Chromium timestamps", () => {
    expect(chromiumTime(13_380_000_000_000_000n)?.getUTCFullYear()).toBe(2024);
    expect(chromiumTime(0)).toBeNull();
  });

  it("reads real Chromium and Firefox history files from a copy", async () => {
    const home = await mkdtemp(join(tmpdir(), "sentinel-home-"));
    folders.push(home);
    const chrome = join(home, ".config/google-chrome/Default");
    const firefox = join(home, ".mozilla/firefox/abc123.default-release");
    await mkdir(chrome, { recursive: true });
    await mkdir(firefox, { recursive: true });
    const now = BigInt(Date.now()) * 1000n;
    const c = new DatabaseSync(join(chrome, "History"));
    c.exec("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, last_visit_time INTEGER)");
    c.prepare("INSERT INTO urls (url, last_visit_time) VALUES (?, ?), (?, ?), (?, ?)").run(
      "https://evil.example/login", now + 11_644_473_600_000_000n,
      "https://good.example/", now + 11_644_473_600_000_000n,
      "https://c2.example.net/old", 11_644_473_600_000_000n + 1000n, // 1970: older than the window
    );
    c.close();
    const f = new DatabaseSync(join(firefox, "places.sqlite"));
    f.exec("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, last_visit_date INTEGER)");
    f.prepare("INSERT INTO moz_places (url, last_visit_date) VALUES (?, ?)").run("https://shared.example.org/login/bank", now);
    f.close();

    const files = await findHistoryFiles("linux", home);
    expect(files.map((file) => [file.browser, file.profile, file.kind])).toEqual([
      ["Chrome", "Default", "chromium"],
      ["Firefox", "default-release", "firefox"],
    ]);
    const report = await checkHistory(list, 30, files);
    expect(report.browsers.map((b) => [b.browser, b.visits, b.error])).toEqual([
      ["Chrome", 2, null],
      ["Firefox", 1, null],
    ]);
    expect(report.matches.map((m) => [m.browser, m.host])).toEqual(
      expect.arrayContaining([
        ["Chrome", "evil.example"],
        ["Firefox", "shared.example.org"],
      ]),
    );
    expect(report.matches).toHaveLength(2);
  });
});

describe("disk encryption", () => {
  it("reads lsblk, fdesetup and BitLocker answers", () => {
    const luks = JSON.stringify({ blockdevices: [{ name: "nvme0n1", type: "disk", mountpoints: [null], children: [{ name: "nvme0n1p2", type: "part", mountpoints: [null], children: [{ name: "luks-1", type: "crypt", mountpoints: [null], children: [{ name: "vg-root", type: "lvm", mountpoints: ["/"] }] }] }] }] });
    expect(parseLsblk(luks).state).toBe("on");
    expect(parseLsblk(JSON.stringify({ blockdevices: [{ name: "sda", type: "disk", mountpoints: [null], children: [{ name: "sda1", type: "part", mountpoints: ["/"] }] }] })).state).toBe("off");
    expect(parseLsblk("{}").state).toBe("unknown");
    expect(parseLsblk("garbage").state).toBe("unknown");
    expect(parseFdesetup("FileVault is On.\n").state).toBe("on");
    expect(parseFdesetup("FileVault is Off.\n").state).toBe("off");
    expect(parseBitLocker("1\r\n").state).toBe("on");
    expect(parseBitLocker("2").state).toBe("off");
    expect(parseBitLocker("5").state).toBe("partial");
    expect(parseBitLocker("").state).toBe("unknown");
  });
});

describe("desktop VPN", () => {
  it("generates WireGuard keys and a tunnel file, refusing unexpected values", () => {
    const keys = generateKeyPair();
    expect(keys.publicKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(keys.privateKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(keys.publicKey).not.toBe(keys.privateKey);
    const config = {
      peer: { id: "p1", name: "PC", address: "10.13.13.2" },
      address: "10.13.13.2/32",
      dns: "10.13.13.1",
      server_public_key: generateKeyPair().publicKey,
      endpoint: "vpn.example.org:51820",
      allowed_ips: "0.0.0.0/0, ::/0",
    };
    const text = buildConfig(config, keys.privateKey);
    expect(text).toContain(`PrivateKey = ${keys.privateKey}`);
    expect(text).toContain("AllowedIPs = 0.0.0.0/0, ::/0");
    expect(() => buildConfig({ ...config, endpoint: "x\nPostUp = rm -rf /" }, keys.privateKey)).toThrow();
    expect(() => buildConfig({ ...config, server_public_key: "bad" }, keys.privateKey)).toThrow();
  });

  it("reads NetworkManager's connection list", () => {
    expect(parseConnections("Wired:802-3-ethernet:eth0\nqalaa-vpn:wireguard:qalaa-vpn\n")).toBe("connected");
    expect(parseConnections("qalaa-vpn:wireguard:\n")).toBe("disconnected");
    expect(parseConnections("Wired:802-3-ethernet:eth0\n")).toBe("not_imported");
  });
});
