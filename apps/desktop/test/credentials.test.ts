import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { CredentialGuardService, type Signal } from "../src/core/credential-guard-service";
import { createHandlers } from "../src/core/handlers";
import { buildHome } from "../src/core/home";
import { credentialKind, displayPath, keychainDumps, nameAllowed, parseLsof, parsePsComm, procOpenFiles } from "../src/engine/credentials";
import { codesignArgs, linuxTrustedLocation, macBundle, macTrustedLocation } from "../src/engine/program-trust";

const HOME = "/home/sam";

describe("which files are credentials", () => {
  it("recognises SSH keys, .env files, cloud credentials and browser secret stores", () => {
    expect(credentialKind(`${HOME}/.ssh/id_ed25519`, HOME)).toBe("ssh_key");
    expect(credentialKind(`${HOME}/.ssh/work_rsa`, HOME)).toBe("ssh_key");
    expect(credentialKind(`${HOME}/code/app/.env`, HOME)).toBe("env_file");
    expect(credentialKind(`/srv/app/.env.production`, HOME)).toBe("env_file");
    expect(credentialKind(`${HOME}/.aws/credentials`, HOME)).toBe("cloud_credentials");
    expect(credentialKind(`${HOME}/.kube/config`, HOME)).toBe("cloud_credentials");
    expect(credentialKind(`${HOME}/.config/google-chrome/Default/Cookies`, HOME)).toBe("browser_secrets");
    expect(credentialKind(`${HOME}/.config/google-chrome/Profile 1/Login Data`, HOME)).toBe("browser_secrets");
    expect(credentialKind(`${HOME}/.mozilla/firefox/abc.default/logins.json`, HOME)).toBe("browser_secrets");
    expect(credentialKind(`${HOME}/Library/Application Support/Firefox/Profiles/x/key4.db`, HOME)).toBe("browser_secrets");
  });

  it("recognises keychains, password databases, wallets, chat tokens and system secrets (SigmaHQ paths)", () => {
    const cases: [string, string][] = [
      [`${HOME}/Library/Keychains/login.keychain-db`, "keychain"],
      [`${HOME}/Documents/Passwords.kdbx`, "password_manager"],
      [`${HOME}/.electrum/wallets/default_wallet`, "crypto_wallet"],
      [`${HOME}/.config/Exodus/exodus.wallet/seed.seco`, "crypto_wallet"],
      [`${HOME}/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log`, "crypto_wallet"],
      [`${HOME}/.config/discord/Local Storage/leveldb/000005.ldb`, "messaging_tokens"],
      [`${HOME}/.local/share/TelegramDesktop/tdata/key_datas`, "messaging_tokens"],
      ["/etc/shadow", "system_secrets"],
      [`${HOME}/.config/google-chrome/Local State`, "browser_key"],
      [`${HOME}/.config/gh/hosts.yml`, "cloud_credentials"],
    ];
    for (const [path, kind] of cases) expect(credentialKind(path, HOME), path).toBe(kind);
    // Windows paths, with any capitalisation.
    const winHome = "C:\\Users\\sam";
    expect(credentialKind("C:\\Users\\sam\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", winHome)).toBe("browser_secrets");
    expect(credentialKind("C:\\Users\\sam\\AppData\\Roaming\\Microsoft\\Credentials\\ABCDEF", winHome)).toBe("windows_credentials");
    expect(credentialKind("C:\\Users\\sam\\appdata\\roaming\\Telegram Desktop\\tdata\\x", winHome)).toBe("messaging_tokens");
  });

  it("leaves public keys, examples and look-alikes alone", () => {
    for (const path of [
      `${HOME}/.ssh/id_ed25519.pub`,
      `${HOME}/.ssh/known_hosts`,
      `${HOME}/.ssh/config`,
      `${HOME}/.ssh/authorized_keys`,
      `${HOME}/code/app/.env.example`,
      `${HOME}/code/app/.env.sample`,
      `${HOME}/code/app/.environment`,
      `${HOME}/Documents/Cookies`,
      `${HOME}/Documents/credentials`,
      `/etc/ssh/ssh_host_ed25519_key`,
    ]) {
      expect(credentialKind(path, HOME), path).toBeNull();
    }
  });

  it("never shows the full home folder", () => {
    expect(displayPath(`${HOME}/.ssh/id_rsa`, HOME)).toBe("~/.ssh/id_rsa");
    expect(displayPath("/srv/app/.env", HOME)).toBe("/srv/app/.env");
  });
});

describe("which programs may read them", () => {
  it("knows the expected tools for each kind by name", () => {
    expect(nameAllowed("ssh_key", "/usr/bin/ssh")).toBe(true);
    expect(nameAllowed("ssh_key", "/usr/lib/git-core/git-remote-https")).toBe(true);
    expect(nameAllowed("env_file", "/usr/share/code/code")).toBe(true);
    expect(nameAllowed("browser_secrets", "Google Chrome Helper (Renderer)")).toBe(true);
    expect(nameAllowed("password_manager", "C:\\Program Files\\KeePass\\KeePass.exe")).toBe(true);
    expect(nameAllowed("ssh_key", "/usr/bin/python3.12")).toBe(false);
    expect(nameAllowed("ssh_key", "/opt/google/chrome/chrome")).toBe(false);
    expect(nameAllowed("ssh_key", "/tmp/sshstealer")).toBe(false);
  });
});

describe("where a trusted name has to live", () => {
  const root = { uid: 0, mode: 0o40755, isFile: () => false };
  const tree: Record<string, { uid: number; mode: number; isFile: () => boolean }> = {
    "/": root,
    "/usr": root,
    "/usr/bin": root,
    "/usr/bin/ssh": { uid: 0, mode: 0o100755, isFile: () => true },
    "/home": root,
    "/home/sam": { uid: 1000, mode: 0o40700, isFile: () => false },
    "/home/sam/.local": { uid: 1000, mode: 0o40755, isFile: () => false },
    "/home/sam/.local/bin": { uid: 1000, mode: 0o40755, isFile: () => false },
    "/home/sam/.local/bin/git": { uid: 1000, mode: 0o100755, isFile: () => true },
    "/tmp": { uid: 0, mode: 0o41777, isFile: () => false },
    "/tmp/ssh": { uid: 0, mode: 0o100755, isFile: () => true },
    "/opt": root,
    "/opt/shared": { uid: 0, mode: 0o40777, isFile: () => false },
    "/opt/shared/ssh": { uid: 0, mode: 0o100755, isFile: () => true },
    "/usr/bin/sshw": { uid: 0, mode: 0o100777, isFile: () => true },
  };
  const statOf = async (p: string) => {
    const hit = tree[p];
    if (!hit) throw new Error("ENOENT");
    return hit;
  };
  const same = async (p: string) => p;

  it("Linux: root-owned all the way up, and not writable by others", async () => {
    expect(await linuxTrustedLocation("/usr/bin/ssh", statOf, same)).toBe(true);
    // A copy of ssh in /tmp, or a "git" in the person's own folder, is not the real thing.
    expect(await linuxTrustedLocation("/tmp/ssh", statOf, same)).toBe(false);
    expect(await linuxTrustedLocation("/home/sam/.local/bin/git", statOf, same)).toBe(false);
    expect(await linuxTrustedLocation("/opt/shared/ssh", statOf, same)).toBe(false);
    expect(await linuxTrustedLocation("/usr/bin/sshw", statOf, same)).toBe(false);
    expect(await linuxTrustedLocation("/usr/bin/ssh (deleted)", statOf, same)).toBe(false);
    expect(await linuxTrustedLocation("ssh", statOf, same)).toBe(false);
    expect(await linuxTrustedLocation("/nope/ssh", statOf, same)).toBe(false);
    // A symlink is judged by where it points.
    expect(await linuxTrustedLocation("/usr/local/bin/ssh", statOf, async () => "/tmp/ssh")).toBe(false);
  });

  it("macOS: SIP-protected paths, or an Apple / Developer ID signature", async () => {
    const calls: string[][] = [];
    const runner = async (_cmd: string, args: string[]) => {
      calls.push(args);
      return args.at(-1) === "/Applications/Brave Browser.app";
    };
    expect(await macTrustedLocation("/usr/bin/ssh", runner)).toBe(true);
    expect(calls).toEqual([]);
    expect(await macTrustedLocation("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser", runner)).toBe(true);
    expect(await macTrustedLocation("/Users/sam/Downloads/ssh", runner)).toBe(false);
    expect(codesignArgs("/Applications/X.app/Contents/MacOS/X")).toEqual(["--verify", "--strict", "-R=anchor apple generic", "/Applications/X.app"]);
    expect(macBundle("/usr/local/bin/gh")).toBe("/usr/local/bin/gh");
  });
});

describe("listing open files", () => {
  let dir = "";
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = "";
  });

  it("reads macOS lsof field output, and the full program path from ps", () => {
    const text = ["p501", "cpython3", "n/Users/sam/.ssh/id_rsa", "n/dev/null", "p777", "cssh", "n/Users/sam/.ssh/id_ed25519", ""].join("\n");
    expect(parseLsof(text)).toEqual([
      { pid: 501, path: "/Users/sam/.ssh/id_rsa" },
      { pid: 501, path: "/dev/null" },
      { pid: 777, path: "/Users/sam/.ssh/id_ed25519" },
    ]);
    // lsof's command column is cut short ("Google Ch"); ps has the whole path.
    expect(parsePsComm("  501 /opt/homebrew/bin/python3\n  777 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n")).toEqual(
      new Map([
        [501, "/opt/homebrew/bin/python3"],
        [777, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
      ]),
    );
  });

  it("spots keychain dumps by command line (SigmaHQ macOS security rules)", () => {
    const ps = [
      "  10 /usr/bin/security dump-keychain -d login.keychain",
      "  11 security find-generic-password -wa Chrome",
      "  12 /usr/bin/security find-generic-password -s Wi-Fi",
      "  13 /usr/bin/security list-keychains",
      "  14 /usr/bin/python3 security.py dump-keychain",
    ].join("\n");
    expect(keychainDumps(ps)).toEqual([
      { pid: 10, command: "security dump-keychain" },
      { pid: 11, command: "security find-generic-password" },
    ]);
  });

  it("reads /proc fd links, skipping processes it can't see", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-proc-"));
    await mkdir(join(dir, "123", "fd"), { recursive: true });
    await symlink("/usr/bin/python3", join(dir, "123", "exe"));
    await symlink(`${HOME}/.ssh/id_rsa`, join(dir, "123", "fd", "3"));
    await symlink("/dev/null", join(dir, "123", "fd", "0"));
    await symlink("socket:[1234]", join(dir, "123", "fd", "4"));
    await mkdir(join(dir, "456"), { recursive: true }); // another user's: no fd folder visible
    await writeFile(join(dir, "self"), "");
    const files = await procOpenFiles((p) => credentialKind(p, HOME) !== null, dir);
    expect(files).toEqual([{ pid: 123, exe: "/usr/bin/python3", path: `${HOME}/.ssh/id_rsa` }]);
  });
});

function makeService(overrides: Partial<ConstructorParameters<typeof CredentialGuardService>[0]> = {}, file = "/nonexistent/qalaa-test/cg.json") {
  const events: [string, unknown][] = [];
  const signals: [number, Signal][] = [];
  const running = new Map<number, string>([[900, "/usr/bin/python3"]]);
  const hashes = new Map<string, string>();
  const service = new CredentialGuardService({
    file,
    home: HOME,
    platform: "linux",
    emit: (event, payload) => events.push([event, payload]),
    source: async () => [],
    exeOf: async (pid) => running.get(pid) ?? null,
    signal: (pid, sig) => {
      if (!running.has(pid)) throw Object.assign(new Error("no such process"), { code: "ESRCH" });
      signals.push([pid, sig]);
    },
    commands: async () => [],
    // In these tests only /usr is a place the person's programs can't write to.
    trustedLocation: async (exe) => exe.startsWith("/usr/"),
    hashFile: async (exe) => hashes.get(exe) ?? `sha-of:${exe}`,
    now: () => Date.parse("2026-11-24T10:00:00Z"),
    selfPid: 1,
    ...overrides,
  });
  return { service, events, signals, running, hashes };
}

describe("credential guard service", () => {
  let dir = "";
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = "";
  });

  it("raises one high-priority alert per program and file, never for expected tools", async () => {
    const { service, events } = makeService();
    expect(await service.observe(800, `${HOME}/.ssh/id_rsa`, "/usr/bin/ssh")).toBeNull();
    expect(await service.observe(900, `${HOME}/Documents/notes.txt`)).toBeNull();
    const incident = await service.observe(900, `${HOME}/.ssh/id_rsa`);
    expect(incident).toMatchObject({ pid: 900, program: "python3", credential: "ssh_key", file: "~/.ssh/id_rsa", state: "open" });
    expect(await service.observe(900, `${HOME}/.ssh/id_rsa`)).toBeNull();
    expect(await service.observe(1, `${HOME}/.ssh/id_rsa`, "/x/self")).toBeNull(); // Qalaa itself
    expect(events).toEqual([["alert", { kind: "credential", id: incident!.id, pid: 900, program: "python3", credential: "ssh_key", file: "~/.ssh/id_rsa", severity: "warning" }]]);
    expect(JSON.stringify(events)).not.toContain(HOME);
    expect(service.pendingCount()).toBe(1);
  });

  it("polls the source and stays quiet when turned off", async () => {
    const { service, events } = makeService({ source: async () => [{ pid: 900, exe: "/usr/bin/python3", path: `${HOME}/.aws/credentials` }] });
    service.configure({ enabled: false });
    expect(await service.poll()).toEqual([]);
    service.configure({ enabled: true });
    expect((await service.poll()).map((i) => i.credential)).toEqual(["cloud_credentials"]);
    expect(events).toHaveLength(1);
  });

  it("suspends, resumes and terminates only the same program", async () => {
    const { service, signals, running } = makeService();
    const incident = (await service.observe(900, `${HOME}/.env`))!;
    expect((await service.suspend(incident.id)).incidents[0]!.state).toBe("suspended");
    expect((await service.resume(incident.id)).incidents[0]!.state).toBe("open");
    expect((await service.terminate(incident.id)).incidents[0]!.state).toBe("terminated");
    expect(signals).toEqual([[900, "SIGSTOP"], [900, "SIGCONT"], [900, "SIGKILL"]]);
    expect(service.pendingCount()).toBe(0);

    // The pid now belongs to a different program: nothing is signalled.
    const second = (await service.observe(900, `${HOME}/.ssh/id_ed25519`))!;
    running.set(900, "/usr/bin/bash");
    await expect(service.suspend(second.id)).rejects.toMatchObject({ code: "not_found" });
    expect(signals).toHaveLength(3);
    await expect(service.suspend("missing")).rejects.toMatchObject({ code: "not_found" });
    await expect(service.suspend(42)).rejects.toMatchObject({ code: "bad_params" });
  });

  it("explains when a program belongs to someone else", async () => {
    const { service } = makeService({
      signal: () => {
        throw Object.assign(new Error("denied"), { code: "EPERM" });
      },
    });
    const incident = (await service.observe(900, `${HOME}/.env`))!;
    await expect(service.suspend(incident.id)).rejects.toMatchObject({ code: "not_allowed" });
  });

  it("is honest about Windows", async () => {
    const { service } = makeService({ platform: "win32", source: undefined });
    expect(service.status()).toMatchObject({ supported: false, mode: "unavailable" });
  });

  it("only claims every-open mode on Linux", () => {
    const linux = makeService().service;
    linux.configure({ everyOpen: true });
    expect(linux.mode()).toBe("every_open");
    const mac = makeService({ platform: "darwin" }).service;
    mac.configure({ everyOpen: true });
    expect(mac.mode()).toBe("polling");
  });

  it("remembers allowed programs, resuming a paused one", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-cg-"));
    const file = join(dir, "cg.json");
    const { service, signals } = makeService({}, file);
    await service.load();
    const incident = (await service.observe(900, `${HOME}/.ssh/id_rsa`))!;
    await service.suspend(incident.id);
    const status = await service.allow(incident.id);
    expect(status.trusted).toEqual(["/usr/bin/python3"]);
    expect(status.incidents).toEqual([]);
    expect(signals.at(-1)).toEqual([900, "SIGCONT"]);
    // Pinned to that exact binary.
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({ trusted: [{ exe: "/usr/bin/python3", sha256: "sha-of:/usr/bin/python3" }] });

    const reloaded = makeService({}, file).service;
    await reloaded.load();
    expect(await reloaded.observe(901, `${HOME}/.ssh/id_rsa`, "/usr/bin/python3")).toBeNull();
    expect((await reloaded.untrust("/usr/bin/python3")).trusted).toEqual([]);
  });

  it("never lets a look-alike borrow a trusted name", async () => {
    const { service } = makeService();
    // Same names as the default list, but in folders the person (or malware running as them) can write to.
    expect(await service.observe(901, `${HOME}/.ssh/id_rsa`, "/tmp/.x/ssh")).toMatchObject({ program: "ssh" });
    expect(await service.observe(902, `${HOME}/.git-credentials`, `${HOME}/.local/bin/git`)).toMatchObject({ program: "git" });
    expect(await service.observe(903, `${HOME}/.ssh/id_rsa`, "/usr/bin/ssh")).toBeNull();
  });

  it("reports an allowed program again if its binary changes", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-cg-"));
    const { service, hashes } = makeService({}, join(dir, "cg.json"));
    const first = (await service.observe(900, `${HOME}/.ssh/id_rsa`, "/opt/tool/sync"))!;
    await service.allow(first.id);
    expect(await service.observe(910, `${HOME}/.ssh/id_rsa`, "/opt/tool/sync")).toBeNull();
    hashes.set("/opt/tool/sync", "replaced");
    expect(await service.observe(911, `${HOME}/.ssh/id_rsa`, "/opt/tool/sync")).toMatchObject({ program: "sync" });
  });

  it("pins the hash of programs allowed before hashes were kept", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-cg-"));
    const file = join(dir, "cg.json");
    await writeFile(file, JSON.stringify({ trusted: ["/opt/tool/sync"] }));
    const { service, hashes } = makeService({}, file);
    await service.load();
    expect(await service.observe(920, `${HOME}/.ssh/id_rsa`, "/opt/tool/sync")).toBeNull();
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({ trusted: [{ exe: "/opt/tool/sync", sha256: "sha-of:/opt/tool/sync" }] });
    hashes.set("/opt/tool/sync", "replaced");
    expect(await service.observe(921, `${HOME}/.ssh/id_rsa`, "/opt/tool/sync")).not.toBeNull();
  });

  it("raises a high-priority alert for the browser-stealer pattern and for high-value stores", async () => {
    const { service, events } = makeService();
    const chrome = `${HOME}/.config/google-chrome`;
    const key = await service.observe(930, `${chrome}/Local State`, "/tmp/.cache/upd");
    expect(key).toMatchObject({ credential: "browser_key", severity: "warning" });
    const secrets = await service.observe(930, `${chrome}/Default/Login Data`, "/tmp/.cache/upd");
    expect(secrets).toMatchObject({ credential: "browser_secrets", severity: "high", pattern: "browser_key_and_secrets" });
    expect(events.at(-1)?.[1]).toMatchObject({ severity: "high", pattern: "browser_key_and_secrets" });
    // The browser itself reading its own files is expected.
    expect(await service.observe(931, `${chrome}/Local State`, "/usr/bin/google-chrome")).toBeNull();
    expect(await service.observe(932, `${HOME}/.electrum/wallets/default_wallet`, "/tmp/x")).toMatchObject({ credential: "crypto_wallet", severity: "high" });
  });

  it("reports keychain dumps seen on the command line", async () => {
    const { service, events } = makeService({
      platform: "darwin",
      commands: async () => [{ pid: 940, exe: "/usr/bin/security", command: "security dump-keychain", kind: "keychain" }],
    });
    const found = await service.poll();
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ program: "security", credential: "keychain", file: "security dump-keychain", severity: "high" });
    expect(await service.poll()).toEqual([]); // once per process
    expect(events).toHaveLength(1);
  });

  it("is reachable over IPC and puts a priority action on Home", async () => {
    const { service } = makeService();
    const incident = (await service.observe(900, `${HOME}/.ssh/id_rsa`))!;
    const emitted: string[] = [];
    const handlers = createHandlers(
      {
        version: "test",
        credentials: service,
        homeInput: async () => ({
          now: new Date("2026-11-24T10:00:00Z"),
          platform: "linux",
          watchEnabled: true,
          onAccessScan: false,
          ransomwareWatch: true,
          networkWatch: true,
          cloudLookup: true,
          signatures: { count: 10, updatedAt: "2026-11-24T09:00:00Z", error: null },
          lastScanAt: "2026-11-24T09:00:00Z",
          lastNetworkScanAt: "2026-11-24T09:00:00Z",
          lastBackupAt: "2026-11-24T09:00:00Z",
          lastBackupError: null,
          backupConfigured: true,
          quarantineCount: 0,
          recentThreats: 0,
          ransomwareAlertAt: null,
          updateAvailable: null,
          silentUntil: null,
          credentialGuard: { on: true, available: true, pending: service.pendingCount() },
        }),
        updateToggles: async () => {},
        quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }),
        updateSignatures: async () => {},
      },
      (event) => emitted.push(event),
    );
    const home = (await handlers["home.get"]!(undefined)) as ReturnType<typeof buildHome>;
    expect(home.state).toBe("attention");
    expect(home.actions[0]).toMatchObject({ id: "review_credentials", priority: 1 });
    expect(home.toggles.find((t) => t.key === "credentialGuard")).toEqual({ key: "credentialGuard", on: true, available: true });
    expect(((await handlers["credentials.get"]!(undefined)) as { incidents: unknown[] }).incidents).toHaveLength(1);
    await handlers["credentials.dismiss"]!({ id: incident.id });
    expect(emitted).toContain("home.changed");
    expect(service.pendingCount()).toBe(0);
    await expect(createHandlers({ version: "x", homeInput: async () => { throw new Error(); }, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {} }, () => {})["credentials.get"]!(undefined)).rejects.toMatchObject({ code: "unavailable" });
  });
});

describe("program trust on this machine", () => {
  it.runIf(process.platform === "linux")("trusts root-owned system binaries, never a copy in a temporary folder", async () => {
    const { sha256File } = await import("../src/engine/program-trust");
    expect(await linuxTrustedLocation("/usr/bin/env")).toBe(true);
    const dir = await mkdtemp(join(tmpdir(), "qalaa-trust-"));
    try {
      const copy = join(dir, "ssh");
      await writeFile(copy, "#!/bin/sh\n", { mode: 0o755 });
      expect(await linuxTrustedLocation(copy)).toBe(false);
      expect(await sha256File(copy)).toBe("a8076d3d28d21e02012b20eaf7dbf75409a6277134439025f282e368e3305abf");
      expect(await sha256File(join(dir, "missing"))).toBeNull();
      expect(await sha256File("relative/path")).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
