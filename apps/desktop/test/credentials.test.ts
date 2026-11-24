import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { CredentialGuardService, type Signal } from "../src/core/credential-guard-service";
import { createHandlers } from "../src/core/handlers";
import { buildHome } from "../src/core/home";
import { credentialKind, displayPath, isAllowed, parseLsof, procOpenFiles } from "../src/engine/credentials";

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
  it("allows the expected tools for each kind", () => {
    expect(isAllowed("ssh_key", "/usr/bin/ssh", [])).toBe(true);
    expect(isAllowed("ssh_key", "/usr/lib/git-core/git-remote-https", [])).toBe(true);
    expect(isAllowed("env_file", "/usr/share/code/code", [])).toBe(true);
    expect(isAllowed("browser_secrets", "/opt/google/chrome/chrome", [])).toBe(true);
    expect(isAllowed("browser_secrets", "Google Chrome Helper (Renderer)", [])).toBe(true);
    expect(isAllowed("cloud_credentials", "/usr/local/bin/aws", [])).toBe(true);
  });

  it("flags scripts and other programs, and a browser reading SSH keys", () => {
    expect(isAllowed("ssh_key", "/usr/bin/python3.12", [])).toBe(false);
    expect(isAllowed("browser_secrets", "/tmp/.x/stealer", [])).toBe(false);
    expect(isAllowed("ssh_key", "/opt/google/chrome/chrome", [])).toBe(false);
    expect(isAllowed("env_file", "/usr/bin/curl", [])).toBe(false);
    // A look-alike name doesn't borrow an allowed one.
    expect(isAllowed("ssh_key", "/tmp/sshstealer", [])).toBe(false);
  });

  it("honours programs the person trusted", () => {
    expect(isAllowed("ssh_key", "/usr/bin/python3.12", ["/usr/bin/python3.12"])).toBe(true);
    expect(isAllowed("ssh_key", "/usr/bin/python3.12", ["/usr/bin/python3.11"])).toBe(false);
  });
});

describe("listing open files", () => {
  let dir = "";
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = "";
  });

  it("reads macOS lsof field output", () => {
    const text = ["p501", "cpython3", "n/Users/sam/.ssh/id_rsa", "n/dev/null", "p777", "cssh", "n/Users/sam/.ssh/id_ed25519", ""].join("\n");
    expect(parseLsof(text)).toEqual([
      { pid: 501, exe: "python3", path: "/Users/sam/.ssh/id_rsa" },
      { pid: 501, exe: "python3", path: "/dev/null" },
      { pid: 777, exe: "ssh", path: "/Users/sam/.ssh/id_ed25519" },
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
    now: () => Date.parse("2026-11-24T10:00:00Z"),
    selfPid: 1,
    ...overrides,
  });
  return { service, events, signals, running };
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
    expect(events).toEqual([["alert", { kind: "credential", id: incident!.id, pid: 900, program: "python3", credential: "ssh_key", file: "~/.ssh/id_rsa" }]]);
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
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({ trusted: ["/usr/bin/python3"] });

    const reloaded = makeService({}, file).service;
    await reloaded.load();
    expect(await reloaded.observe(901, `${HOME}/.ssh/id_rsa`, "/usr/bin/python3")).toBeNull();
    expect((await reloaded.untrust("/usr/bin/python3")).trusted).toEqual([]);
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
