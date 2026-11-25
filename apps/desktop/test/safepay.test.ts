import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { type Child, SafePayService } from "../src/core/safepay-service";
import { type Browser, PROFILE_PREFIX, candidates, dnsMode, findBrowsers, firefoxPrefs, launchPlan, parseSafePayLink, safeUrl } from "../src/engine/safepay";

const chrome: Browser = { id: "chrome", name: "Google Chrome", family: "chromium", path: "/usr/bin/google-chrome" };
const firefox: Browser = { id: "firefox", name: "Firefox", family: "firefox", path: "/usr/bin/firefox" };

describe("SafePay launch rules", () => {
  it("accepts web addresses only, without credentials", () => {
    expect(safeUrl(undefined)).toBe("about:blank");
    expect(safeUrl("bank.example")).toBe("https://bank.example/");
    expect(safeUrl("https://bank.example/login?x=1")).toBe("https://bank.example/login?x=1");
    for (const bad of ["javascript:alert(1)", "file:///etc/passwd", "https://user:pw@bank.example/", "chrome://settings", 42, "x".repeat(3000)]) {
      expect(safeUrl(bad), String(bad).slice(0, 30)).toBeNull();
    }
  });

  it("chooses where lookups go", () => {
    expect(dnsMode("chromium", true)).toBe("safe_dns");
    expect(dnsMode("firefox", true)).toBe("safe_dns");
    expect(dnsMode("firefox", false)).toBe("browser_doh");
    expect(dnsMode("chromium", false)).toBe("system");
  });

  it("starts Chromium browsers with a fresh profile, no extensions and no own DoH under Safe DNS", () => {
    const plan = launchPlan(chrome, "https://bank.example/", "/tmp/qalaa-safepay-x", "safe_dns");
    expect(plan.command).toBe("/usr/bin/google-chrome");
    expect(plan.args).toContain("--user-data-dir=/tmp/qalaa-safepay-x");
    expect(plan.args).toContain("--disable-extensions");
    expect(plan.args).toContain("--disable-sync");
    const disabled = plan.args.filter((a) => a.startsWith("--disable-features="));
    expect(disabled).toEqual(["--disable-features=AutofillServerCommunication,PasswordManagerOnboarding,DnsOverHttps"]);
    expect(plan.args.at(-1)).toBe("https://bank.example/");
    expect(launchPlan(chrome, "about:blank", "/p", "system").args.join(" ")).not.toContain("DnsOverHttps");
    expect(plan.files).toEqual([]);
  });

  it("starts Firefox with its own profile and private prefs", () => {
    const plan = launchPlan(firefox, "https://bank.example/", "/tmp/p", "browser_doh");
    expect(plan.args).toEqual(["-profile", "/tmp/p", "-no-remote", "-new-instance", "https://bank.example/"]);
    expect(plan.files[0]!.path).toBe(join("/tmp/p", "user.js"));
    const prefs = plan.files[0]!.content;
    expect(prefs).toContain('user_pref("network.trr.mode", 3);');
    expect(prefs).toContain('user_pref("network.trr.uri", "https://dns.quad9.net/dns-query");');
    expect(prefs).toContain('user_pref("extensions.enabledScopes", 0);');
    expect(prefs).toContain('user_pref("signon.rememberSignons", false);');
    // Under Safe DNS, Firefox's own DoH is off so lookups go through Qalaa.
    expect(firefoxPrefs("safe_dns")).toContain('user_pref("network.trr.mode", 5);');
    expect(firefoxPrefs("safe_dns")).not.toContain("network.trr.uri");
  });

  it("finds installed browsers in order, one path each", async () => {
    const present = new Set(["/usr/bin/chromium", "/snap/bin/chromium", "/usr/bin/firefox"]);
    const found = await findBrowsers("linux", {}, async (p) => present.has(p));
    expect(found).toEqual([
      { id: "firefox", name: "Firefox", family: "firefox", path: "/usr/bin/firefox" },
      { id: "chromium", name: "Chromium", family: "chromium", path: "/usr/bin/chromium" },
    ]);
    expect(candidates("win32", { ProgramFiles: "D:\\PF" })[0]!.paths[0]).toBe("D:\\PF\\Mozilla Firefox\\firefox.exe");
    expect(candidates("darwin").map((c) => c.id)).toEqual(["firefox", "brave", "chrome", "edge"]);
  });

  it("accepts only https pages from qalaa://safepay links", () => {
    expect(parseSafePayLink("qalaa://safepay?url=https%3A%2F%2Fbank.example%2Flogin")).toBe("https://bank.example/login");
    expect(parseSafePayLink("qalaa://safepay?url=http%3A%2F%2Fbank.example%2F")).toBeNull();
    expect(parseSafePayLink("qalaa://safepay?url=javascript%3Aalert(1)")).toBeNull();
    expect(parseSafePayLink("qalaa://other?url=https%3A%2F%2Fbank.example%2F")).toBeNull();
    expect(parseSafePayLink("qalaa://safepay")).toBeNull();
    expect(parseSafePayLink("not a link")).toBeNull();
  });
});

class FakeChild extends EventEmitter implements Child {
  pid = 4242;
}

describe("SafePay service", () => {
  let dir = "";
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = "";
  });

  async function setup(browsers: Browser[] = [firefox, chrome], safeDnsOn = false) {
    dir = await mkdtemp(join(tmpdir(), "qalaa-sp-test-"));
    const events: [string, unknown][] = [];
    const started: { command: string; args: string[]; child: FakeChild }[] = [];
    const service = new SafePayService({
      platform: "linux",
      tmp: dir,
      emit: (event, payload) => events.push([event, payload]),
      safeDnsOn: () => safeDnsOn,
      find: async () => browsers,
      start: (command, args) => {
        const child = new FakeChild();
        started.push({ command, args, child });
        return child;
      },
      now: () => Date.parse("2026-11-24T10:00:00Z"),
    });
    return { service, events, started };
  }

  it("creates a private profile, and deletes it when the browser closes", async () => {
    const { service, events, started } = await setup();
    const session = await service.launch({ url: "https://bank.example/login?session=secret" });
    expect(session).toMatchObject({ browser: "Firefox", host: "bank.example", dns: "browser_doh" });
    const profile = started[0]!.args[1]!;
    expect(profile.startsWith(join(dir, PROFILE_PREFIX))).toBe(true);
    expect((await stat(profile)).mode & 0o777).toBe(0o700);
    expect(await readFile(join(profile, "user.js"), "utf8")).toContain("network.trr.mode");
    expect((await service.status()).sessions).toHaveLength(1);

    started[0]!.child.emit("exit", 0);
    await new Promise((r) => setTimeout(r, 50));
    await expect(stat(profile)).rejects.toThrow();
    expect((await service.status()).sessions).toEqual([]);
    expect(events.map(([e]) => e)).toEqual(["safepay.started", "safepay.ended"]);
    // Only the host name leaves the service.
    expect(JSON.stringify(events)).not.toContain("secret");
    expect(JSON.stringify(session)).not.toContain(dir);
  });

  it("uses the chosen browser and Safe DNS when it's on", async () => {
    const { service, started } = await setup([firefox, chrome], true);
    const session = await service.launch({ url: "https://bank.example/", browser: "chrome" });
    expect(session.dns).toBe("safe_dns");
    expect(started[0]!.args.join(" ")).toContain("DnsOverHttps");
    await expect(service.launch({ browser: "edge" })).rejects.toMatchObject({ code: "not_found" });
    await expect(service.launch({ url: "file:///etc/passwd" })).rejects.toMatchObject({ code: "bad_params" });
  });

  it("says so when no browser is installed", async () => {
    const { service } = await setup([]);
    expect(await service.status()).toMatchObject({ available: false, browsers: [] });
    await expect(service.launch({})).rejects.toMatchObject({ code: "unavailable" });
  });

  it("removes profiles left behind by a crash, but not live ones", async () => {
    const { service, started } = await setup();
    await mkdir(join(dir, `${PROFILE_PREFIX}old1`));
    await mkdir(join(dir, `${PROFILE_PREFIX}old2`));
    await mkdir(join(dir, "unrelated"));
    await service.launch({});
    expect(await service.cleanup()).toBe(2);
    const left = await readdir(dir);
    expect(left).toContain("unrelated");
    expect(left.filter((n) => n.startsWith(PROFILE_PREFIX))).toEqual([started[0]!.args[1]!.split("/").at(-1)]);
  });

  it("cleans up after a real process exits", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-sp-test-"));
    // Node stands in for a browser: it refuses the Chromium switches and exits at once.
    const service = new SafePayService({ platform: "linux", tmp: dir, emit: () => {}, safeDnsOn: () => false, find: async () => [{ ...chrome, path: process.execPath }] });
    await service.launch({ url: "https://bank.example/" });
    for (let i = 0; i < 50 && (await readdir(dir)).length; i++) await new Promise((r) => setTimeout(r, 50));
    expect(await readdir(dir)).toEqual([]);
  });

  it("is reachable over IPC", async () => {
    const { service } = await setup();
    const handlers = createHandlers({ version: "t", safePay: service, homeInput: async () => { throw new Error(); }, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {} }, () => {});
    expect(await handlers["safepay.get"]!(undefined)).toMatchObject({ available: true, browsers: [{ id: "firefox", name: "Firefox" }, { id: "chrome", name: "Google Chrome" }], safeDnsOn: false });
    expect(await handlers["safepay.launch"]!({ url: "https://bank.example/" })).toMatchObject({ host: "bank.example" });
  });
});
