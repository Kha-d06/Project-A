import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { type Keychain, type StdinRunner, systemKeychain } from "../src/core/keychain";
import { type MailDeps, MailService } from "../src/core/mail-service";
import { EMPTY_STATE, type MailResult, sanitizeAccount, worrying } from "../src/engine/mail";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});
async function temp() {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-mail-"));
  folders.push(dir);
  return dir;
}

const SECRET = "app-pass word \"quoted\" 123";

describe("keychain", () => {
  function recorder(answers: Record<string, string> = {}) {
    const calls: { command: string; args: string[]; input: string }[] = [];
    const run: StdinRunner = async (command, args, input) => {
      calls.push({ command, args, input });
      const key = `${command} ${args[0] ?? ""}`;
      if (key in answers) return answers[key]!;
      return "";
    };
    return { calls, run };
  }

  it("never puts the secret in a command-line argument, on any system", async () => {
    for (const platform of ["linux", "darwin", "win32"] as const) {
      const { calls, run } = recorder({ "powershell.exe -NoProfile": "01000000d08c9ddf" });
      const dir = await temp();
      const kc = systemKeychain(platform, dir, run);
      await kc.set("mail-password", SECRET);
      expect(calls.length, platform).toBeGreaterThan(0);
      for (const c of calls) {
        expect(c.args.join(" "), platform).not.toContain("app-pass");
        expect(c.input, platform).toContain(platform === "darwin" ? 'app-pass word \\"quoted\\" 123' : SECRET);
      }
    }
  });

  it("Linux uses the Secret Service; a missing entry reads as none", async () => {
    const { calls, run } = recorder();
    const kc = systemKeychain("linux", await temp(), run);
    await kc.set("mail-password", SECRET);
    expect(calls[0]).toMatchObject({ command: "secret-tool", args: ["store", "--label", "Qalaa: mail-password", "service", "qalaa", "account", "mail-password"] });
    const missing = systemKeychain("linux", await temp(), async () => Promise.reject(new Error("exit 1")));
    expect(await missing.get("mail-password")).toBeNull();
  });

  it("Windows keeps only the DPAPI blob on disk, owner-only", async () => {
    const dir = await temp();
    const { run } = recorder({ "powershell.exe -NoProfile": "01000000d08c9ddf\r\n" });
    await systemKeychain("win32", dir, run).set("mail-password", SECRET);
    const blob = await readFile(join(dir, "mail-password.dpapi"), "utf8");
    expect(blob).toBe("01000000d08c9ddf");
    expect(blob).not.toContain("app-pass");
    if (process.platform !== "win32") expect((await stat(join(dir, "mail-password.dpapi"))).mode & 0o777).toBe(0o600);
  });

  it("refuses names and secrets that could break out of the command", async () => {
    const kc = systemKeychain("linux", await temp(), async () => "");
    await expect(kc.set("../evil", "x")).rejects.toThrow();
    await expect(kc.set("mail-password", "line1\nline2")).rejects.toThrow();
  });
});

function memoryKeychain(available = true, failSet = false): Keychain & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    available: async () => available,
    get: async (n) => store.get(n) ?? null,
    set: async (n, s) => {
      if (failSet) throw new Error("no keyring running");
      store.set(n, s);
    },
    remove: async (n) => void store.delete(n),
  };
}

const result = (uid: number, risk: string, subject: string): MailResult => ({ uid, from: "x@example.com", subject, date: null, risk, summary: risk, findings: [] });

async function service(keychain = memoryKeychain(), overrides: Partial<MailDeps> = {}) {
  const dir = await temp();
  const events: unknown[] = [];
  const seen: string[] = [];
  const svc = new MailService({
    file: join(dir, "mail.json"),
    keychain,
    emptyState: EMPTY_STATE,
    sanitizeAccount,
    scanInbox: async (account, password, state) => {
      seen.push(`${account.user}@${account.host} ${password}`);
      const added = [result(state.lastUid + 1, "suspicious", "Your parcel is waiting"), result(state.lastUid + 2, "no_known_threat", "Lunch?")];
      return { state: { ...state, lastUid: state.lastUid + 2, lastCheck: "2026-11-25T12:00:00.000Z", results: [...added, ...state.results] }, added };
    },
    worrying,
    emit: (_e, p) => events.push(p),
    ...overrides,
  });
  await svc.load();
  return { svc, dir, events, seen, keychain };
}

describe("mail service", () => {
  it("connects, keeps the password in the keychain (never the file), and checks once", async () => {
    const { svc, dir, events, seen, keychain } = await service();
    const status = await svc.connect({ host: "imap.example.com", port: 993, user: "me@example.com", password: SECRET });
    expect(status).toMatchObject({ account: { host: "imap.example.com", port: 993, user: "me@example.com" }, hasPassword: true, keychain: true, checking: false });
    expect(status.results.map((r) => r.subject)).toEqual(["Your parcel is waiting", "Lunch?"]);
    expect(seen).toEqual([`me@example.com@imap.example.com ${SECRET}`]);
    expect(keychain.store.get("mail-password")).toBe(SECRET);
    const file = await readFile(join(dir, "mail.json"), "utf8");
    expect(file).not.toContain("app-pass");
    if (process.platform !== "win32") expect((await stat(join(dir, "mail.json"))).mode & 0o777).toBe(0o600);
    expect(events).toEqual([{ kind: "mail", count: 1, subject: "Your parcel is waiting" }]);
  });

  it("without a working keychain, the password lasts for this session only, and says so", async () => {
    for (const keychain of [memoryKeychain(false), memoryKeychain(true, true)]) {
      const { svc } = await service(keychain);
      const status = await svc.connect({ host: "imap.example.com", port: 993, user: "me", password: SECRET });
      expect(status).toMatchObject({ hasPassword: true, keychain: false });
    }
  });

  it("after a restart with no keychain entry, a check asks for the password again", async () => {
    const first = await service(memoryKeychain(false));
    await first.svc.connect({ host: "imap.example.com", port: 993, user: "me", password: SECRET });
    const again = new MailService({ ...(first.svc as unknown as { deps: MailDeps }).deps });
    await again.load();
    expect(await again.status()).toMatchObject({ account: { user: "me" }, hasPassword: false });
    await expect(again.check()).rejects.toMatchObject({ code: "no_password" });
  });

  it("checks input and refuses watching without an inbox", async () => {
    const { svc } = await service();
    await expect(svc.connect({ host: "imap.example.com", port: 993, user: "me" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.connect({ host: "imap.example.com", port: 993, user: "me", password: "a\nb" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.connect({ host: "", port: 993, user: "me", password: "x" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.check()).rejects.toMatchObject({ code: "not_set_up" });
    await expect(svc.setWatch({ on: true })).rejects.toMatchObject({ code: "not_set_up" });
  });

  it("disconnecting forgets the password and the account", async () => {
    const { svc, keychain } = await service();
    await svc.connect({ host: "imap.example.com", port: 993, user: "me", password: SECRET });
    await svc.setWatch({ on: true });
    const status = await svc.disconnect();
    expect(status).toMatchObject({ account: null, watch: false, hasPassword: false, results: [] });
    expect(keychain.store.size).toBe(0);
    svc.stop();
  });

  it("concurrent checks share one inbox read", async () => {
    const { svc, seen } = await service();
    await svc.connect({ host: "imap.example.com", port: 993, user: "me", password: SECRET });
    await Promise.all([svc.check(), svc.check()]);
    expect(seen).toHaveLength(2); // the connect's check, then one shared check
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const MAIL_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/mail.json");

it("mail replies match the fixture the Rust client decodes", async () => {
  const { svc } = await service(memoryKeychain(), {
    scanInbox: async (_a, _p, state) => {
      const added: MailResult[] = [
        { uid: 41, from: "\"DHL Express\" <noreply@dhl-parcel.example>", subject: "Your parcel is waiting", date: "2026-11-25T09:00:00.000Z", risk: "suspicious", summary: "Warning signs", findings: [{ severity: "high", title: "The sender's name doesn't match its address", explanation: "Says DHL, but sends from dhl-parcel.example." }], linksChecked: true },
        { uid: 42, from: "sara@example.com", subject: "Lunch?", date: "2026-11-25T10:00:00.000Z", risk: "no_known_threat", summary: "No known threat", findings: [], linksChecked: false },
      ];
      return { state: { ...state, lastUid: 42, lastCheck: "2026-11-25T12:00:00.000Z", results: added }, added };
    },
  });
  const status = await svc.connect({ host: "imap.example.com", port: 993, user: "me@example.com", password: SECRET });
  const fixture = { status: { ...status, watch: true } };
  if (process.env.UPDATE_FIXTURES) await writeFile(MAIL_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(MAIL_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});
