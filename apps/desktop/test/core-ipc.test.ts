import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { type Socket, createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createHandlers, toggleChanges } from "../src/core/handlers";
import { type HomeInput, buildHome } from "../src/core/home";
import { ipcPaths } from "../src/core/paths";
import { IpcError, parseRequest } from "../src/core/protocol";
import { type IpcServer, startIpcServer } from "../src/core/server";
import { createDaemonHost } from "../src/daemon";

const NOW = new Date("2026-11-24T12:00:00Z");
const base: HomeInput = {
  now: NOW,
  platform: "linux",
  watchEnabled: true,
  onAccessScan: false,
  ransomwareWatch: true,
  networkWatch: true,
  cloudLookup: false,
  signatures: { count: 1000, updatedAt: "2026-11-24T06:00:00Z", error: null },
  lastScanAt: "2026-11-23T12:00:00Z",
  lastNetworkScanAt: "2026-11-20T12:00:00Z",
  lastBackupAt: "2026-11-22T12:00:00Z",
  lastBackupError: null,
  backupConfigured: true,
  quarantineCount: 0,
  recentThreats: 0,
  ransomwareAlertAt: null,
  updateAvailable: null,
  silentUntil: null,
};

describe("Home model", () => {
  it("a well-kept computer is protected, with freshness on each check", () => {
    const home = buildHome(base);
    expect(home.state).toBe("protected");
    expect(home.score).toBe(100);
    expect(home.checks.find((c) => c.id === "signatures")?.checkedAt).toBe("2026-11-24T06:00:00Z");
    expect(home.actions).toEqual([]);
    expect(home.toggles.find((t) => t.key === "onAccessScan")?.available).toBe(true);
    expect(buildHome({ ...base, platform: "win32" }).toggles.find((t) => t.key === "onAccessScan")?.available).toBe(false);
  });

  it("puts the most urgent actions first", () => {
    const home = buildHome({ ...base, watchEnabled: false, recentThreats: 2, backupConfigured: false, signatures: { count: 0, updatedAt: null, error: "offline" } });
    expect(home.state).toBe("at_risk");
    expect(home.actions.map((a) => a.id)).toEqual(["review_threats", "turn_on_realtime", "update_signatures", "set_up_backup"]);
    expect(home.actions[1]?.command).toEqual({ method: "settings.set", params: { watchEnabled: true } });
    expect(home.score).toBeLessThan(60);
  });

  it("stale checks ask for attention, never-run ones are unknown", () => {
    const home = buildHome({ ...base, lastScanAt: "2026-10-01T00:00:00Z", lastNetworkScanAt: null });
    expect(home.checks.find((c) => c.id === "last_scan")?.status).toBe("attention");
    expect(home.checks.find((c) => c.id === "network")?.status).toBe("unknown");
    expect(home.actions.map((a) => a.id)).toEqual(["quick_scan", "scan_network"]);
    expect(home.state).toBe("attention");
  });
});

describe("protocol and handlers", () => {
  it("parses requests strictly", () => {
    expect(parseRequest('{"id":3,"method":"home.get"}')).toEqual({ id: 3, method: "home.get", params: undefined });
    for (const bad of ["nope", "[]", '{"method":"home.get"}', '{"id":1,"method":"Home Get!"}']) expect(() => parseRequest(bad)).toThrow(IpcError);
  });

  it("only Home toggles can change, only to booleans", () => {
    expect(toggleChanges({ watchEnabled: false })).toEqual({ watchEnabled: false });
    expect(() => toggleChanges({ serverUrl: "https://evil.example" })).toThrow(/can't be changed/);
    expect(() => toggleChanges({ watchEnabled: "yes" })).toThrow(/true or false/);
    expect(() => toggleChanges({})).toThrow();
  });

  it("refuses to turn on what this system can't do", async () => {
    const host = { version: "t", homeInput: async () => ({ ...base, platform: "darwin" as const }), updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {} };
    const handlers = createHandlers(host, () => {});
    await expect(handlers["settings.set"]?.({ onAccessScan: true })).rejects.toThrow(/isn't available/);
  });
});

class Client {
  private buffer = "";
  private waiting = new Map<number, (value: Record<string, unknown>) => void>();
  readonly events: Record<string, unknown>[] = [];
  closed = false;
  private constructor(private readonly socket: Socket) {
    socket.setEncoding("utf8");
    socket.on("close", () => (this.closed = true));
    socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      let i: number;
      while ((i = this.buffer.indexOf("\n")) >= 0) {
        const message = JSON.parse(this.buffer.slice(0, i)) as Record<string, unknown>;
        this.buffer = this.buffer.slice(i + 1);
        if (typeof message.id === "number") this.waiting.get(message.id)?.(message);
        else this.events.push(message);
      }
    });
  }
  static connect(endpoint: string): Promise<Client> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(endpoint, () => resolve(new Client(socket)));
      socket.once("error", reject);
    });
  }
  private next = 1;
  call(method: string, params?: unknown): Promise<Record<string, unknown>> {
    const id = this.next++;
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.socket.write(`${JSON.stringify({ id, method, params })}\n`);
    });
  }
  end() {
    this.socket.end();
  }
}

const servers: IpcServer[] = [];
afterEach(async () => {
  while (servers.length) await servers.pop()?.close();
});

describe.skipIf(process.platform === "win32")("daemon over a Unix socket", () => {
  it("serves Home, applies toggles, broadcasts changes, and rejects strangers", { timeout: 30_000 }, async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "qalaa-daemon-"));
    const downloads = join(dataDir, "watched");
    await (await import("node:fs/promises")).mkdir(downloads);
    await writeFile(join(downloads, "notes.txt"), "hello");
    await writeFile(join(dataDir, "settings.json"), JSON.stringify({ watchFolders: [downloads], serverUrl: "http://127.0.0.1:9" }));
    const endpoint = join(dataDir, "d.sock");
    const paths = { ...ipcPaths("linux", { QALAA_IPC_ENDPOINT: endpoint }, dataDir) };

    const host = await createDaemonHost(dataDir);
    let server: IpcServer | null = null;
    const handlers = createHandlers(host, (event, payload) => server?.broadcast(event, payload));
    server = await startIpcServer(paths, handlers, { version: host.version });
    servers.push(server);

    // The token file is private to this user.
    expect((await stat(paths.tokenFile)).mode & 0o777).toBe(0o600);
    expect((await stat(endpoint)).mode & 0o777).toBe(0o600);
    const token = (await readFile(paths.tokenFile, "utf8")).trim();

    const stranger = await Client.connect(endpoint);
    const refused = await stranger.call("home.get");
    expect(refused.error).toMatchObject({ code: "unauthorized" });
    const wrong = await Client.connect(endpoint);
    expect((await wrong.call("hello", { token: "0".repeat(64) })).error).toMatchObject({ code: "unauthorized" });

    const client = await Client.connect(endpoint);
    expect((await client.call("hello", { token, client: "test" })).result).toMatchObject({ protocol: 1 });
    const home = (await client.call("home.get")).result as { toggles: { key: string; on: boolean }[] };
    expect(home.toggles.find((t) => t.key === "networkWatch")?.on).toBe(false);

    const updated = (await client.call("settings.set", { networkWatch: true })).result as { toggles: { key: string; on: boolean }[] };
    expect(updated.toggles.find((t) => t.key === "networkWatch")?.on).toBe(true);
    expect(JSON.parse(await readFile(join(dataDir, "settings.json"), "utf8")).networkWatch).toBe(true);
    expect(client.events.at(-1)).toMatchObject({ event: "home.changed" });

    expect((await client.call("settings.set", { serverUrl: "https://evil.example" })).error).toMatchObject({ code: "not_allowed" });
    expect((await client.call("vault.dump")).error).toMatchObject({ code: "unknown_method" });
    expect((await client.call("__proto__")).error).toMatchObject({ code: "bad_request" });

    const scan = (await client.call("scan.quick")).result as { scanned: number };
    expect(scan.scanned).toBe(1);
    // The Guardian pet reacts to these.
    const names = client.events.map((e) => e.event);
    expect(names.indexOf("scan.started")).toBeLessThan(names.indexOf("scan.finished"));
    expect(client.events.find((e) => e.event === "scan.finished")).toMatchObject({ payload: { scanned: 1, malicious: 0, suspicious: 0 } });
    expect(JSON.parse(await readFile(join(dataDir, "history.json"), "utf8"))).toHaveLength(1);

    // A second service on the same endpoint refuses to start.
    await expect(startIpcServer(paths, handlers, { version: "x" })).rejects.toThrow(/already running/);
    client.end();
    stranger.end();
    wrong.end();
  });
});
