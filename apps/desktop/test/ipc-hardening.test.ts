import { mkdtemp, readFile, stat } from "node:fs/promises";
import { type Socket, createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { freshPipeName, ipcPaths, validPipeName } from "../src/core/paths";
import { type IpcServer, startIpcServer } from "../src/core/server";

const servers: IpcServer[] = [];
afterEach(async () => {
  while (servers.length) await servers.pop()?.close();
});

async function setup(limits?: { helloDeadlineMs?: number; maxUnauthenticated?: number }, endpointFile = false) {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-ipc-hard-"));
  const paths = { endpoint: join(dir, "d.sock"), socketDir: null, tokenFile: join(dir, "ipc-token"), endpointFile: endpointFile ? join(dir, "ipc-endpoint") : null };
  const server = await startIpcServer(paths, { "test.slow": () => new Promise((r) => setTimeout(() => r("done"), 200)), "test.ping": async () => "pong" }, { version: "t" }, limits);
  servers.push(server);
  return { dir, paths, server, token: (await readFile(paths.tokenFile, "utf8")).trim() };
}

function open(endpoint: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(endpoint, () => resolve(socket));
    socket.once("error", reject);
  });
}

function closed(socket: Socket, withinMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    if (socket.destroyed) return resolve(true);
    const timer = setTimeout(() => resolve(false), withinMs);
    socket.once("close", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

function call(socket: Socket, id: number, method: string, params?: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString();
      for (const line of buffer.split("\n").slice(0, -1)) {
        const message = JSON.parse(line) as Record<string, unknown>;
        if (message.id === id) {
          socket.off("data", onData);
          resolve(message);
        }
      }
    };
    socket.on("data", onData);
    socket.write(`${JSON.stringify({ id, method, params })}\n`);
  });
}

describe.skipIf(process.platform === "win32")("qalaa-ipc connection limits", () => {
  it("closes a connection that doesn't say hello in time, and refuses anything before hello", async () => {
    const { paths, token } = await setup({ helloDeadlineMs: 150 });
    const silent = await open(paths.endpoint);
    expect(await closed(silent, 1000)).toBe(true);

    const early = await open(paths.endpoint);
    const refused = await call(early, 1, "test.ping");
    expect(refused).toMatchObject({ error: { code: "unauthorized" } });
    expect(await closed(early, 1000)).toBe(true);

    const wrong = await open(paths.endpoint);
    expect(await call(wrong, 1, "hello", { token: "0".repeat(64) })).toMatchObject({ error: { code: "unauthorized" } });

    // Authenticated: the deadline no longer applies.
    const good = await open(paths.endpoint);
    expect(await call(good, 1, "hello", { token })).toMatchObject({ result: { protocol: expect.any(Number) } });
    await new Promise((r) => setTimeout(r, 300));
    expect(await call(good, 2, "test.ping")).toEqual({ id: 2, result: "pong" });
    good.end();
  });

  it("refuses more than a few connections waiting to authenticate (exhaustion)", async () => {
    const { paths, token } = await setup({ maxUnauthenticated: 3, helloDeadlineMs: 5000 });
    const idle = await Promise.all([1, 2, 3].map(() => open(paths.endpoint)));
    const extra = await open(paths.endpoint);
    expect(await closed(extra, 1000)).toBe(true);
    // Once one of them leaves, a real client gets in and authenticates.
    idle[0]!.destroy();
    await new Promise((r) => setTimeout(r, 50));
    const good = await open(paths.endpoint);
    expect(await call(good, 1, "hello", { token })).toHaveProperty("result");
    for (const s of idle.slice(1)) s.destroy();
    good.end();
  });

  it("serves concurrent clients, and survives a client that disappears mid-request", async () => {
    const { paths, token } = await setup();
    const a = await open(paths.endpoint);
    const b = await open(paths.endpoint);
    await call(a, 1, "hello", { token });
    await call(b, 1, "hello", { token });
    a.write(`${JSON.stringify({ id: 2, method: "test.slow" })}\n`);
    a.destroy(); // gone before the answer
    const [one, two] = await Promise.all([call(b, 2, "test.slow"), call(b, 3, "test.ping")]);
    expect(one).toEqual({ id: 2, result: "done" });
    expect(two).toEqual({ id: 3, result: "pong" });
    b.end();
  });

  it("publishes this run's endpoint in a private file, and removes it on close", async () => {
    const { paths, server } = await setup({}, true);
    expect((await readFile(paths.endpointFile!, "utf8")).trim()).toBe(paths.endpoint);
    expect((await stat(paths.endpointFile!)).mode & 0o077).toBe(0);
    servers.pop();
    await server.close();
    await expect(stat(paths.endpointFile!)).rejects.toThrow();
  });
});

describe("Windows pipe names", () => {
  it("are fresh on every start and can't be guessed", () => {
    const dir = String.raw`C:\Users\sara\AppData\Roaming\Qalaa Desktop`;
    const a = ipcPaths("win32", { USERNAME: "Sara K" }, dir);
    const b = ipcPaths("win32", { USERNAME: "Sara K" }, dir);
    expect(a.endpoint).not.toBe(b.endpoint);
    expect(a.endpoint).toMatch(/^\\\\\.\\pipe\\qalaa-daemon-Sara_K-[0-9a-f]{32}$/);
    expect(a.endpointFile?.endsWith("ipc-endpoint")).toBe(true);
    expect(validPipeName(a.endpoint)).toBe(true);
    expect(validPipeName(freshPipeName("x", "0".repeat(32)))).toBe(true);
    // Only a name this service could have written: no other pipe, the old fixed name, a path or extra text.
    for (const bad of [String.raw`\\.\pipe\qalaa-daemon-Sara`, String.raw`\\.\pipe\other-` + "a".repeat(32), String.raw`C:\evil.sock`, `${a.endpoint}\nx`]) {
      expect(validPipeName(bad)).toBe(false);
    }
  });
});
