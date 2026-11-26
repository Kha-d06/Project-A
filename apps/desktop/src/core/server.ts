/**
 * The qalaa-ipc server. Shared by the headless daemon and the Electron shell.
 * Clients must say `hello` with the token first; requests are answered in
 * order per connection; events go to every authenticated client.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { type Server, type Socket, createConnection, createServer } from "node:net";

import type { Handler } from "./handlers";
import { type IpcPaths, validPipeName } from "./paths";
import { type EventMessage, IpcError, MAX_LINE_BYTES, PROTOCOL_VERSION, type Response, parseRequest } from "./protocol";

/** A connection that hasn't said hello with the token by then is closed. */
export const HELLO_DEADLINE_MS = 5_000;
/** Connections at once, and of those, ones that haven't authenticated yet. */
export const MAX_CONNECTIONS = 64;
export const MAX_UNAUTHENTICATED = 8;

export interface IpcServer {
  broadcast(event: string, payload: unknown): void;
  close(): Promise<void>;
  clients(): number;
}

/** Reads the token, creating one (mode 0600) the first time. */
export async function loadToken(file: string): Promise<string> {
  try {
    const existing = (await readFile(file, "utf8")).trim();
    if (/^[a-f0-9]{64}$/.test(existing)) return existing;
  } catch {
    // create below
  }
  const token = randomBytes(32).toString("hex");
  await writeFile(file, token, { mode: 0o600 });
  await chmod(file, 0o600).catch(() => undefined);
  return token;
}

/** The id of a request, even one that fails validation, so the client gets its answer. */
function requestId(line: string): number {
  try {
    const id = (JSON.parse(line) as { id?: unknown }).id;
    return typeof id === "number" && Number.isInteger(id) && id >= 0 ? id : 0;
  } catch {
    return 0;
  }
}

function sameToken(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * The socket's folder must belong to this user and be closed to everyone else,
 * and so must its parent unless root owns it. Otherwise another user who created
 * the folder first (the /tmp fallback when XDG_RUNTIME_DIR isn't set) could
 * swap the socket and collect the token from the next client.
 */
export async function assertPrivateDir(dir: string, uid: number | undefined = process.getuid?.()): Promise<void> {
  if (uid === undefined) return; // Windows: no socket folder
  const info = await lstat(dir);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${dir} isn't a plain folder, so the background service won't listen there.`);
  if (info.uid !== uid) throw new Error(`${dir} belongs to another user, so the background service won't listen there.`);
  if (info.mode & 0o077) throw new Error(`${dir} can be opened by other users, so the background service won't listen there.`);
  const parent = await lstat(dirname(dir));
  if (parent.uid !== uid && parent.uid !== 0) throw new Error(`${dirname(dir)} belongs to another user, so the background service won't listen there.`);
  if (parent.uid === uid && parent.mode & 0o022) throw new Error(`Other users can write to ${dirname(dir)}, so the background service won't listen there.`);
}

/** True when another process already answers on this endpoint. */
export function endpointInUse(endpoint: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createConnection(endpoint);
    probe.once("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.once("error", () => resolve(false));
  });
}

export async function startIpcServer(
  paths: IpcPaths,
  handlers: Record<string, Handler>,
  info: { version: string },
  limits: { helloDeadlineMs?: number; maxUnauthenticated?: number } = {},
): Promise<IpcServer> {
  const helloDeadlineMs = limits.helloDeadlineMs ?? HELLO_DEADLINE_MS;
  const maxUnauthenticated = limits.maxUnauthenticated ?? MAX_UNAUTHENTICATED;
  const token = await loadToken(paths.tokenFile);
  if (await endpointInUse(paths.endpoint)) throw new Error("Another Qalaa background service is already running.");
  // Windows: this run's pipe has a fresh random name; a previous run's is in the endpoint file.
  if (paths.endpointFile) {
    const previous = (await readFile(paths.endpointFile, "utf8").catch(() => "")).trim();
    if (validPipeName(previous) && (await endpointInUse(previous))) throw new Error("Another Qalaa background service is already running.");
  }
  if (paths.socketDir) {
    await mkdir(paths.socketDir, { recursive: true, mode: 0o700 });
    await chmod(paths.socketDir, 0o700).catch(() => undefined);
    await assertPrivateDir(paths.socketDir);
  }
  // A stale socket file from a crash; endpointInUse() showed nobody answers on it.
  if (process.platform !== "win32") await rm(paths.endpoint, { force: true });
  const authed = new Set<Socket>();

  const send = (socket: Socket, message: Response | EventMessage) => {
    if (!socket.destroyed) socket.write(`${JSON.stringify(message)}\n`);
  };

  let unauthenticated = 0;
  const server: Server = createServer((socket) => {
    // Too many connections still waiting to say hello: refuse more (exhaustion).
    if (unauthenticated >= maxUnauthenticated) {
      socket.destroy();
      return;
    }
    unauthenticated += 1;
    let counted = true;
    const authenticated = () => {
      if (counted) unauthenticated -= 1;
      counted = false;
      clearTimeout(deadline);
    };
    const deadline = setTimeout(() => {
      if (!authed.has(socket)) socket.destroy();
    }, helloDeadlineMs);
    deadline.unref?.();
    let buffer = "";
    let queue = Promise.resolve();
    socket.setEncoding("utf8");
    socket.on("error", () => socket.destroy());
    socket.on("close", () => {
      authed.delete(socket);
      authenticated();
    });
    socket.once("qalaa:authenticated", authenticated);
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > MAX_LINE_BYTES && !buffer.includes("\n")) {
        socket.destroy();
        return;
      }
      let newline: number;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        queue = queue.then(() => handle(socket, line));
      }
    });
  });

  async function handle(socket: Socket, line: string) {
    let id = requestId(line);
    try {
      const request = parseRequest(line);
      id = request.id;
      if (!authed.has(socket)) {
        const given = (request.params as { token?: unknown } | undefined)?.token;
        if (request.method !== "hello" || typeof given !== "string" || !sameToken(given, token)) {
          send(socket, { id, error: { code: "unauthorized", message: "Say hello with the token first." } });
          socket.end();
          return;
        }
        authed.add(socket);
        // Counted as authenticated from here (the deadline no longer applies).
        socket.emit("qalaa:authenticated");
        send(socket, { id, result: { protocol: PROTOCOL_VERSION, version: info.version } });
        return;
      }
      const handler = Object.hasOwn(handlers, request.method) ? handlers[request.method] : undefined;
      if (!handler) throw new IpcError("unknown_method", `No method "${request.method}".`);
      send(socket, { id, result: await handler(request.params) });
    } catch (error) {
      const code = error instanceof IpcError ? error.code : "failed";
      const message = error instanceof Error ? error.message : String(error);
      send(socket, { id, error: { code, message } });
    }
  }

  server.maxConnections = MAX_CONNECTIONS;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(paths.endpoint, () => resolve());
  });
  if (process.platform !== "win32") await chmod(paths.endpoint, 0o600).catch(() => undefined);
  // Published only after the pipe exists, readable only by this user (the data folder's ACL).
  if (paths.endpointFile) {
    const temporary = `${paths.endpointFile}.${process.pid}.tmp`;
    await writeFile(temporary, paths.endpoint, { mode: 0o600 });
    await rename(temporary, paths.endpointFile);
  }

  return {
    broadcast(event, payload) {
      for (const socket of authed) send(socket, { event, payload });
    },
    clients: () => authed.size,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of authed) socket.destroy();
        server.close(() => {
          // Remove the endpoint file only if it still names this run's pipe.
          if (!paths.endpointFile) return resolve();
          void readFile(paths.endpointFile, "utf8")
            .then((current) => (current.trim() === paths.endpoint ? rm(paths.endpointFile!, { force: true }) : undefined))
            .catch(() => undefined)
            .finally(() => resolve());
        });
      }),
  };
}
