/**
 * qalaa-ipc: the local protocol between the background service and the native
 * interface (apps/desktop-native/crates/qalaa-ipc mirrors these types).
 *
 * Newline-delimited JSON over a Unix domain socket (mode 0600) or a Windows
 * named pipe. The first message must be `hello` with the token from a file
 * only this user can read; anything else closes the connection.
 *
 *   -> {"id":1,"method":"hello","params":{"token":"…","client":"qalaa-command"}}
 *   <- {"id":1,"result":{"protocol":1,"version":"0.2.0"}}
 *   -> {"id":2,"method":"home.get"}
 *   <- {"id":2,"result":{…HomeModel…}}
 *   <- {"event":"home.changed","payload":{…HomeModel…}}
 */
export const PROTOCOL_VERSION = 1;
/** Longest accepted line; larger requests close the connection. */
export const MAX_LINE_BYTES = 256 * 1024;

export interface Request {
  id: number;
  method: string;
  params?: unknown;
}

export type Response = { id: number; result: unknown } | { id: number; error: { code: string; message: string } };

export interface EventMessage {
  event: string;
  payload: unknown;
}

export class IpcError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export function parseRequest(line: string): Request {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new IpcError("bad_json", "The request is not valid JSON.");
  }
  if (!value || typeof value !== "object") throw new IpcError("bad_request", "Expected an object.");
  const { id, method, params } = value as Record<string, unknown>;
  if (typeof id !== "number" || !Number.isInteger(id) || id < 0) throw new IpcError("bad_request", "Missing a numeric id.");
  if (typeof method !== "string" || !/^[a-z][a-z.-]{1,40}$/.test(method)) throw new IpcError("bad_request", "Missing a method name.");
  return { id, method, params };
}
