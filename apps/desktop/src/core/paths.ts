/** Where the background service listens, and where its token lives, per OS. */
import { randomBytes } from "node:crypto";
import { homedir, tmpdir, userInfo } from "node:os";
import { join } from "node:path";

export interface IpcPaths {
  /** Unix socket path, or a Windows named pipe name. */
  endpoint: string;
  /** Directory that holds the socket (Unix only); created with mode 0700. */
  socketDir: string | null;
  tokenFile: string;
  /**
   * Windows only: the file (in the user's own data folder) that names this run's
   * pipe. The name has 128 random bits and changes every start, so another user
   * can't create the pipe first: they can't know what it will be called.
   */
  endpointFile: string | null;
}

/** A pipe name for one run of the service: the user's name plus 128 random bits. */
export function freshPipeName(user: string, random: string = randomBytes(16).toString("hex")): string {
  return `\\\\.\\pipe\\qalaa-daemon-${user.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64)}-${random}`;
}

/** Accepts only a pipe name this service could have written (the client checks the same). */
export function validPipeName(name: string): boolean {
  return /^\\\\\.\\pipe\\qalaa-daemon-[A-Za-z0-9_-]{0,64}-[0-9a-f]{32}$/.test(name);
}

export function dataDirFor(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  if (env.QALAA_DATA_DIR) return env.QALAA_DATA_DIR;
  if (env.SENTINEL_DESKTOP_PROFILE) return env.SENTINEL_DESKTOP_PROFILE;
  // The packaged Electron app's userData folder, so both read the same files.
  const name = "Qalaa Desktop";
  if (platform === "win32") return join(env.APPDATA ?? join(homedir(), "AppData", "Roaming"), name);
  if (platform === "darwin") return join(homedir(), "Library", "Application Support", name);
  return join(env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), name);
}

export function ipcPaths(platform: NodeJS.Platform, env: NodeJS.ProcessEnv, dataDir: string): IpcPaths {
  const tokenFile = join(dataDir, "ipc-token");
  if (env.QALAA_IPC_ENDPOINT) return { endpoint: env.QALAA_IPC_ENDPOINT, socketDir: null, tokenFile, endpointFile: null };
  if (platform === "win32") {
    return { endpoint: freshPipeName(env.USERNAME ?? userInfo().username), socketDir: null, tokenFile, endpointFile: join(dataDir, "ipc-endpoint") };
  }
  const base = env.XDG_RUNTIME_DIR ?? (platform === "darwin" ? dataDir : join(tmpdir(), `qalaa-${userInfo().uid}`));
  const socketDir = platform === "darwin" ? dataDir : join(base, "qalaa");
  return { endpoint: join(socketDir, "daemon.sock"), socketDir, tokenFile, endpointFile: null };
}
