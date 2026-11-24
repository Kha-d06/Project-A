/** Where the background service listens, and where its token lives, per OS. */
import { homedir, tmpdir, userInfo } from "node:os";
import { join } from "node:path";

export interface IpcPaths {
  /** Unix socket path, or a Windows named pipe name. */
  endpoint: string;
  /** Directory that holds the socket (Unix only); created with mode 0700. */
  socketDir: string | null;
  tokenFile: string;
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
  if (env.QALAA_IPC_ENDPOINT) return { endpoint: env.QALAA_IPC_ENDPOINT, socketDir: null, tokenFile };
  if (platform === "win32") {
    const user = (env.USERNAME ?? userInfo().username).replace(/[^A-Za-z0-9_-]/g, "_");
    return { endpoint: `\\\\.\\pipe\\qalaa-daemon-${user}`, socketDir: null, tokenFile };
  }
  const base = env.XDG_RUNTIME_DIR ?? (platform === "darwin" ? dataDir : join(tmpdir(), `qalaa-${userInfo().uid}`));
  const socketDir = platform === "darwin" ? dataDir : join(base, "qalaa");
  return { endpoint: join(socketDir, "daemon.sock"), socketDir, tokenFile };
}
