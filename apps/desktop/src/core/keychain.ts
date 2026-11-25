/**
 * A small keychain for the background service, which has no Electron
 * safeStorage. One secret per name, kept by the operating system:
 *
 * - Linux: the Secret Service (GNOME Keyring, KWallet) through `secret-tool`.
 * - macOS: the login Keychain through `security`, in its interactive mode so
 *   the secret is never a command-line argument.
 * - Windows: DPAPI (ConvertFrom-SecureString), which only this Windows user
 *   can decrypt; the encrypted blob is kept in the service's data folder.
 *
 * The secret always travels on standard input, never in argv where other
 * processes could read it. Where none of these is available, `available()` is
 * false and the caller keeps the secret in memory for this session only, and
 * says so.
 */
import { execFile } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const SERVICE = "qalaa";

/** Runs a command with `input` on stdin; resolves with stdout. */
export type StdinRunner = (command: string, args: string[], input: string) => Promise<string>;

export const runWithStdin: StdinRunner = (command, args, input) =>
  new Promise((resolve, reject) => {
    const child = execFile(command, args, { timeout: 20_000, windowsHide: true, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) =>
      error ? reject(new Error(String(stderr || error.message).trim().slice(0, 300))) : resolve(String(stdout)),
    );
    child.stdin?.end(input);
  });

export interface Keychain {
  available(): Promise<boolean>;
  get(name: string): Promise<string | null>;
  set(name: string, secret: string): Promise<void>;
  remove(name: string): Promise<void>;
}

/** A name safe to pass as an argument or a file name. */
function checkName(name: string): string {
  if (!/^[a-z0-9_.-]{1,64}$/.test(name)) throw new Error("Bad keychain entry name.");
  return name;
}

/** The secret goes in a quoted single line; keychain tools can't take newlines. */
function checkSecret(secret: string): string {
  if (!secret || secret.length > 4096 || /[\r\n\0]/.test(secret)) throw new Error("That password can't be stored.");
  return secret;
}

export function systemKeychain(platform: NodeJS.Platform, dataDir: string, run: StdinRunner = runWithStdin): Keychain {
  if (platform === "linux") {
    return {
      available: () => run("sh", ["-c", "command -v secret-tool"], "").then(() => true, () => false),
      get: (name) => run("secret-tool", ["lookup", "service", SERVICE, "account", checkName(name)], "").then((out) => out.replace(/\n$/, "") || null, () => null),
      set: async (name, secret) => {
        await run("secret-tool", ["store", "--label", `Qalaa: ${checkName(name)}`, "service", SERVICE, "account", name], checkSecret(secret));
      },
      remove: async (name) => {
        await run("secret-tool", ["clear", "service", SERVICE, "account", checkName(name)], "").catch(() => undefined);
      },
    };
  }
  if (platform === "darwin") {
    // `security -i` reads commands from stdin; the secret is quoted inside that line, not in argv.
    const quote = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    return {
      available: () => run("sh", ["-c", "command -v security"], "").then(() => true, () => false),
      get: (name) => run("security", ["find-generic-password", "-s", SERVICE, "-a", checkName(name), "-w"], "").then((out) => out.replace(/\n$/, "") || null, () => null),
      set: async (name, secret) => {
        await run("security", ["-i"], `add-generic-password -U -s ${SERVICE} -a ${checkName(name)} -w ${quote(checkSecret(secret))}\n`);
      },
      remove: async (name) => {
        await run("security", ["delete-generic-password", "-s", SERVICE, "-a", checkName(name)], "").catch(() => undefined);
      },
    };
  }
  if (platform === "win32") {
    const file = (name: string) => join(dataDir, `${checkName(name)}.dpapi`);
    const ps = (script: string, input: string) => run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], input);
    return {
      available: async () => true,
      get: async (name) => {
        const blob = await readFile(file(name), "utf8").catch(() => null);
        if (!blob) return null;
        const script = "$b=[Console]::In.ReadLine(); $s=ConvertTo-SecureString $b; [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))";
        return ps(script, `${blob.trim()}\n`).then((out) => out.replace(/\r?\n$/, "") || null, () => null);
      },
      set: async (name, secret) => {
        const script = "$p=[Console]::In.ReadLine(); ConvertTo-SecureString $p -AsPlainText -Force | ConvertFrom-SecureString";
        const blob = (await ps(script, `${checkSecret(secret)}\n`)).trim();
        if (!/^[0-9a-f]+$/i.test(blob)) throw new Error("Windows couldn't protect the password.");
        await writeFile(file(name), blob, { mode: 0o600 });
      },
      remove: (name) => rm(file(name), { force: true }),
    };
  }
  return { available: async () => false, get: async () => null, set: async () => Promise.reject(new Error("No keychain on this system.")), remove: async () => {} };
}
