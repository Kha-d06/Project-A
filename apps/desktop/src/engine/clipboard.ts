/**
 * Clipboard auto-clear.
 *
 * When a secret is on the clipboard (copied from Qalaa, or recognised by its
 * shape: a private key, a cloud or API token, a .env line, a long random
 * string), it is wiped after a short time, default 30 seconds. It is only
 * cleared if the clipboard still holds that same secret, compared by hash, so
 * something copied afterwards is never lost. The text itself is never logged,
 * stored or sent anywhere; only its kind ("private key") is shown.
 *
 * The clipboard is read and cleared with the system's own tools (no Electron),
 * so the headless service can do it: wl-paste/wl-copy or xclip on Linux,
 * PowerShell on Windows, pbpaste/pbcopy on macOS.
 */
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";

export type SecretKind = "private_key" | "cloud_key" | "api_token" | "jwt" | "env_secret" | "high_entropy" | "copied_from_qalaa";

/** Shannon entropy in bits per character. */
export function entropy(text: string): number {
  if (!text) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / text.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export const PATTERNS: [SecretKind, RegExp][] = [
  ["private_key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/],
  ["cloud_key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b/],
  ["api_token", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b|\bxox[abposr]-[A-Za-z0-9-]{10,}\b|\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b|\bsk_live_[A-Za-z0-9]{20,}\b|\bglpat-[A-Za-z0-9_-]{20,}\b/],
  ["jwt", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
];

/**
 * `NAME=value` where the name says it is a secret. Checked line by line with a
 * bounded name: the earlier single pattern ("[A-Z0-9_]*SECRET[A-Z0-9_]*")
 * backtracked quadratically, 0.6 s on 64 KB of "XSECRET" (test/regex-safety).
 */
export const ENV_LINE = /^\s{0,16}(?:export\s{1,4})?([A-Z][A-Z0-9_]{0,99})\s{0,4}=\s{0,4}\S{8}/;
export const ENV_SECRET_NAME = /SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL/;

function envSecret(text: string): boolean {
  for (const line of text.split("\n", 4_000)) {
    if (line.length > 4_096) continue;
    const m = ENV_LINE.exec(line);
    if (m && ENV_SECRET_NAME.test(m[1]!)) return true;
  }
  return false;
}

/** What kind of secret the text looks like, or null for ordinary text. */
export function classifySecret(text: string): SecretKind | null {
  if (!text || text.length > 64 * 1024) return null;
  for (const [kind, pattern] of PATTERNS) if (pattern.test(text)) return kind;
  if (envSecret(text)) return "env_secret";
  const token = text.trim();
  // A single long random-looking word: a password or key with no recognisable prefix.
  if (token.length >= 20 && token.length <= 512 && !/\s/.test(token) && !/^https?:\/\//i.test(token)) {
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(token)).length;
    if (classes >= 3 && entropy(token) >= 4) return "high_entropy";
  }
  return null;
}

export function digest(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export interface ClipboardIo {
  read(): Promise<string | null>;
  clear(): Promise<void>;
  /** Puts text on the clipboard (Qalaa's own "copy secret"). */
  write(text: string): Promise<void>;
}

function run(command: string, args: string[], input?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { timeout: 5_000, windowsHide: true, maxBuffer: 1024 * 1024 }, (error, stdout) => (error ? reject(error) : resolve(String(stdout))));
    if (input !== undefined) child.stdin?.end(input);
  });
}

/**
 * Feeds `input` to a clipboard writer and waits for it to exit. Its output is
 * not captured: xclip and wl-copy fork a child that keeps serving the clipboard,
 * and a captured pipe would stay open as long as that child lives.
 */
function feed(command: string, args: string[], input: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "ignore", "ignore"], windowsHide: true });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${command} timed out`));
    }, 5_000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`${command} exited with ${code}`));
    });
    child.stdin.end(input);
  });
}

/** The system clipboard via the platform's own tools; null where none is available. */
export function systemClipboard(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): ClipboardIo | null {
  if (platform === "darwin") {
    return { read: () => run("pbpaste", []).catch(() => null), clear: () => feed("pbcopy", [], ""), write: (t) => feed("pbcopy", [], t) };
  }
  if (platform === "win32") {
    const ps = (script: string, input?: string) => run("powershell.exe", ["-NoProfile", "-NonInteractive", "-STA", "-Command", script], input);
    return {
      read: () => ps("Get-Clipboard -Raw").catch(() => null),
      clear: () => ps("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::Clear()").then(() => undefined),
      write: (t) => feed("powershell.exe", ["-NoProfile", "-NonInteractive", "-STA", "-Command", "$input | Set-Clipboard"], t),
    };
  }
  if (platform === "linux") {
    if (env.WAYLAND_DISPLAY) {
      return { read: () => run("wl-paste", ["--no-newline"]).catch(() => null), clear: () => feed("wl-copy", ["--clear"], ""), write: (t) => feed("wl-copy", [], t) };
    }
    if (env.DISPLAY) {
      return {
        read: () => run("xclip", ["-selection", "clipboard", "-o"]).catch(() => null),
        clear: () => feed("xclip", ["-selection", "clipboard", "-i"], ""),
        write: (t) => feed("xclip", ["-selection", "clipboard", "-i"], t),
      };
    }
  }
  return null;
}
