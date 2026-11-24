/**
 * Credential guardrails: notice when a program that has no business doing so
 * reads SSH keys, .env files, cloud credentials or a browser's cookie and
 * password stores. Information stealers and rogue AI agents and scripts go
 * after exactly these files.
 *
 * Pure rules here (which paths are credentials, which programs may read them),
 * plus read-only sources of "who has what open":
 * - Linux: every open, from the fanotify on-access helper when it is installed,
 *   and /proc/<pid>/fd of the person's own processes (no root needed);
 * - macOS: `lsof` for the person's processes.
 * Polling sees files a program keeps open; a read that starts and finishes
 * between two looks can be missed. The fanotify source sees every open.
 */
import { readFile, readdir, readlink } from "node:fs/promises";
import { basename, sep } from "node:path";

export type CredentialKind = "ssh_key" | "env_file" | "cloud_credentials" | "browser_secrets";

/** Files under ~/.ssh that are public or not secret. */
const SSH_PUBLIC = /(\.pub|^known_hosts(\.old)?|^authorized_keys2?|^config)$/;
const ENV_EXAMPLES = /\.(example|sample|template|dist|defaults)$/i;
const CLOUD_FILES = [
  ".aws/credentials",
  ".config/gcloud/credentials.db",
  ".config/gcloud/application_default_credentials.json",
  ".kube/config",
  ".docker/config.json",
  ".netrc",
  ".git-credentials",
  ".npmrc",
  ".pypirc",
  ".azure/msal_token_cache.json",
];
const BROWSER_FILES = new Set(["Cookies", "Login Data", "Web Data", "Local State", "cookies.sqlite", "logins.json", "key4.db", "key3.db"]);
const BROWSER_ROOTS = [
  ".config/google-chrome",
  ".config/chromium",
  ".config/BraveSoftware",
  ".config/microsoft-edge",
  ".mozilla/firefox",
  "Library/Application Support/Google/Chrome",
  "Library/Application Support/BraveSoftware",
  "Library/Application Support/Microsoft Edge",
  "Library/Application Support/Firefox",
  "snap/firefox/common/.mozilla/firefox",
];

/** What kind of credential `path` is, or null. `home` is the user's home folder. */
export function credentialKind(path: string, home: string): CredentialKind | null {
  const p = path.split(sep).join("/");
  const h = home.split(sep).join("/").replace(/\/$/, "");
  const name = basename(p);
  if (p.startsWith(`${h}/.ssh/`) && !SSH_PUBLIC.test(name)) return "ssh_key";
  if (/^\.env(\.[\w.-]+)?$/.test(name) && !ENV_EXAMPLES.test(name)) return "env_file";
  if (!p.startsWith(`${h}/`)) return null;
  const rel = p.slice(h.length + 1);
  if (CLOUD_FILES.includes(rel)) return "cloud_credentials";
  if (BROWSER_FILES.has(name) && BROWSER_ROOTS.some((root) => rel.startsWith(`${root}/`))) return "browser_secrets";
  return null;
}

/** Programs expected to read each kind (matched on the executable's name). */
export const DEFAULT_ALLOWLIST: Record<CredentialKind, string[]> = {
  ssh_key: ["ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp", "sshd", "git", "gpg", "gpg-agent", "rsync", "mosh-client", "gnome-keyring-daemon", "seahorse", "qalaa"],
  env_file: ["code", "codium", "cursor", "idea", "pycharm", "webstorm", "goland", "clion", "rider", "nvim", "vim", "vi", "nano", "emacs", "micro", "hx", "subl", "gedit", "kate", "git", "docker", "docker-compose", "qalaa"],
  cloud_credentials: ["aws", "gcloud", "kubectl", "helm", "k9s", "docker", "docker-credential-desktop", "git", "git-credential-libsecret", "npm", "pip", "twine", "az", "terraform", "qalaa"],
  browser_secrets: ["chrome", "google-chrome", "chromium", "chromium-browser", "brave", "brave-browser", "microsoft-edge", "msedge", "firefox", "firefox-bin", "Google Chrome", "Brave Browser", "Microsoft Edge", "qalaa"],
};

/** Normalised program name: "/usr/bin/python3.12" → "python3.12", "Google Chrome Helper" kept. */
export function programName(exe: string): string {
  return basename(exe.replace(/ \(deleted\)$/, "")).trim();
}

/** Allowed when the program is on the default list for that kind or trusted by the person. */
export function isAllowed(kind: CredentialKind, exe: string, trusted: string[]): boolean {
  const name = programName(exe);
  if (trusted.includes(exe) || trusted.includes(name)) return true;
  const base = name.toLowerCase();
  return DEFAULT_ALLOWLIST[kind].some((allowed) => {
    const a = allowed.toLowerCase();
    // "Google Chrome Helper (Renderer)" belongs to Chrome; "git-remote-https" to git.
    return base === a || base.startsWith(`${a} `) || base.startsWith(`${a}-`);
  });
}

/** "~/.ssh/id_ed25519" for display: the home folder is never shown in full. */
export function displayPath(path: string, home: string): string {
  return path.startsWith(`${home}/`) ? `~/${path.slice(home.length + 1)}` : path;
}

export interface OpenFile {
  pid: number;
  exe: string;
  path: string;
}

/** macOS `lsof -u <user> -Fpcn -n -P`: p<pid>, c<command>, n<name> lines. */
export function parseLsof(text: string): OpenFile[] {
  const files: OpenFile[] = [];
  let pid = 0;
  let command = "";
  for (const line of text.split("\n")) {
    if (line.startsWith("p")) pid = Number(line.slice(1));
    else if (line.startsWith("c")) command = line.slice(1);
    else if (line.startsWith("n/") && pid > 0) files.push({ pid, exe: command, path: line.slice(1) });
  }
  return files;
}

/**
 * Linux: open files of the person's own processes from /proc. Reading another
 * user's /proc/<pid>/fd is refused by the kernel, which is fine: those are
 * skipped.
 */
export async function procOpenFiles(filter: (path: string) => boolean, proc = "/proc"): Promise<OpenFile[]> {
  const out: OpenFile[] = [];
  const pids = (await readdir(proc).catch(() => [] as string[])).filter((d) => /^\d+$/.test(d));
  await Promise.all(
    pids.map(async (pid) => {
      const fds = await readdir(`${proc}/${pid}/fd`).catch(() => null);
      if (!fds) return;
      let exe: string | null = null;
      for (const fd of fds) {
        const target = await readlink(`${proc}/${pid}/fd/${fd}`).catch(() => null);
        if (!target || !target.startsWith("/") || !filter(target)) continue;
        exe ??= await readlink(`${proc}/${pid}/exe`).catch(async () => (await readFile(`${proc}/${pid}/comm`, "utf8").catch(() => "unknown")).trim());
        out.push({ pid: Number(pid), exe, path: target });
      }
    }),
  );
  return out;
}

/** The executable a process runs now, to guard against a reused process id. */
export async function exeOf(pid: number, platform: NodeJS.Platform = process.platform, proc = "/proc"): Promise<string | null> {
  if (platform === "linux") return readlink(`${proc}/${pid}/exe`).catch(async () => (await readFile(`${proc}/${pid}/comm`, "utf8").catch(() => "")).trim() || null);
  return null;
}
