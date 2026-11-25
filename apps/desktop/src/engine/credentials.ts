/**
 * Credential guardrails: notice when a program that has no business doing so
 * reads SSH keys, .env files, cloud credentials, a browser's cookie and
 * password stores, keychains, password-manager databases, crypto wallets or
 * chat-app session tokens. Information stealers and rogue scripts go after
 * exactly these files. The paths follow SigmaHQ's credential-access rules
 * (Detection Rule License 1.1; adapted, not copied).
 *
 * Who counts as expected is decided in two steps:
 * 1. the program's name is on the default list for that kind of file, and
 * 2. it lives where the person's own programs can't have put it: on Linux the
 *    binary and every folder above it belong to root and aren't writable by
 *    others; on macOS it's a system path protected by SIP, or it carries a
 *    valid Apple or Developer ID signature. (Checked in the service, which
 *    can look at the disk.)
 * A program the person allowed is trusted by its full path and SHA-256, so a
 * look-alike in another folder, or a changed binary, is still reported.
 */
import { readFile, readdir, readlink } from "node:fs/promises";
import { basename, sep } from "node:path";

export type CredentialKind =
  | "ssh_key"
  | "env_file"
  | "cloud_credentials"
  | "browser_secrets"
  /** A Chromium browser's "Local State": holds the key that decrypts its saved passwords and cookies. */
  | "browser_key"
  | "keychain"
  | "password_manager"
  | "crypto_wallet"
  | "messaging_tokens"
  | "system_secrets"
  | "windows_credentials";

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
  ".config/gh/hosts.yml",
  ".terraform.d/credentials.tfrc.json",
];
const BROWSER_FILES = new Set(["cookies", "login data", "web data", "cookies.sqlite", "logins.json", "key4.db", "key3.db"]);
const BROWSER_ROOTS = [
  ".config/google-chrome/",
  ".config/chromium/",
  ".config/bravesoftware/",
  ".config/microsoft-edge/",
  ".mozilla/firefox/",
  "snap/firefox/common/.mozilla/firefox/",
  "library/application support/google/chrome/",
  "library/application support/bravesoftware/",
  "library/application support/microsoft edge/",
  "library/application support/firefox/",
  "appdata/local/google/chrome/user data/",
  "appdata/local/microsoft/edge/user data/",
  "appdata/local/bravesoftware/brave-browser/user data/",
  "appdata/roaming/mozilla/firefox/profiles/",
];
/** MetaMask's extension id; its vault lives in the browser profile. */
const METAMASK = "/local extension settings/nkbihfbeogaeaoehlefnkodbefgpgknn/";
const WALLET_ROOTS = [
  ".electrum/wallets/",
  "appdata/roaming/electrum/wallets/",
  ".config/exodus/exodus.wallet/",
  "library/application support/exodus/exodus.wallet/",
  "appdata/roaming/exodus/exodus.wallet/",
  ".ethereum/keystore/",
  "library/ethereum/keystore/",
  "appdata/roaming/ethereum/keystore/",
];
const MESSAGING_ROOTS = [
  ".config/discord/local storage/leveldb/",
  "library/application support/discord/local storage/leveldb/",
  "appdata/roaming/discord/local storage/leveldb/",
  ".local/share/telegramdesktop/tdata/",
  "library/application support/telegram desktop/tdata/",
  "appdata/roaming/telegram desktop/tdata/",
];
const WINDOWS_CREDENTIAL_ROOTS = [
  "appdata/roaming/microsoft/credentials/",
  "appdata/local/microsoft/credentials/",
  "appdata/roaming/microsoft/protect/",
  "appdata/local/microsoft/vault/",
];
const SYSTEM_SECRETS = new Set(["/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-"]);

/** What kind of credential `path` is, or null. `home` is the user's home folder. */
export function credentialKind(path: string, home: string): CredentialKind | null {
  const p = path.split(sep).join("/").replace(/\\/g, "/");
  const h = home.split(sep).join("/").replace(/\\/g, "/").replace(/\/$/, "");
  const name = basename(p);
  if (SYSTEM_SECRETS.has(p)) return "system_secrets";
  if (p.startsWith(`${h}/.ssh/`) && !SSH_PUBLIC.test(name)) return "ssh_key";
  if (/^\.env(\.[\w.-]+)?$/.test(name) && !ENV_EXAMPLES.test(name)) return "env_file";
  if (/\.kdbx$/i.test(name)) return "password_manager";
  if (!p.toLowerCase().startsWith(`${h.toLowerCase()}/`)) return null;
  // Compared without case: Windows and macOS folders are case-insensitive.
  const rel = p.slice(h.length + 1).toLowerCase();
  const lowerName = name.toLowerCase();
  if (CLOUD_FILES.includes(rel)) return "cloud_credentials";
  if (rel.startsWith("library/keychains/") && /\.keychain(-db)?$/.test(lowerName)) return "keychain";
  if (WINDOWS_CREDENTIAL_ROOTS.some((root) => rel.startsWith(root))) return "windows_credentials";
  if (WALLET_ROOTS.some((root) => rel.startsWith(root))) return "crypto_wallet";
  if (MESSAGING_ROOTS.some((root) => rel.startsWith(root))) return "messaging_tokens";
  const inBrowser = BROWSER_ROOTS.some((root) => rel.startsWith(root));
  if (inBrowser && `/${rel}`.includes(METAMASK)) return "crypto_wallet";
  if (inBrowser && lowerName === "local state") return "browser_key";
  if (inBrowser && BROWSER_FILES.has(lowerName)) return "browser_secrets";
  return null;
}

const BROWSERS = ["chrome", "google-chrome", "chromium", "chromium-browser", "brave", "brave-browser", "microsoft-edge", "msedge", "firefox", "firefox-bin", "Google Chrome", "Brave Browser", "Microsoft Edge"];
const EDITORS = ["code", "codium", "cursor", "idea", "pycharm", "webstorm", "goland", "clion", "rider", "nvim", "vim", "vi", "nano", "emacs", "micro", "hx", "subl", "gedit", "kate"];

/** Programs expected to read each kind (matched on the executable's name, then checked for where it lives). */
export const DEFAULT_ALLOWLIST: Record<CredentialKind, string[]> = {
  ssh_key: ["ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp", "sshd", "git", "gpg", "gpg-agent", "rsync", "mosh-client", "gnome-keyring-daemon", "seahorse", "qalaa"],
  env_file: [...EDITORS, "git", "docker", "docker-compose", "qalaa"],
  cloud_credentials: ["aws", "gcloud", "kubectl", "helm", "k9s", "docker", "docker-credential-desktop", "git", "git-credential-libsecret", "gh", "npm", "pip", "twine", "az", "terraform", "qalaa"],
  browser_secrets: [...BROWSERS, "qalaa"],
  browser_key: [...BROWSERS, "qalaa"],
  keychain: ["securityd", "secd", "trustd", "Keychain Access", "qalaa"],
  password_manager: ["keepassxc", "keepassxc-proxy", "KeePassXC", "keepass", "KeePass", "keepass2", "qalaa"],
  // Browser wallets (MetaMask) live in the browser's own profile.
  crypto_wallet: ["electrum", "Electrum", "exodus", "Exodus", "geth", ...BROWSERS, "qalaa"],
  messaging_tokens: ["discord", "Discord", "Telegram", "telegram-desktop", "qalaa"],
  system_secrets: ["unix_chkpwd", "passwd", "chage", "chpasswd", "sudo", "su", "sshd", "login", "gdm-session-worker", "useradd", "usermod", "cockpit-session", "qalaa"],
  windows_credentials: ["lsass", "svchost", "qalaa"],
};

/** Kinds whose theft is serious enough for a high-priority alert on its own. */
export const HIGH_SEVERITY: ReadonlySet<CredentialKind> = new Set(["system_secrets", "crypto_wallet", "keychain", "windows_credentials"]);

/** Normalised program name: "/usr/bin/python3.12" → "python3.12", "C:\\x\\KeePass.exe" → "KeePass". */
export function programName(exe: string): string {
  return basename(exe.replace(/ \(deleted\)$/, "").replace(/\\/g, "/"))
    .replace(/\.exe$/i, "")
    .trim();
}

/** The name is on the default list for this kind. Where it lives is checked separately. */
export function nameAllowed(kind: CredentialKind, exe: string): boolean {
  const base = programName(exe).toLowerCase();
  return DEFAULT_ALLOWLIST[kind].some((allowed) => {
    const a = allowed.toLowerCase();
    // "Google Chrome Helper (Renderer)" belongs to Chrome; "git-remote-https" to git.
    return base === a || base.startsWith(`${a} `) || base.startsWith(`${a}-`);
  });
}

/** A program the person allowed: its full path and the SHA-256 of the binary they allowed. */
export interface TrustedProgram {
  exe: string;
  sha256: string | null;
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

/**
 * macOS `lsof -u <user> -Fpn -n -P`: p<pid> and n<name> lines. The command
 * name lsof prints is cut to a few characters, so the executable is looked up
 * by pid instead (see parsePsComm).
 */
export function parseLsof(text: string): { pid: number; path: string }[] {
  const files: { pid: number; path: string }[] = [];
  let pid = 0;
  for (const line of text.split("\n")) {
    if (line.startsWith("p")) pid = Number(line.slice(1));
    else if (line.startsWith("n/") && pid > 0) files.push({ pid, path: line.slice(1) });
  }
  return files;
}

/** `ps -o pid=,comm= -p …` on macOS: the full executable path per pid. */
export function parsePsComm(text: string): Map<number, string> {
  const out = new Map<number, string>();
  for (const line of text.split("\n")) {
    const m = /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
    if (m) out.set(Number(m[1]), m[2]!);
  }
  return out;
}

/**
 * macOS: keychain dumping through the `security` tool (SigmaHQ
 * proc_creation_macos_security_*), from `ps -axo pid=,command=`.
 */
export function keychainDumps(psCommands: string): { pid: number; command: string }[] {
  const found: { pid: number; command: string }[] = [];
  for (const line of psCommands.split("\n")) {
    const m = /^\s*(\d+)\s+(\S*\/?security)\s+(.+)$/.exec(line);
    if (!m) continue;
    const args = m[3]!;
    if (/\bdump-keychain\b/.test(args) || (/\bfind-(generic|internet)-password\b/.test(args) && /(^|\s)-[a-zA-Z]*w/.test(args))) {
      found.push({ pid: Number(m[1]), command: `security ${args.split(/\s+/)[0]}` });
    }
  }
  return found;
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
