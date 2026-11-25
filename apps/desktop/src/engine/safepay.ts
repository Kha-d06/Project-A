/**
 * SafePay: open a banking or shopping site in a separate, clean browser
 * session.
 *
 * - A brand-new profile in a private temporary folder (mode 0700), deleted when
 *   the browser closes: no extensions, saved cookies, history or other sites'
 *   sessions come along, and nothing is left behind.
 * - Extensions, sync, background apps, password saving and form filling are off.
 * - DNS: when Qalaa's Safe DNS is on, the browser's own DNS-over-HTTPS is turned
 *   off so every lookup goes through Qalaa's filter on 127.0.0.1 (and out
 *   encrypted). When Safe DNS is off, Firefox is pointed straight at an
 *   encrypted malware-blocking resolver; Chromium-based browsers can only be
 *   given one by system policy, so they use the system's DNS and the interface
 *   suggests turning Safe DNS on.
 *
 * This isn't a sandbox: it keeps the session apart from the person's everyday
 * browser, it doesn't make a compromised computer safe.
 */
import { access } from "node:fs/promises";
import { join } from "node:path";

export type BrowserFamily = "chromium" | "firefox";

export interface Browser {
  id: "chrome" | "edge" | "brave" | "chromium" | "firefox";
  name: string;
  family: BrowserFamily;
  path: string;
}

export type DnsMode = "safe_dns" | "browser_doh" | "system";

const QUAD9_DOH = "https://dns.quad9.net/dns-query";

/** Where each browser usually lives, most private-by-default first. */
export type Candidate = Omit<Browser, "path"> & { paths: string[] };

export function candidates(platform: NodeJS.Platform, env: NodeJS.ProcessEnv = process.env): Candidate[] {
  const pf = env.ProgramFiles ?? "C:\\Program Files";
  const pf86 = env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)";
  const local = env.LOCALAPPDATA ?? "";
  if (platform === "win32") {
    return [
      { id: "firefox", name: "Firefox", family: "firefox", paths: [`${pf}\\Mozilla Firefox\\firefox.exe`, `${pf86}\\Mozilla Firefox\\firefox.exe`] },
      { id: "brave", name: "Brave", family: "chromium", paths: [`${pf}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`, `${local}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`] },
      { id: "chrome", name: "Google Chrome", family: "chromium", paths: [`${pf}\\Google\\Chrome\\Application\\chrome.exe`, `${pf86}\\Google\\Chrome\\Application\\chrome.exe`, `${local}\\Google\\Chrome\\Application\\chrome.exe`] },
      { id: "edge", name: "Microsoft Edge", family: "chromium", paths: [`${pf86}\\Microsoft\\Edge\\Application\\msedge.exe`, `${pf}\\Microsoft\\Edge\\Application\\msedge.exe`] },
    ];
  }
  if (platform === "darwin") {
    return [
      { id: "firefox", name: "Firefox", family: "firefox", paths: ["/Applications/Firefox.app/Contents/MacOS/firefox"] },
      { id: "brave", name: "Brave", family: "chromium", paths: ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"] },
      { id: "chrome", name: "Google Chrome", family: "chromium", paths: ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"] },
      { id: "edge", name: "Microsoft Edge", family: "chromium", paths: ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"] },
    ];
  }
  return [
    { id: "firefox", name: "Firefox", family: "firefox", paths: ["/usr/bin/firefox", "/usr/lib/firefox/firefox", "/snap/bin/firefox"] },
    { id: "brave", name: "Brave", family: "chromium", paths: ["/usr/bin/brave-browser", "/usr/bin/brave", "/snap/bin/brave"] },
    { id: "chrome", name: "Google Chrome", family: "chromium", paths: ["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/opt/google/chrome/chrome"] },
    { id: "chromium", name: "Chromium", family: "chromium", paths: ["/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"] },
    { id: "edge", name: "Microsoft Edge", family: "chromium", paths: ["/usr/bin/microsoft-edge-stable", "/usr/bin/microsoft-edge"] },
  ];
}

export async function findBrowsers(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env, exists: (p: string) => Promise<boolean> = (p) => access(p).then(() => true, () => false)): Promise<Browser[]> {
  const found: Browser[] = [];
  for (const c of candidates(platform, env)) {
    for (const path of c.paths) {
      if (path && (await exists(path))) {
        found.push({ id: c.id, name: c.name, family: c.family, path });
        break;
      }
    }
  }
  return found;
}

/** Only web addresses, with no credentials in them; anything else is refused. */
export function safeUrl(input: unknown): string | null {
  if (input === undefined || input === null || input === "") return "about:blank";
  if (typeof input !== "string" || input.length > 2048) return null;
  try {
    const url = new URL(input.includes("://") ? input : `https://${input}`);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username || url.password) return null;
    return url.toString();
  } catch {
    return null;
  }
}

export function dnsMode(family: BrowserFamily, safeDnsOn: boolean): DnsMode {
  if (safeDnsOn) return "safe_dns";
  return family === "firefox" ? "browser_doh" : "system";
}

/** Firefox preferences for a clean, private session (written as user.js). */
export function firefoxPrefs(mode: DnsMode): string {
  const prefs: [string, string | number | boolean][] = [
    ["browser.shell.checkDefaultBrowser", false],
    ["browser.startup.homepage_override.mstone", "ignore"],
    ["browser.aboutwelcome.enabled", false],
    ["datareporting.policy.dataSubmissionEnabled", false],
    ["datareporting.healthreport.uploadEnabled", false],
    ["toolkit.telemetry.enabled", false],
    ["app.shield.optoutstudies.enabled", false],
    ["extensions.enabledScopes", 0],
    ["extensions.autoDisableScopes", 15],
    ["xpinstall.enabled", false],
    ["signon.rememberSignons", false],
    ["browser.formfill.enable", false],
    ["extensions.formautofill.addresses.enabled", false],
    ["extensions.formautofill.creditCards.enabled", false],
    ["privacy.trackingprotection.enabled", true],
    ["dom.security.https_only_mode", true],
    ["network.trr.mode", mode === "browser_doh" ? 3 : 5],
    ...(mode === "browser_doh" ? ([["network.trr.uri", QUAD9_DOH]] as [string, string][]) : []),
  ];
  return prefs.map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join("\n") + "\n";
}

export interface LaunchPlan {
  command: string;
  args: string[];
  /** Files to write into the profile before starting (Firefox's user.js). */
  files: { path: string; content: string }[];
}

export function launchPlan(browser: Browser, url: string, profileDir: string, mode: DnsMode): LaunchPlan {
  if (browser.family === "firefox") {
    return {
      command: browser.path,
      args: ["-profile", profileDir, "-no-remote", "-new-instance", url],
      files: [{ path: join(profileDir, "user.js"), content: firefoxPrefs(mode) }],
    };
  }
  const args = [
    `--user-data-dir=${profileDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-component-extensions-with-background-pages",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-background-mode",
    "--disable-features=AutofillServerCommunication,PasswordManagerOnboarding",
    "--password-store=basic",
    "--new-window",
  ];
  // With Safe DNS on, the browser's own DoH would skip Qalaa's filter.
  if (mode === "safe_dns") args.push("--disable-features=DnsOverHttps");
  return { command: browser.path, args: [...mergeDisabledFeatures(args), url], files: [] };
}

/** Chromium only honours the last --disable-features, so they are merged into one. */
function mergeDisabledFeatures(args: string[]): string[] {
  const prefix = "--disable-features=";
  const features = args.filter((a) => a.startsWith(prefix)).flatMap((a) => a.slice(prefix.length).split(","));
  const rest = args.filter((a) => !a.startsWith(prefix));
  return features.length ? [...rest, `${prefix}${[...new Set(features)].join(",")}`] : rest;
}

/** Temporary profile folders start with this, so ones left by a crash can be found and removed. */
export const PROFILE_PREFIX = "qalaa-safepay-";

/**
 * `qalaa://safepay?url=https://bank.example/` from the browser extension (the
 * browser asks the person before handing the link over). Only https pages: a
 * web page could build this link too, and all it can do is open an https page
 * in a clean session.
 */
export function parseSafePayLink(link: string): string | null {
  try {
    const parsed = new URL(link);
    if (parsed.protocol !== "qalaa:" || parsed.hostname !== "safepay") return null;
    const target = safeUrl(parsed.searchParams.get("url") ?? "");
    return target?.startsWith("https://") ? target : null;
  } catch {
    return null;
  }
}
