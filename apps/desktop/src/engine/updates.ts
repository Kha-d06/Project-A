/**
 * Automatic updates, downloaded from the person's own SENTINEL server
 * (<server>/downloads/desktop/), never from a third party.
 *
 * - Windows (NSIS installer) and Linux AppImage update in place. macOS updates
 *   only when the app is code-signed, which is a release-time setting.
 * - Linux .deb and .rpm installs are updated by the system package manager, so
 *   the app only reports that a new version exists.
 * - electron-updater checks the SHA-512 of the download against the server's
 *   latest.yml before installing it.
 */
export type UpdateState =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "none"; checkedAt: string }
  | { state: "available"; version: string }
  | { state: "downloading"; percent: number }
  | { state: "ready"; version: string }
  | { state: "manual"; version: string; reason: string }
  | { state: "error"; message: string };

export function feedUrl(serverUrl: string): string {
  return `${serverUrl.replace(/\/$/, "")}/downloads/desktop`;
}

/** How this copy was installed, which decides whether it can update itself. */
export function installKind(platform: NodeJS.Platform, env: NodeJS.ProcessEnv, packaged: boolean): "appimage" | "deb-rpm" | "installer" | "development" {
  if (!packaged) return "development";
  if (platform === "linux") return env.APPIMAGE ? "appimage" : "deb-rpm";
  return "installer";
}

/** Compare dotted versions numerically: 0.10.0 is newer than 0.9.3. */
export function isNewer(candidate: string, current: string): boolean {
  const parse = (v: string) => v.replace(/^v/, "").split("-")[0]!.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const a = parse(candidate);
  const b = parse(current);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return false;
}

/** Version from the server's latest-linux.yml / latest.yml (first "version:" line). */
export function versionFromManifest(yaml: string): string | null {
  return /^version:\s*['"]?([0-9][\w.\-]*)['"]?\s*$/m.exec(yaml)?.[1] ?? null;
}
