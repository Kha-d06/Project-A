/** Reading the update manifests the server publishes under /downloads/. */

export interface DesktopRelease {
  version: string;
  file: string;
  sha512: string | null;
}

/** electron-builder's latest*.yml: version, then the first file entry. */
export function parseManifest(yaml: string): DesktopRelease | null {
  const version = /^version:\s*['"]?([0-9][\w.\-]*)['"]?\s*$/m.exec(yaml)?.[1];
  const file = /^\s*-\s*url:\s*['"]?([^'"\s]+)['"]?\s*$/m.exec(yaml)?.[1] ?? /^path:\s*['"]?([^'"\s]+)/m.exec(yaml)?.[1];
  if (!version || !file) return null;
  const sha512 = /^\s*sha512:\s*(\S+)\s*$/m.exec(yaml)?.[1] ?? null;
  // Only plain file names: the page builds the link itself under /downloads/.
  if (!/^[\w.\- ]+$/.test(file)) return null;
  return { version, file, sha512 };
}

export interface AndroidRelease {
  version: string;
  file: string;
  sha256: string;
}

export function parseAndroid(json: unknown): AndroidRelease | null {
  if (!json || typeof json !== "object") return null;
  const value = json as Record<string, unknown>;
  const { version, file, sha256 } = value;
  if (typeof version !== "string" || typeof file !== "string" || typeof sha256 !== "string") return null;
  if (!/^[\w.\-]+\.apk$/.test(file) || !/^[0-9a-f]{64}$/.test(sha256)) return null;
  return { version, file, sha256 };
}

/** The .deb and .rpm sit next to the AppImage with predictable names. */
export function linuxPackages(version: string): { deb: string; rpm: string } {
  return { deb: `Qalaa-Desktop-${version}-amd64.deb`, rpm: `Qalaa-Desktop-${version}-x86_64.rpm` };
}
