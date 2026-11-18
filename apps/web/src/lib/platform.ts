/** Which download to offer first, from what the browser says about the device. */
export type Platform = "windows" | "mac" | "linux" | "android" | "ios" | "chromeos" | "unknown";

export function detectPlatform(userAgent: string, uaDataPlatform?: string | null, maxTouchPoints = 0): Platform {
  const hint = (uaDataPlatform ?? "").toLowerCase();
  if (hint === "windows") return "windows";
  if (hint === "macos") return "mac";
  if (hint === "android") return "android";
  if (hint === "chrome os" || hint === "chromeos") return "chromeos";
  if (hint === "linux") return "linux";
  const ua = userAgent;
  if (/iPhone|iPad|iPod/.test(ua)) return "ios";
  // iPadOS 13+ presents itself as a Mac; a touch screen gives it away.
  if (/Macintosh/.test(ua) && maxTouchPoints > 1) return "ios";
  if (/Android/.test(ua)) return "android";
  if (/CrOS/.test(ua)) return "chromeos";
  if (/Windows NT|Win64|Win32/.test(ua)) return "windows";
  if (/Mac OS X|Macintosh/.test(ua)) return "mac";
  if (/Linux|X11|Ubuntu|Fedora/.test(ua)) return "linux";
  return "unknown";
}

/** Debian-family or Red Hat-family Linux, when the browser says so (Firefox on Ubuntu often does). */
export function linuxFamily(userAgent: string): "deb" | "rpm" | null {
  if (/Ubuntu|Debian|Mint|Pop!_OS|elementary/i.test(userAgent)) return "deb";
  if (/Fedora|Red Hat|CentOS|openSUSE|SUSE/i.test(userAgent)) return "rpm";
  return null;
}
