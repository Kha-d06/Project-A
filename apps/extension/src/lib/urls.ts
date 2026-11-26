/** Decides which addresses are worth checking. Runs before anything leaves the browser. */

const PRIVATE_IPV4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^0\./,
];
const LOCAL_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home.arpa"];

export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || !h.includes(".") && !h.includes(":")) return true;
  if (LOCAL_SUFFIXES.some((suffix) => h.endsWith(suffix))) return true;
  if (PRIVATE_IPV4.some((pattern) => pattern.test(h))) return true;
  if (h.includes(":")) return h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd");
  return false;
}

/** The URL to check, or null if it should not be checked at all. */
export function checkableUrl(raw: string): URL | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (isLocalHost(url.hostname)) return null;
  url.hash = "";
  url.username = "";
  url.password = "";
  return url;
}

/** True if host equals an entry or is a subdomain of it. */
export function matchesHostList(host: string, list: string[]): boolean {
  const h = host.toLowerCase();
  return list.some((entry) => h === entry || h.endsWith(`.${entry}`));
}
