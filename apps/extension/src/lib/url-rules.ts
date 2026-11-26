/**
 * The address checks, run inside the browser: a port of the server's
 * services/api/app/analyzers/url_heuristics.py, reading the same rules file
 * (services/api/app/rules/url_rules.json, bundled at build time and refreshed
 * from the server). Both are tested against tests/fixtures/url-vectors.json, so
 * they give the same results. Nothing here sends anything anywhere.
 */
import { parse as parseDomain } from "tldts";

import bundledRules from "../../../../services/api/app/rules/url_rules.json";

export interface UrlRules {
  version: string;
  brands: Record<string, { name: string; domains: string[] }>;
  shorteners: string[];
  credentialPathWords: string[];
  riskyDownloadExtensions: string[];
  minTyposquatLength: number;
  maxOrdinarySubdomainDepth: number;
  longHostLength: number;
  confusables: Record<string, string>;
  arabic: { fold: Record<string, string>; strip: string[]; lookalikeLetters: string[]; brands: Record<string, string> };
}

export const BUNDLED_RULES = bundledRules as UrlRules;

export interface ParsedAddress {
  normalized: string;
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  hasCredentials: boolean;
  registrableDomain: string;
  subdomain: string;
  domainLabel: string;
  isIpAddress: boolean;
}

export interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  explanation: string;
  source: string;
}

const SOURCE = "Qalaa address patterns";

/** The parts the checks need, normalised the way the server's threat store is. */
export function parseAddress(raw: string): ParsedAddress | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, "");
  if (scheme !== "http" && scheme !== "https") return null;
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!host) return null;
  const parsed = parseDomain(host);
  const isIp = parsed.isIp === true;
  const port = url.port ? Number(url.port) : null;
  const netlocHost = host.includes(":") ? `[${host}]` : host;
  const path = url.pathname || "/";
  return {
    normalized: `${scheme}://${netlocHost}${port ? `:${port}` : ""}${path}${url.search.length > 1 ? url.search : ""}`,
    scheme,
    host,
    port,
    path,
    hasCredentials: url.username !== "" || url.password !== "",
    registrableDomain: isIp ? host : (parsed.domain ?? host),
    subdomain: isIp ? "" : (parsed.subdomain ?? ""),
    domainLabel: isIp ? host : (parsed.domainWithoutSuffix ?? host),
    isIpAddress: isIp,
  };
}

// --- Helpers ----------------------------------------------------------------------

/** Optimal string alignment distance (adjacent swaps count as one edit). */
export function editDistance(left: string, right: string): number {
  const a = [...left];
  const b = [...right];
  const table = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const row = table[i]!;
      row[j] = Math.min(table[i - 1]![j]! + 1, row[j - 1]! + 1, table[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) row[j] = Math.min(row[j]!, table[i - 2]![j - 2]! + 1);
    }
  }
  return table[a.length]![b.length]!;
}

/** RFC 3492 decoding of one "xn--" label; the label itself if it isn't valid. */
export function unicodeLabel(label: string): string {
  if (!label.startsWith("xn--")) return label;
  const input = label.slice(4);
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const adapt = (delta: number, points: number, first: boolean) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (c: number) => (c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base);
  const dash = input.lastIndexOf("-");
  const output = dash > 0 ? [...input.slice(0, dash)].map((c) => c.codePointAt(0)!) : [];
  let n = 128, i = 0, bias = 72;
  for (let pos = dash > 0 ? dash + 1 : 0; pos < input.length; ) {
    const oldI = i;
    for (let w = 1, k = base; ; k += base) {
      if (pos >= input.length) return label;
      const d = digit(input.charCodeAt(pos++));
      if (d >= base) return label;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    if (n > 0x10ffff) return label;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

// The first word of each letter's Unicode name, as the server groups them.
const SCRIPTS: [RegExp, string][] = [
  [/\p{Script_Extensions=Latin}/u, "LATIN"],
  [/\p{Script_Extensions=Cyrillic}/u, "CYRILLIC"],
  [/\p{Script_Extensions=Greek}/u, "GREEK"],
  [/\p{Script_Extensions=Arabic}/u, "ARABIC"],
  [/\p{Script_Extensions=Hebrew}/u, "HEBREW"],
  [/\p{Script_Extensions=Armenian}/u, "ARMENIAN"],
  [/\p{Script_Extensions=Georgian}/u, "GEORGIAN"],
  [/\p{Script_Extensions=Han}/u, "CJK"],
  [/\p{Script_Extensions=Hiragana}/u, "HIRAGANA"],
  [/\p{Script_Extensions=Katakana}/u, "KATAKANA"],
  [/\p{Script_Extensions=Hangul}/u, "HANGUL"],
  [/\p{Script_Extensions=Thai}/u, "THAI"],
  [/\p{Script_Extensions=Devanagari}/u, "DEVANAGARI"],
];

function scripts(text: string): Set<string> {
  const found = new Set<string>();
  for (const char of text) {
    if (!/\p{L}/u.test(char)) continue;
    found.add(SCRIPTS.find(([pattern]) => pattern.test(char))?.[1] ?? "OTHER");
  }
  return found;
}

function translate(text: string, table: Record<string, string | null>): string {
  let out = "";
  for (const char of text) {
    const mapped = Object.prototype.hasOwnProperty.call(table, char) ? table[char] : char;
    if (mapped !== null && mapped !== undefined) out += mapped;
  }
  return out;
}

const brandName = (rules: UrlRules, brand: string) => rules.brands[brand]?.name ?? brand.charAt(0).toUpperCase() + brand.slice(1);
const isArabic = (text: string) => [...text].some((c) => (c >= "؀" && c <= "ۿ") || (c >= "ݐ" && c <= "ݿ"));

export function arabicFold(text: string, rules: UrlRules = BUNDLED_RULES): string {
  const table: Record<string, string | null> = { ...rules.arabic.fold };
  for (const char of rules.arabic.strip) table[char] = null;
  return translate(text, table);
}

// --- The checks (same order and wording as the server) ---------------------------------

function homographFindings(url: ParsedAddress, rules: UrlRules): Finding[] {
  const label = unicodeLabel(url.domainLabel);
  if (label === url.domainLabel) return [];
  const skeleton = translate(label, rules.confusables);
  for (const [brand, { domains }] of Object.entries(rules.brands)) {
    if (skeleton === brand && !domains.includes(url.registrableDomain)) {
      return [{
        severity: "high",
        category: "homograph",
        title: `Domain uses look-alike characters to imitate “${brand}”`,
        explanation: `The domain is written with letters from another alphabet that look almost identical to the letters in “${brand}”. This technique is used to make a fake site appear to be a well-known one.`,
        source: SOURCE,
      }];
    }
  }
  if (scripts(label).size > 1) {
    return [{
      severity: "medium",
      category: "homograph",
      title: "Domain mixes letters from different alphabets",
      explanation: "Mixing alphabets inside one domain name is unusual for legitimate sites and is a common way to disguise a look-alike address.",
      source: SOURCE,
    }];
  }
  return [];
}

function arabicFindings(url: ParsedAddress, rules: UrlRules): Finding[] {
  const label = unicodeLabel(url.domainLabel);
  if (!isArabic(label)) return [];
  const folded = arabicFold(label, rules);
  const lookalikeSet = new Set(rules.arabic.lookalikeLetters);
  const lookalikes = [...new Set([...label].filter((c) => lookalikeSet.has(c)))].sort();
  for (const [name, brand] of Object.entries(rules.arabic.brands)) {
    const near = [...name].length >= 5 && editDistance(folded, name) === 1;
    if (folded === name || near) {
      const disguised = lookalikes.length > 0 || near || folded !== label;
      return [{
        severity: disguised ? "high" : "medium",
        category: "homograph",
        title: `Domain written in Arabic imitates ${brandName(rules, brand)}`,
        explanation: `“${label}” reads as ${brandName(rules, brand)}, but “${url.registrableDomain}” is not one of its known domains${disguised ? ", and it is spelled with look-alike letters" : ""}. Check the address before signing in or paying.`,
        source: SOURCE,
      }];
    }
  }
  if (lookalikes.length) {
    return [{
      severity: "medium",
      category: "homograph",
      title: "Domain uses letters that only look Arabic",
      explanation: `The name contains Persian or Urdu letters that look the same as Arabic ones (${lookalikes.join(" ")}). Swapping them in is a way to copy a real Arabic address that can't be told apart by eye.`,
      source: SOURCE,
    }];
  }
  return [];
}

function brandFindings(url: ParsedAddress, rules: UrlRules): Finding[] {
  if (url.isIpAddress) return [];
  const label = translate(url.domainLabel.replaceAll("-", ""), rules.confusables);
  const context = translate(`${url.subdomain}.${url.domainLabel}`.toLowerCase(), rules.confusables);
  const brands = Object.entries(rules.brands);
  if (brands.some(([, { domains }]) => domains.includes(url.registrableDomain))) return [];
  for (const [brand] of brands) {
    if (brand.length < rules.minTyposquatLength) continue;
    const disguised = label === brand && url.domainLabel !== brand;
    if (disguised || editDistance(label, brand) === 1) {
      return [{
        severity: "high",
        category: "typosquatting",
        title: `Domain is a look-alike of “${brand}”`,
        explanation: `“${url.registrableDomain}” is not a domain used by ${brandName(rules, brand)}, but it is spelled almost the same. Look-alike domains are a common way to collect passwords and payment details.`,
        source: SOURCE,
      }];
    }
  }
  for (const [brand] of brands) {
    if (brand.length >= 5 && context.includes(brand)) {
      return [{
        severity: "medium",
        category: "brand_impersonation",
        title: `“${brand}” appears in the address, but the site is not ${brandName(rules, brand)}'s`,
        explanation: `The real domain here is “${url.registrableDomain}”. Putting a familiar brand name elsewhere in the address is a common way to make a link look official.`,
        source: SOURCE,
      }];
    }
  }
  return [];
}

export function analyzeAddress(url: ParsedAddress, rules: UrlRules = BUNDLED_RULES): Finding[] {
  const homograph = homographFindings(url, rules);
  const findings: Finding[] = [...(homograph.length ? homograph : arabicFindings(url, rules)), ...brandFindings(url, rules)];
  const add = (severity: Finding["severity"], category: string, title: string, explanation: string) =>
    findings.push({ severity, category, title, explanation, source: SOURCE });

  if (url.isIpAddress) {
    add("medium", "url_pattern", "Link points to a numeric IP address instead of a domain name", "Legitimate services almost always use a domain name. Raw IP addresses are common in phishing and malware links because they are cheap to set up and hard to recognise.");
  }
  if (url.hasCredentials) {
    add("medium", "url_pattern", "Link hides its real destination behind an “@” sign", `Everything before the “@” in a web address is ignored by the browser. This link really goes to “${url.host}”, whatever the text before it suggests.`);
  }
  if (rules.shorteners.includes(url.registrableDomain)) {
    add("info", "shortener", "Link uses a URL shortener", "Shortened links hide where they lead. That is not harmful in itself, but you cannot judge the destination from the link text.");
  }
  if (url.port !== null) {
    add("low", "url_pattern", `Link uses an unusual port (${url.port})`, "Most public websites use the default web ports. A custom port is not proof of a problem, but it is uncommon for consumer services.");
  }
  const depth = url.subdomain ? url.subdomain.split(".").length : 0;
  if (depth > rules.maxOrdinarySubdomainDepth || url.host.length > rules.longHostLength) {
    add("low", "url_pattern", "Unusually long or deeply nested address", `Very long host names can push the real domain out of view, especially on phones. The real domain here is “${url.registrableDomain}”.`);
  }
  const path = url.path.toLowerCase();
  if (rules.riskyDownloadExtensions.some((ext) => path.endsWith(ext))) {
    add("low", "download", "Link downloads a program or script", "This link points directly at a file type that can run code on your device. Only open it if you were expecting it from a source you trust.");
  }
  if (url.scheme === "http" && rules.credentialPathWords.some((word) => path.includes(word))) {
    add("low", "url_pattern", "Sign-in or account page without an encrypted connection", "The address suggests a sign-in or account page, but it uses http://. Anything typed there can be read by others on the network.");
  }
  return findings;
}

/** Accepts a rules file from the server only if it has the shape the checks need. */
export function validRules(value: unknown): value is UrlRules {
  const r = value as Partial<UrlRules> | null;
  return (
    !!r &&
    typeof r.version === "string" &&
    typeof r.brands === "object" &&
    Array.isArray(r.shorteners) &&
    Array.isArray(r.credentialPathWords) &&
    Array.isArray(r.riskyDownloadExtensions) &&
    typeof r.minTyposquatLength === "number" &&
    typeof r.maxOrdinarySubdomainDepth === "number" &&
    typeof r.longHostLength === "number" &&
    typeof r.confusables === "object" &&
    !!r.arabic &&
    typeof r.arabic.fold === "object" &&
    Array.isArray(r.arabic.strip) &&
    Array.isArray(r.arabic.lookalikeLetters) &&
    typeof r.arabic.brands === "object"
  );
}
