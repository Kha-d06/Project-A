/**
 * Checking an email's links against Qalaa's threat lists without sending them.
 * Shared by the Thunderbird add-on and the desktop mail scanner.
 *
 *  1. Each link is normalised the way the server's threat store is
 *     (scheme://host[:port]/path?query; no user name, no fragment; host in
 *     lower-case ASCII). The same rules as the browser extension, held to the
 *     shared vectors in services/api/tests/fixtures/url-vectors.json.
 *  2. SHA-256 of the address, of the address without its query, and of the host
 *     and each parent domain, are computed here.
 *  3. Each digest's first 4 bytes are looked up in the downloaded prefix list
 *     (GET /email/threat-prefixes, the whole list, every 6 hours).
 *  4. Only on a prefix hit: POST /email/threat-hashes with those prefixes plus 3
 *     random ones from the list. The full hashes come back and are compared here.
 *
 * So the server sees, at most, a few 4-byte prefixes that many addresses share.
 * Links never appear in a request, a log line or an error message from this
 * module: errors are reported as fixed phrases.
 */

export const LIST_REFRESH_MS = 6 * 60 * 60 * 1000;
export const LIST_STALE_MS = 24 * 60 * 60 * 1000;
const HASH_CACHE_MS = 30 * 60 * 1000;
const DECOYS = 3;
const MAX_LINKS = 50;
const MAX_PREFIXES_PER_QUERY = 32;

/** The address as the threat store keys it, or null for anything but http(s). */
export function normalizeUrl(raw) {
  let url;
  try {
    url = new URL(String(raw).trim());
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, "");
  if (scheme !== "http" && scheme !== "https") return null;
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!host) return null;
  const port = url.port ? `:${url.port}` : "";
  const netloc = host.includes(":") ? `[${host}]` : host;
  const path = url.pathname || "/";
  const query = url.search.length > 1 ? url.search : "";
  return { normalized: `${scheme}://${netloc}${port}${path}${query}`, bare: `${scheme}://${netloc}${port}${path}`, host };
}

const isIp = (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");

/** The host and each parent domain with at least two labels ("a.b.example.com" → 3 names). */
export function hostCandidates(host) {
  if (isIp(host)) return [host];
  const labels = host.split(".");
  const out = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."));
  return out;
}

export async function sha256Hex(text) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The sorted 4-byte prefixes, searchable without allocating per lookup. */
export class PrefixList {
  constructor(base64) {
    const binary = atob(base64 || "");
    this.bytes = new Uint8Array(binary.length - (binary.length % 4));
    for (let i = 0; i < this.bytes.length; i++) this.bytes[i] = binary.charCodeAt(i);
    this.count = this.bytes.length / 4;
  }

  at(index) {
    const b = this.bytes;
    const i = index * 4;
    return ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
  }

  has(prefixHex) {
    const target = parseInt(prefixHex, 16) >>> 0;
    let low = 0;
    let high = this.count - 1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      const value = this.at(mid);
      if (value === target) return true;
      if (value < target) low = mid + 1;
      else high = mid - 1;
    }
    return false;
  }

  decoys(n, exclude) {
    const out = new Set();
    for (let tries = 0; this.count > exclude.size && out.size < n && tries < 20; tries++) {
      const pick = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] % this.count;
      const hex = this.at(pick).toString(16).padStart(8, "0");
      if (!exclude.has(hex)) out.add(hex);
    }
    return [...out];
  }
}

const TEXT = {
  en: {
    listedUrl: (by, threat) => [`A link is listed by ${by}`, `The address was catalogued as malicious${threat ? ` (${threat})` : ""}. Don't open it or anything it downloads.`],
    listedHost: (by) => [`A link goes to a site listed by ${by}`, "The site itself is on a threat list. Don't sign in, pay or download anything there."],
    otherOnHost: (by) => [`Other addresses on a linked site are listed by ${by}`, "A different address on the same site was reported. On shared hosting this says little about this link, so treat it as context."],
    community: ["A link was reported by Qalaa users as a scam", "People reported it and a moderator confirmed the reports. Treat it as a likely scam."],
    noList: "The list of known dangerous links hasn't been downloaded recently, so links were only checked for warning signs.",
    unconfirmed: "A link may be on a threat list, but the full check couldn't be completed. Be careful with this email's links.",
  },
  ar: {
    listedUrl: (by, threat) => [`رابط مدرج لدى ${by}`, `صُنّف هذا العنوان على أنه ضار${threat ? ` (${threat})` : ""}. لا تفتحه ولا تفتح ما ينزّله.`],
    listedHost: (by) => [`رابط يؤدي إلى موقع مدرج لدى ${by}`, "الموقع نفسه مدرج في قائمة تهديدات. لا تسجّل الدخول ولا تدفع ولا تنزّل شيئًا منه."],
    otherOnHost: (by) => [`عناوين أخرى على موقع مرتبط مدرجة لدى ${by}`, "أُبلغ عن عنوان آخر على الموقع نفسه. في الاستضافة المشتركة لا يعني ذلك الكثير عن هذا الرابط، فاعتبره سياقًا فقط."],
    community: ["أبلغ مستخدمو قلعة عن رابط على أنه احتيال", "أبلغ عنه أشخاص وراجع مشرف البلاغات وأكّدها. اعتبره احتيالًا محتملًا."],
    noList: "لم تُنزَّل قائمة الروابط الخطرة مؤخرًا، فلم تُفحص الروابط إلا بحثًا عن علامات التحذير.",
    unconfirmed: "قد يكون أحد الروابط مدرجًا في قائمة تهديدات، لكن تعذّر إكمال الفحص. توخَّ الحذر مع روابط هذه الرسالة.",
  },
};

const finding = (severity, category, [title, explanation], link) => ({ severity, category, title, explanation, link });

/**
 * A link checker around a prefix list and a hash lookup, both supplied by the
 * caller (so the add-on and the desktop app use their own storage and network).
 *   getList(): Promise<{ prefixes, fetchedAt, sources } | null>
 *   fetchHashes(prefixes): Promise<{ digest, kind, source, source_name, threat }[]>
 */
export function createLinkChecker({ getList, fetchHashes, now = () => Date.now() }) {
  let decoded = null;
  const cache = new Map(); // prefix -> { at, matches }

  async function lookup(list, prefixes) {
    const t = now();
    const missing = prefixes.filter((p) => (cache.get(p)?.at ?? -Infinity) + HASH_CACHE_MS <= t);
    for (let i = 0; i < missing.length; i += MAX_PREFIXES_PER_QUERY - DECOYS) {
      const chunk = missing.slice(i, i + MAX_PREFIXES_PER_QUERY - DECOYS);
      const query = [...chunk, ...list.decoys(DECOYS, new Set(chunk))].sort();
      const matches = await fetchHashes(query);
      for (const prefix of query) cache.set(prefix, { at: t, matches: matches.filter((m) => m.digest.startsWith(prefix)) });
    }
    return prefixes.flatMap((p) => cache.get(p)?.matches ?? []);
  }

  /** Findings for the links, whether the check could be completed, and what limited it. */
  return async function checkLinks(rawLinks, lang = "en") {
    const s = TEXT[lang === "ar" ? "ar" : "en"];
    const links = [];
    for (const raw of rawLinks) {
      const n = normalizeUrl(raw);
      if (n && !links.some((l) => l.normalized === n.normalized)) links.push(n);
      if (links.length >= MAX_LINKS) break;
    }
    if (!links.length) return { findings: [], checked: true, limitations: [] };

    const stored = await getList().catch(() => null);
    const fresh = stored && stored.sources?.length && now() - stored.fetchedAt < LIST_STALE_MS;
    if (!stored?.prefixes) return { findings: [], checked: false, limitations: [s.noList] };
    if (decoded?.source !== stored.prefixes) decoded = { source: stored.prefixes, list: new PrefixList(stored.prefixes) };
    const list = decoded.list;

    const digests = await Promise.all(
      links.map(async (l) => ({
        link: l,
        url: await sha256Hex(l.normalized),
        bare: await sha256Hex(l.bare),
        hosts: await Promise.all(hostCandidates(l.host).map(sha256Hex)),
      })),
    );
    const hits = new Set();
    for (const d of digests) for (const h of [d.url, d.bare, ...d.hosts]) if (list.has(h.slice(0, 8))) hits.add(h.slice(0, 8));
    const limitations = fresh ? [] : [s.noList];
    if (!hits.size) return { findings: [], checked: Boolean(fresh), limitations };

    let matches;
    try {
      matches = await lookup(list, [...hits]);
    } catch {
      return { findings: [], checked: false, limitations: [...limitations, s.unconfirmed] };
    }
    const findings = [];
    for (const d of digests) {
      const shown = d.link.host;
      const urlMatches = matches.filter((m) => m.kind === "url" && (m.digest === d.url || m.digest === d.bare));
      const hostMatches = matches.filter((m) => m.kind === "host" && d.hosts.includes(m.digest));
      for (const m of urlMatches) {
        findings.push(m.source === "community" ? finding("high", "community_report", s.community, shown) : finding("critical", "threat_intelligence", s.listedUrl(m.source_name, m.threat?.replaceAll("_", " ")), shown));
      }
      if (urlMatches.length) continue;
      for (const m of hostMatches) {
        if (m.source === "community") findings.push(finding("high", "community_report", s.community, shown));
        else if (m.source === "threatfox") findings.push(finding("critical", "threat_intelligence", s.listedHost(m.source_name), shown));
        else findings.push(finding("low", "threat_intelligence", s.otherOnHost(m.source_name), shown));
      }
    }
    return { findings, checked: Boolean(fresh), limitations };
  };
}
