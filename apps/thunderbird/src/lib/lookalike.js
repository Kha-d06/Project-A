/**
 * Does a domain imitate a known brand? Used for email senders and link targets.
 * Reads the server's address rules (rule pack `url_rules`, the same file the
 * browser extension checks pages with): brand domains, look-alike characters
 * and the Arabic brand names. Pure functions, no network.
 */

const DEFAULT_CONFUSABLES = { 0: "o", 1: "l", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ο": "o" };

/** Optimal string alignment distance (an adjacent swap is one edit). */
export function editDistance(left, right) {
  const a = [...left];
  const b = [...right];
  const rows = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) rows[i][j] = Math.min(rows[i][j], rows[i - 2][j - 2] + 1);
    }
  }
  return rows[a.length][b.length];
}

/** RFC 3492 decoding of one "xn--" label; the label itself if it isn't valid. */
export function unicodeLabel(label) {
  if (!label.startsWith("xn--")) return label;
  const input = label.slice(4);
  const base = 36;
  const adapt = (delta, points, first) => {
    delta = first ? Math.floor(delta / 700) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > 455) {
      delta = Math.floor(delta / 35);
      k += base;
    }
    return k + Math.floor((36 * delta) / (delta + 38));
  };
  const digit = (c) => (c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base);
  const dash = input.lastIndexOf("-");
  const output = dash > 0 ? [...input.slice(0, dash)].map((c) => c.codePointAt(0)) : [];
  let n = 128;
  let i = 0;
  let bias = 72;
  for (let pos = dash > 0 ? dash + 1 : 0; pos < input.length; ) {
    const oldI = i;
    for (let w = 1, k = base; ; k += base) {
      if (pos >= input.length) return label;
      const d = digit(input.charCodeAt(pos++));
      if (d >= base) return label;
      i += d * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
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

function translate(text, table) {
  let out = "";
  for (const ch of text) {
    const mapped = Object.prototype.hasOwnProperty.call(table, ch) ? table[ch] : ch;
    if (mapped !== null && mapped !== undefined) out += mapped;
  }
  return out;
}

export function arabicFold(text, rules) {
  if (!rules?.arabic) return text;
  const table = { ...rules.arabic.fold };
  for (const ch of rules.arabic.strip ?? []) table[ch] = null;
  return translate(text, table);
}

const isArabic = (text) => /[؀-ۿݐ-ݿ]/.test(text);

/** The brand a piece of Arabic text names ("مصرف الراجحي" → "alrajhi"), or null. */
export function arabicBrandIn(text, rules) {
  if (!rules?.arabic?.brands || !isArabic(text)) return null;
  const folded = arabicFold(text, rules).replace(/\s+/g, "");
  for (const [name, brand] of Object.entries(rules.arabic.brands)) if (folded.includes(name)) return brand;
  return null;
}

/**
 * Whether `site` (a registrable domain such as "paypa1.com") imitates a brand.
 * Returns { brand, kind } with kind "typo" (one letter off, or digits for
 * letters), "homograph" (letters from another alphabet), "arabic" (an Arabic
 * spelling of a regional brand) or "contains" (the brand plus other words), or
 * null. A brand's own domains never count.
 */
export function impersonatedBrand(site, pack) {
  const brands = pack?.brands ?? {};
  const rules = pack?.url_rules ?? {};
  const host = String(site || "").toLowerCase();
  if (!host || Object.values(brands).some((b) => b.domains.includes(host))) return null;
  const asciiLabel = host.split(".")[0];
  const label = unicodeLabel(asciiLabel);
  const confusables = rules.confusables ?? DEFAULT_CONFUSABLES;
  const skeleton = translate(label.replaceAll("-", ""), confusables);
  const minLength = rules.minTyposquatLength ?? 6;

  for (const key of Object.keys(brands)) {
    if (label !== asciiLabel && skeleton === key) return { brand: key, kind: "homograph" };
  }
  if (isArabic(label) && rules.arabic?.brands) {
    const folded = arabicFold(label, rules);
    for (const [name, brand] of Object.entries(rules.arabic.brands)) {
      if (folded === name || ([...name].length >= 5 && editDistance(folded, name) === 1)) return { brand, kind: "arabic" };
    }
  }
  for (const key of Object.keys(brands)) {
    if (key.length < minLength) continue;
    if ((skeleton === key && asciiLabel !== key) || editDistance(skeleton, key) === 1) return { brand: key, kind: "typo" };
  }
  for (const key of Object.keys(brands)) {
    if (key.length >= 5 && skeleton.includes(key) && skeleton !== key) return { brand: key, kind: "contains" };
  }
  return null;
}
