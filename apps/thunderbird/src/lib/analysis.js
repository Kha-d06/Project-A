/**
 * Checking an email on the device. Shared by the Thunderbird add-on and the
 * desktop mailbox scanner (which imports this file), so both behave the same.
 *
 * Everything here runs locally: the wording rules come from the server's public
 * rule pack (downloaded, not sent), and the sender, header and link checks are
 * plain code. The only thing that leaves the device is the list returned by
 * linksToCheck(): bare links (scheme, host and path), for a reputation lookup.
 */

const SECOND_LEVEL = new Set(["co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "mil", "sch", "nic"]);
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const MAX_LINKS = 50;
const EXCERPT = 30;

/** The registrable part of a host name, by a simple rule ("a.b.example.co.uk" -> "example.co.uk"). */
export function siteOf(host) {
  const labels = String(host || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const [second, top] = labels.slice(-2);
  const keep = top.length === 2 && SECOND_LEVEL.has(second) ? 3 : 2;
  return labels.slice(-keep).join(".");
}

export function parseAddress(header) {
  const text = String(header || "").trim();
  const angle = /^(.*?)<([^<>]+)>\s*$/.exec(text);
  const name = (angle ? angle[1] : "").trim().replace(/^"(.*)"$/, "$1").trim();
  const address = (angle ? angle[2] : text).trim().toLowerCase();
  const at = address.lastIndexOf("@");
  const domain = at > 0 ? address.slice(at + 1).replace(/[>\s]+$/, "") : "";
  return { name, address, domain };
}

/** The first result for each method, as the receiving mail server reported it. */
export function authResults(header) {
  const results = {};
  for (const [, method, result] of String(header || "").matchAll(/\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/gi)) {
    const key = method.toLowerCase();
    if (!(key in results)) results[key] = result.toLowerCase();
  }
  return results;
}

/** Scheme, host and path: no user name, query string or fragment. */
export function bareUrl(raw) {
  try {
    const url = new URL(String(raw).trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return null;
  }
}

/** Every link in the email, stripped to bare form, for the reputation check. */
export function linksToCheck(email) {
  const found = [...(email.links || []).map((link) => link.href), ...String(email.text || "").matchAll(/https?:\/\/[^\s<>"'،؛)\]]+/gi)].map((m) =>
    typeof m === "string" ? m : m[0],
  );
  const out = [];
  for (const raw of found) {
    const url = bareUrl(raw);
    if (url && !out.includes(url)) out.push(url);
    if (out.length >= MAX_LINKS) break;
  }
  return out;
}

const TEXT = {
  en: {
    dmarc: ["The sender's domain says this email is not from it", "Your mail provider checked this message against the published rules of the domain in the From address (DMARC), and it failed. Forged senders look like this."],
    spf: ["This email could not prove where it came from", "Both the sending-server check (SPF) and the signature check (DKIM) failed. Genuine mail from large companies normally passes at least one."],
    shownAddress: (shown, address) => ["The sender's name shows a different address", `The name shows ${shown}, but the message was sent from ${address}. Putting an address in the name is a common way to hide the real sender.`],
    brand: (brand, site) => [`The sender claims to be ${brand}`, `The name says ${brand}, but the message came from ${site}, which is not one of its domains.`],
    replyTo: (from, reply) => ["Replies would go to a different domain", `The message is from ${from}, but replying sends your answer to ${reply}. Scammers do this to receive replies to a borrowed name.`],
    linkMismatch: (shown, opens) => ["A link shows one address but opens another", `The link reads “${shown}” but opens ${opens}.`],
    summary: {
      known_malicious: "This email links to a site on a threat list. Do not open its links or attachments.",
      suspicious: "This email shows warning signs of a scam or phishing attempt.",
      no_known_threat: "No warning signs were found in this email. That is not a guarantee it is genuine.",
    },
  },
  ar: {
    dmarc: ["نطاق المرسل يقول إن هذه الرسالة ليست منه", "تحقق مزود بريدك من هذه الرسالة وفق القواعد المنشورة لنطاق عنوان المرسل (DMARC) وفشل التحقق. هكذا تبدو رسائل المرسلين المزيفين."],
    spf: ["لم تستطع هذه الرسالة إثبات مصدرها", "فشل كل من التحقق من خادم الإرسال (SPF) والتحقق من التوقيع (DKIM). عادةً ما تنجح الرسائل الحقيقية من الشركات الكبيرة في أحدهما على الأقل."],
    shownAddress: (shown, address) => ["اسم المرسل يعرض عنوانًا مختلفًا", `يعرض الاسم ${shown}، لكن الرسالة أُرسلت من ${address}. وضع عنوان في الاسم طريقة شائعة لإخفاء المرسل الحقيقي.`],
    brand: (brand, site) => [`يدّعي المرسل أنه ${brand}`, `يقول الاسم ${brand}، لكن الرسالة جاءت من ${site}، وهو ليس من نطاقاتها.`],
    replyTo: (from, reply) => ["الردود ستذهب إلى نطاق مختلف", `الرسالة من ${from}، لكن الرد عليها يرسل إجابتك إلى ${reply}. يفعل المحتالون ذلك لتلقي الردود باسم مستعار.`],
    linkMismatch: (shown, opens) => ["رابط يعرض عنوانًا ويفتح عنوانًا آخر", `يظهر الرابط “${shown}” لكنه يفتح ${opens}.`],
    summary: {
      known_malicious: "تحتوي هذه الرسالة على رابط لموقع مدرج في قوائم التهديدات. لا تفتح روابطها أو مرفقاتها.",
      suspicious: "تظهر على هذه الرسالة علامات تحذير من احتيال أو تصيد.",
      no_known_threat: "لم تُرصد علامات تحذير في هذه الرسالة. هذا لا يضمن أنها حقيقية.",
    },
  },
};

function finding(severity, category, [title, explanation]) {
  return { severity, category, title, explanation };
}

function excerpt(text, match) {
  const start = Math.max(0, match.index - EXCERPT);
  const end = Math.min(text.length, match.index + match[0].length + EXCERPT);
  return `${start ? "…" : ""}${text.slice(start, end).replace(/\s+/g, " ").trim()}${end < text.length ? "…" : ""}`;
}

/** Compiles the rule pack's patterns once. Bad patterns are skipped, never thrown. */
export function compilePack(pack) {
  if (!pack) return null;
  const rules = (pack.rules || []).map((rule) => ({
    ...rule,
    compiled: rule.patterns.flatMap((source) => {
      try {
        return [new RegExp(source, "iu")];
      } catch {
        return [];
      }
    }),
  }));
  return { ...pack, rules };
}

function wordingFindings(text, pack, lang) {
  const findings = [];
  for (const rule of pack?.rules ?? []) {
    for (const pattern of rule.compiled ?? []) {
      const match = pattern.exec(text);
      if (!match) continue;
      findings.push({
        severity: rule.severity,
        category: rule.category,
        title: lang === "ar" ? rule.title_ar : rule.title,
        explanation: lang === "ar" ? rule.explanation_ar : rule.explanation,
        excerpt: excerpt(text, match),
      });
      break;
    }
  }
  return findings;
}

function senderFindings(email, pack, s) {
  const findings = [];
  const from = parseAddress(email.from_header);
  if (!from.domain) return findings;
  const site = siteOf(from.domain);

  const shown = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/.exec(from.name);
  if (shown && siteOf(shown[1]) !== site) findings.push(finding("high", "sender_mismatch", s.shownAddress(shown[0], from.address)));

  const lower = from.name.toLowerCase();
  const words = new Set(lower.split(/[^a-z0-9]+/).filter((w) => w.length >= 3));
  const squashed = lower.replace(/[^a-z0-9]/g, "");
  for (const [key, brand] of Object.entries(pack?.brands ?? {})) {
    if ((words.has(key) || squashed === key) && !brand.domains.some((d) => siteOf(d) === site)) {
      findings.push(finding("high", "brand_impersonation", s.brand(brand.name, site)));
      break;
    }
  }

  const reply = parseAddress(email.reply_to || "");
  if (reply.domain && siteOf(reply.domain) !== site) findings.push(finding("medium", "reply_to_mismatch", s.replyTo(site, siteOf(reply.domain))));
  return findings;
}

function authFindings(results, s) {
  if (results.dmarc === "fail") return [finding("high", "email_authentication", s.dmarc)];
  if ((results.spf === "fail" || results.spf === "softfail") && results.dkim && results.dkim !== "pass") {
    return [finding("medium", "email_authentication", s.spf)];
  }
  return [];
}

function linkFindings(links, s) {
  for (const link of links || []) {
    const shown = /^(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#]\S*)?$/i.exec(String(link.text || "").trim());
    if (!shown) continue;
    let opens;
    try {
      opens = new URL(link.href).hostname;
    } catch {
      continue;
    }
    if (siteOf(shown[1]) !== siteOf(opens)) return [finding("high", "link_mismatch", s.linkMismatch(shown[1], opens))];
  }
  return [];
}

/** Every check that needs nothing but the message and the rule pack. */
export function analyzeLocally(email, pack, lang = "en") {
  const s = TEXT[lang === "ar" ? "ar" : "en"];
  const text = [email.subject, email.text].filter(Boolean).join("\n");
  return [
    ...authFindings(authResults(email.authentication_results), s),
    ...senderFindings(email, pack, s),
    ...linkFindings(email.links, s),
    ...wordingFindings(text, pack, lang),
  ];
}

/** Turns the server's link results into findings, naming the link each is about. */
export function linkReputationFindings(results) {
  return (results || []).flatMap((result) => result.findings.map((f) => ({ ...f, category: "link_reputation", link: result.url })));
}

/** The same thresholds the server uses for scans. */
export function verdict(findings, lang = "en") {
  const severities = findings.map((f) => f.severity);
  const risk = severities.includes("critical")
    ? "known_malicious"
    : severities.includes("high") || severities.includes("medium")
      ? "suspicious"
      : "no_known_threat";
  const sorted = [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  return { risk, summary: TEXT[lang === "ar" ? "ar" : "en"].summary[risk], findings: sorted };
}
