/**
 * Checking an email on the device. Shared by the Thunderbird add-on and the
 * desktop mailbox scanner (which imports this file), so both behave the same.
 *
 * Everything here runs locally: the wording rules come from the server's public
 * rule pack (downloaded, not sent), and the sender, header and link checks are
 * plain code. The only thing that leaves the device is the list returned by
 * nothing: links are checked against the threat lists by hash prefix
 * (threat-prefix.js), so no link, address or text from a message is sent.
 */
import { arabicBrandIn, impersonatedBrand } from "./lookalike.js";

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

/**
 * Every web link in the email, in full. They are hashed on the device
 * (threat-prefix.js) and never sent, so the query string can stay: it is part
 * of the exact address some threat lists record.
 */
export function linksIn(email) {
  const found = [...(email.qr_links || []), ...(email.links || []).map((link) => link.href), ...[...String(email.text || "").matchAll(/https?:\/\/[^\s<>"'،؛)\]]+/gi)].map((m) => m[0])];
  const out = [];
  for (const raw of found) {
    // Sentence punctuation after a link in plain text isn't part of it.
    const href = String(raw).trim().replace(/[.,;:!?'"»”]+$/u, "").slice(0, 2048);
    if (/^https?:\/\//i.test(href) && !out.includes(href)) out.push(href);
    if (out.length >= MAX_LINKS) break;
  }
  return out;
}

/** Every link in the email, stripped to bare form (scheme, host and path). Used by older add-on versions' server lookup. */
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
    lookalikeSender: (brand, site) => [`The sender's domain imitates ${brand}`, `The message came from ${site}, which is spelled like ${brand}'s domain but isn't one of them. Look-alike domains are how invoice and account scams pass at a glance.`],
    lookalikeLink: (brand, site) => [`A link goes to a look-alike of ${brand}`, `${site} is spelled like ${brand}'s domain but isn't one of them. Don't sign in or pay there.`],
    personalAccount: (name, domain) => ["A business title on a personal email account", `The sender calls themselves “${name}” but writes from a personal ${domain} account. Executives and finance teams normally use their organisation's domain.`],
    request: {
      payment: ["The email asks for a payment or a change of bank details", "Requests to pay, wire money or use new bank details are where business email compromise ends. Confirm them by phone, on a number you already have."],
      credentials: ["The email asks for a password or verification code", "Legitimate services don't ask for passwords or one-time codes by email."],
      gift_cards: ["The email asks you to buy gift cards", "Gift-card requests from a manager or colleague are a common scam."],
    },
    qr: (sites) => ["The email contains a QR code", `It opens ${sites}. A QR code hides where it leads and is usually scanned on a phone, outside this computer's protection. Check the address before scanning it.`],
    qrPhishing: ["A QR code with a sign-in or payment request", "Scam emails use QR codes to get people to sign in or pay on their phone, where link checks don't reach. Open the service yourself instead of scanning."],
    bec: (what) => ["This looks like business email compromise", `It combines a sender that may not be who they claim with a request to ${what}. Verify it through another channel before acting.`],
    becWhat: { payment: "send money or change bank details", credentials: "share a password or code", gift_cards: "buy gift cards" },
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
    lookalikeSender: (brand, site) => [`نطاق المرسل يقلّد ${brand}`, `جاءت الرسالة من ${site}، وهو مكتوب بشكل يشبه نطاق ${brand} لكنه ليس من نطاقاتها. هكذا تمرّ عمليات احتيال الفواتير والحسابات من النظرة الأولى.`],
    lookalikeLink: (brand, site) => [`رابط يؤدي إلى موقع يقلّد ${brand}`, `${site} مكتوب بشكل يشبه نطاق ${brand} لكنه ليس من نطاقاتها. لا تسجّل الدخول ولا تدفع فيه.`],
    personalAccount: (name, domain) => ["لقب وظيفي على حساب بريد شخصي", `يقدّم المرسل نفسه باسم “${name}” لكنه يراسل من حساب شخصي على ${domain}. يستخدم المديرون وفرق المالية عادةً نطاق مؤسستهم.`],
    request: {
      payment: ["تطلب الرسالة دفعة أو تغيير بيانات الحساب البنكي", "طلبات الدفع أو التحويل أو استخدام حساب بنكي جديد هي ما ينتهي إليه احتيال البريد التجاري. تأكّد منها هاتفيًا على رقم تعرفه مسبقًا."],
      credentials: ["تطلب الرسالة كلمة مرور أو رمز تحقق", "لا تطلب الخدمات الحقيقية كلمات المرور أو الرموز المؤقتة عبر البريد."],
      gift_cards: ["تطلب الرسالة شراء بطاقات هدايا", "طلب بطاقات الهدايا من مدير أو زميل احتيال شائع."],
    },
    qr: (sites) => ["تحتوي الرسالة على رمز QR", `يفتح ${sites}. يخفي رمز QR وجهته، ويُمسح عادةً بالهاتف بعيدًا عن حماية هذا الجهاز. تحقّق من العنوان قبل مسحه.`],
    qrPhishing: ["رمز QR مع طلب تسجيل دخول أو دفع", "تستخدم رسائل الاحتيال رموز QR لدفع الناس إلى تسجيل الدخول أو الدفع على هواتفهم، حيث لا تصل فحوص الروابط. افتح الخدمة بنفسك بدل مسح الرمز."],
    bec: (what) => ["تبدو هذه الرسالة احتيالًا على البريد التجاري", `تجمع بين مرسل قد لا يكون من يدّعي، وطلب ${what}. تحقّق منها عبر وسيلة أخرى قبل أي إجراء.`],
    becWhat: { payment: "تحويل أموال أو تغيير بيانات بنكية", credentials: "مشاركة كلمة مرور أو رمز", gift_cards: "شراء بطاقات هدايا" },
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

/**
 * Refuses pattern shapes that can backtrack catastrophically on a long message:
 * an unboundedly repeated group that itself contains an unbounded repeat
 * ("(a+)+", "(\\w+\\.)*"), backreferences, and very long patterns. The server's
 * own patterns are tested to pass (test/fixtures/server-patterns.json).
 */
export function safePatternSource(source) {
  if (typeof source !== "string" || source.length > 500) return false;
  if (/\\[1-9]|\\k</.test(source)) return false;
  const groups = []; // for each open group: does it contain an unbounded repeat?
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "(") groups.push(false);
    else if (c === "+" || c === "*" || (c === "{" && /^\{\d+,\}/.test(source.slice(i)))) {
      if (groups.length) groups[groups.length - 1] = true;
    } else if (c === ")") {
      const unboundedInside = groups.pop() ?? false;
      const next = source.slice(i + 1);
      const repeatedUnbounded = /^(?:[+*]|\{\d+,\})/.test(next);
      if (unboundedInside && repeatedUnbounded) return false;
      if (unboundedInside && groups.length) groups[groups.length - 1] = true;
    }
  }
  return true;
}

/** Compiles the rule pack's patterns once. Bad or unsafe patterns are skipped, never thrown. */
export function compilePack(pack) {
  if (!pack) return null;
  const rules = (pack.rules || []).map((rule) => ({
    ...rule,
    compiled: rule.patterns.flatMap((source) => {
      if (!safePatternSource(source)) return [];
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

// Personal mailbox providers: fine for people, unusual for a company's finance team or CEO.
const PERSONAL_MAIL = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com"]);
// Role and title words in display names (English and Arabic, after folding).
const ROLE = /\b(ceo|cfo|coo|chairman|president|director|managing|manager|finance|accounts?|payroll|treasury|procurement|hr)\b|المدير|مدير|الرئيس|رئيس|المالي|الماليه|الحسابات|المحاسب|الرواتب|المشتريات|الموارد البشريه|الخزينه/i;
// Requests that end a BEC: money, credentials, gift cards. English and Arabic.
const REQUESTS = {
  payment: /\b(wire|bank)\s+transfer|\bIBAN\b|\b(new|updated?|change[ds]?)\s+(of\s+|to\s+)?(our\s+|my\s+|the\s+|your\s+)?(bank|banking|account|payment)\s+(details|account|information)|\bremittance\b|\b(swift|routing)\s+(code|number)|حوال[هة]\s+(بنكي[هة]|مالي[هة])|تحويل\s+(بنكي|مبلغ|مالي|الأموال|الاموال|المبلغ)|(?:آ|أ|ا)يبان|رقم\s+(الحساب|الآيبان)|حساب\s+بنكي\s+جديد|(تغيير|تحديث)\s+(بيانات|معلومات)\s+(الحساب|البنك)/iu,
  credentials: /\b(password|passcode|verification\s+code|one[-\s]time\s+(code|password)|OTP|login\s+details)\b|كلم[ةه]\s+(المرور|السر)|رمز\s+(التحقق|التفعيل|الدخول)|بيانات\s+الدخول/iu,
  gift_cards: /\bgift\s*cards?\b|\b(itunes|google\s+play|steam|amazon)\s+cards?\b|بطاقات?\s+(هدايا|هدية|شحن)/iu,
};

/** Which kinds of sensitive request the text makes (none, one or several). */
export function sensitiveRequests(text) {
  return Object.entries(REQUESTS)
    .filter(([, pattern]) => pattern.test(text))
    .map(([kind]) => kind);
}

function brandName(pack, key) {
  return pack?.brands?.[key]?.name ?? key;
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
  let claimed = false;
  for (const [key, brand] of Object.entries(pack?.brands ?? {})) {
    if ((words.has(key) || squashed === key) && !brand.domains.some((d) => siteOf(d) === site)) {
      findings.push(finding("high", "brand_impersonation", s.brand(brand.name, site)));
      claimed = true;
      break;
    }
  }
  // The same in Arabic ("مصرف الراجحي" from a domain that isn't Al Rajhi's).
  const arabic = claimed ? null : arabicBrandIn(from.name, pack?.url_rules);
  if (arabic && pack?.brands?.[arabic] && !pack.brands[arabic].domains.some((d) => siteOf(d) === site)) {
    findings.push(finding("high", "brand_impersonation", s.brand(brandName(pack, arabic), site)));
  }

  // A domain spelled like a brand's ("paypa1.com", "الراجحی.com", "alrajhi-bank.co").
  const imitated = impersonatedBrand(site, pack);
  if (imitated) findings.push(finding(imitated.kind === "contains" ? "medium" : "high", "lookalike_sender", s.lookalikeSender(brandName(pack, imitated.brand), site)));

  // A finance or executive title on a personal mailbox.
  const foldedName = from.name.normalize("NFKC").replace(/[ة]/g, "ه");
  if (PERSONAL_MAIL.has(site) && ROLE.test(foldedName)) findings.push(finding("medium", "personal_account", s.personalAccount(from.name, site)));

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

function lookalikeLinkFindings(links, pack, s) {
  const seen = new Set();
  for (const link of links || []) {
    let site;
    try {
      site = siteOf(new URL(link.href).hostname);
    } catch {
      continue;
    }
    if (seen.has(site)) continue;
    seen.add(site);
    const imitated = impersonatedBrand(site, pack);
    // "paypal-login.example": the brand plus other words is a weaker sign than a misspelling.
    if (imitated) return [finding(imitated.kind === "contains" ? "medium" : "high", "lookalike_link", s.lookalikeLink(brandName(pack, imitated.brand), site))];
  }
  return [];
}

/** QR codes decoded from the message's images (by the desktop scanner); never opened. */
function qrFindings(qrLinks, text, sender, s) {
  const sites = [];
  for (const href of qrLinks || []) {
    try {
      const site = siteOf(new URL(href).hostname);
      if (!sites.includes(site)) sites.push(site);
    } catch {
      // not a web address
    }
  }
  if (!sites.length) return [];
  const requests = sensitiveRequests(text);
  const doubtful = sender.some((f) => f.severity === "high" || f.severity === "medium");
  const accountWords = /\b(sign\s*in|log\s*in|verify|account|password|payment|pay)\b|تسجيل\s+الدخول|تحقق|حساب|كلمة\s+المرور|دفع/iu.test(text);
  const out = [finding("low", "qr_code", s.qr(sites.join(", ")))];
  if (doubtful || requests.includes("credentials") || requests.includes("payment") || (accountWords && sender.length)) out.push(finding("medium", "qr_phishing", s.qrPhishing));
  return out;
}

/**
 * Business email compromise is a combination: a sender that may not be who they
 * claim, plus a request for money, credentials or gift cards. Either alone is
 * common in genuine mail, so a request on its own is only noted (low).
 */
function becFindings(text, sender, s) {
  const requests = sensitiveRequests(text);
  if (!requests.length) return [];
  const doubtful = sender.some((f) => ["sender_mismatch", "brand_impersonation", "lookalike_sender", "personal_account", "reply_to_mismatch"].includes(f.category));
  if (doubtful) return [finding("high", "bec", s.bec(s.becWhat[requests[0]]))];
  return [finding("low", "sensitive_request", s.request[requests[0]])];
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
  const sender = senderFindings(email, pack, s);
  return [
    ...authFindings(authResults(email.authentication_results), s),
    ...sender,
    ...linkFindings(email.links, s),
    ...lookalikeLinkFindings([...(email.links || []), ...(email.qr_links || []).map((href) => ({ href, text: "" }))], pack, s),
    ...becFindings(text, sender, s),
    ...qrFindings(email.qr_links, text, sender, s),
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
  // What the warning rests on: a doubtful sender, a doubtful message, or a threat-list match.
  const serious = (f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium";
  const SENDER = new Set(["sender_mismatch", "brand_impersonation", "lookalike_sender", "personal_account", "reply_to_mismatch", "email_authentication"]);
  const assessment = {
    confirmed: findings.some((f) => f.severity === "critical" && (f.category === "threat_intelligence" || f.category === "link_reputation")),
    sender: findings.some((f) => serious(f) && SENDER.has(f.category)),
    message: findings.some((f) => serious(f) && !SENDER.has(f.category) && f.category !== "threat_intelligence"),
  };
  return { risk, summary: TEXT[lang === "ar" ? "ar" : "en"].summary[risk], findings: sorted, assessment };
}
