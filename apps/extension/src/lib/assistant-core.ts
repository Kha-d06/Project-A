/**
 * Pure helpers for the on-screen assistant, shared by the content script and
 * the background, and unit-tested: the page summary model and the built-in
 * answers used when the server has no AI provider.
 */
import type { AssistantContext } from "./api";
import { dictionary, type Language } from "./i18n";
import type { CheckResult, Verdict } from "./types";
import { siteOf, type Tracker } from "./trackers";

export interface CookieInfo {
  name: string;
  domain: string;
  thirdParty: boolean;
  session: boolean;
  days: number | null;
}

export interface PageSummary {
  host: string;
  result: CheckResult | null;
  cookies: CookieInfo[];
  trackers: Tracker[];
  cookiesAvailable: boolean;
}

const WARNING: Verdict[] = ["dangerous", "suspicious", "caution", "blocked_by_you"];

export function isWarning(verdict: Verdict | undefined): boolean {
  return !!verdict && WARNING.includes(verdict);
}

/** Cookie metadata only. chrome.cookies.Cookie.value is deliberately never copied. */
export function describeCookie(cookie: chrome.cookies.Cookie, pageHost: string, now = Date.now()): CookieInfo {
  const session = cookie.session || cookie.expirationDate === undefined;
  return {
    name: cookie.name.slice(0, 120),
    domain: cookie.domain.replace(/^\./, ""),
    thirdParty: siteOf(cookie.domain) !== siteOf(pageHost),
    session,
    days: session ? null : Math.max(0, Math.round(((cookie.expirationDate ?? 0) * 1000 - now) / 86_400_000)),
  };
}

export function toAssistantContext(summary: PageSummary, hasPasswordField: boolean): AssistantContext {
  return {
    host: summary.host,
    verdict: summary.result?.verdict ?? "unavailable",
    warning_signs: (summary.result?.reasons ?? []).slice(0, 10).map((reason) => reason.title),
    cookies: summary.cookies.slice(0, 60).map((c) => ({
      name: c.name,
      domain: c.domain,
      third_party: c.thirdParty,
      session: c.session,
      days: c.days,
    })),
    trackers: summary.trackers.slice(0, 40).map((tracker) => tracker.name),
    has_password_field: hasPasswordField,
  };
}

type Intent = "trust" | "cookies" | "trackers" | "password" | "unknown";

export function intentOf(question: string): Intent {
  const q = question.toLowerCase();
  if (/cookie|كوكي|ملفات تعريف|الارتباط/.test(q)) return "cookies";
  if (/track|pixel|analytics|تتبع|تعقب|التتبع/.test(q)) return "trackers";
  if (/password|sign ?in|log ?in|كلمة (المرور|السر)|تسجيل الدخول/.test(q)) return "password";
  if (/safe|trust|legit|scam|real|fake|danger|آمن|أمان|موثوق|أثق|احتيال|حقيقي|مزيف|خطير|نصب/.test(q)) return "trust";
  return "unknown";
}

/** A grounded answer from the facts SENTINEL already has, in the given language. */
export function builtInAnswer(question: string, summary: PageSummary, language: Language): string {
  const d = dictionary(language);
  const verdict = summary.result?.verdict;
  const label = verdict ? d.verdicts[verdict].label : d.verdicts.unavailable.label;
  const thirdParty = summary.cookies.filter((c) => c.thirdParty).length;
  switch (intentOf(question)) {
    case "trust":
      if (isWarning(verdict)) return d.answers.trustWarning(summary.host, label, summary.result?.reasons[0]?.title ?? "");
      if (verdict === "no_known_threat") return d.answers.trustClear(summary.host);
      return d.answers.trustUnknown(summary.host);
    case "cookies":
      return d.answers.cookies(summary.cookies.length, thirdParty);
    case "trackers":
      return d.answers.trackers(summary.trackers.map((tracker) => tracker.name).join(language === "ar" ? "، " : ", "));
    case "password":
      return d.answers.password(summary.host, label);
    default:
      return d.answers.fallback;
  }
}
