/**
 * Search and AI-answer-engine metadata, as pure functions so they are tested
 * directly: canonical and hreflang URLs, robots rules, the sitemap, breadcrumbs
 * and JSON-LD. Pages are served in the visitor's language on the same URL; for
 * crawlers every public page also has an explicit Arabic URL, `?lang=ar`.
 */
import type { Locale } from "./i18n/locales";

/** The public site address, read at request time so one build serves any domain. */
export function siteUrl(): string {
  return (process.env.SENTINEL_SITE_URL ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://qalaa.example.org").replace(/\/$/, "");
}
export const SITE_NAME = "Qalaa";

/** Public, indexable pages and how they are named in breadcrumbs. */
export const PUBLIC_PAGES: { path: string; en: string; ar: string; priority: number }[] = [
  { path: "/", en: "Home", ar: "الرئيسية", priority: 1 },
  { path: "/scan", en: "Check a link, message or file", ar: "افحص رابطًا أو رسالة أو ملفًا", priority: 0.9 },
  { path: "/download", en: "Download", ar: "التنزيل", priority: 0.9 },
  { path: "/browser-protection", en: "Browser protection", ar: "حماية المتصفح", priority: 0.8 },
  { path: "/tools/password", en: "Password checker", ar: "فاحص كلمات المرور", priority: 0.7 },
  { path: "/intelligence", en: "Threat intelligence lookup", ar: "البحث في معلومات التهديدات", priority: 0.7 },
  { path: "/learn", en: "Learn to spot scams", ar: "تعلّم كشف الاحتيال", priority: 0.7 },
  { path: "/help/scammed", en: "If you've been scammed", ar: "إذا تعرّضت للاحتيال", priority: 0.7 },
  { path: "/report", en: "Report a scam", ar: "أبلغ عن احتيال", priority: 0.6 },
  { path: "/trends", en: "Scam trends", ar: "اتجاهات الاحتيال", priority: 0.5 },
  { path: "/docs", en: "Documentation", ar: "التوثيق", priority: 0.6 },
  { path: "/about", en: "About", ar: "حول", priority: 0.5 },
  { path: "/privacy", en: "Privacy", ar: "الخصوصية", priority: 0.4 },
  { path: "/terms", en: "Terms", ar: "الشروط", priority: 0.3 },
];

/** Never indexed: accounts, personal results, the API. */
export const PRIVATE_PREFIXES = ["/dashboard", "/api/", "/sign-in", "/sign-up", "/forgot-password", "/reset-password", "/verify-email", "/scans/", "/reports/", "/shared/", "/share", "/offline"];

/** Crawlers named explicitly so their access is a decision, not an accident. */
export const ALLOWED_BOTS = ["Googlebot", "Bingbot", "OAI-SearchBot", "ClaudeBot", "PerplexityBot"];

export function isPrivatePath(path: string): boolean {
  return PRIVATE_PREFIXES.some((prefix) => path === prefix.replace(/\/$/, "") || path.startsWith(prefix));
}

/** The URL of `path` in `locale`: English is the plain path, Arabic adds `?lang=ar`. */
export function localizedUrl(path: string, locale: Locale): string {
  const clean = path === "/" ? "/" : path.replace(/\/+$/, "");
  return `${siteUrl()}${clean}${locale === "ar" ? "?lang=ar" : ""}`;
}

export function alternates(path: string, locale: Locale) {
  return {
    canonical: localizedUrl(path, locale),
    languages: { en: localizedUrl(path, "en"), ar: localizedUrl(path, "ar"), "x-default": localizedUrl(path, "en") },
  };
}

export function robotsRules() {
  const disallow = PRIVATE_PREFIXES;
  return {
    rules: [...ALLOWED_BOTS.map((userAgent) => ({ userAgent, allow: "/", disallow })), { userAgent: "*", allow: "/", disallow }],
    sitemap: `${siteUrl()}/sitemap.xml`,
    host: siteUrl(),
  };
}

export function sitemapEntries(articleSlugs: string[], lastModified: Date) {
  const pages = [
    ...PUBLIC_PAGES.map((p) => ({ path: p.path, priority: p.priority })),
    ...articleSlugs.map((slug) => ({ path: `/learn/${slug}`, priority: 0.6 })),
  ];
  return pages.map(({ path, priority }) => ({
    url: localizedUrl(path, "en"),
    lastModified,
    changeFrequency: "weekly" as const,
    priority,
    alternates: { languages: { en: localizedUrl(path, "en"), ar: localizedUrl(path, "ar") } },
  }));
}

/** Home → … → this page, using the names above (and an article title when given). */
export function breadcrumbs(path: string, locale: Locale, leafName?: string): { name: string; url: string }[] {
  const named = (p: string) => PUBLIC_PAGES.find((page) => page.path === p);
  const crumbs = [{ name: named("/")![locale], url: localizedUrl("/", locale) }];
  if (path === "/") return crumbs;
  const parts = path.split("/").filter(Boolean);
  for (let i = 1; i <= parts.length; i++) {
    const p = `/${parts.slice(0, i).join("/")}`;
    const page = named(p);
    const isLeaf = i === parts.length;
    const name = isLeaf && leafName ? leafName : page?.[locale];
    if (name) crumbs.push({ name, url: localizedUrl(p, locale) });
  }
  return crumbs;
}

// --- JSON-LD ---------------------------------------------------------------------

export function organizationLd() {
  return {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: SITE_NAME,
    url: siteUrl(),
    logo: `${siteUrl()}/icons/icon-512.png`,
    description: "Qalaa is a free security suite that checks links, messages and files for phishing and malware, in English and Arabic.",
  };
}

export function websiteLd() {
  return { "@context": "https://schema.org", "@type": "WebSite", name: SITE_NAME, url: siteUrl(), inLanguage: ["en", "ar"] };
}

export function softwareApplicationLd(version?: string) {
  return {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: SITE_NAME,
    url: siteUrl(),
    applicationCategory: "SecurityApplication",
    operatingSystem: "Windows, macOS, Linux, Android",
    ...(version ? { softwareVersion: version } : {}),
    offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    featureList: [
      "Phishing link, scam message and file checks",
      "Browser extension that blocks known malicious sites",
      "Desktop malware scanning with quarantine",
      "End-to-end encrypted password manager with passkeys and TOTP",
      "Home network scanner",
      "Safe DNS over DNS-over-HTTPS",
      "English and Arabic",
    ],
    isAccessibleForFree: true,
  };
}

/** Only for FAQs shown on the page itself. */
export function faqPageLd(items: { q: string; a: string }[]) {
  return {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: items.map((item) => ({ "@type": "Question", name: item.q, acceptedAnswer: { "@type": "Answer", text: item.a } })),
  };
}

export function breadcrumbLd(crumbs: { name: string; url: string }[]) {
  return {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: crumbs.map((crumb, i) => ({ "@type": "ListItem", position: i + 1, name: crumb.name, item: crumb.url })),
  };
}

export function articleLd(article: { title: string; description: string; path: string; locale: Locale }) {
  return {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    headline: article.title,
    description: article.description,
    inLanguage: article.locale,
    url: localizedUrl(article.path, article.locale),
    publisher: { "@type": "Organization", name: SITE_NAME, url: siteUrl() },
    isAccessibleForFree: true,
  };
}

/** Safe to embed in a <script> element: no closing tag can appear in the text. */
export function jsonLdText(data: unknown): string {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}
