import { describe, expect, it } from "vitest";

import { ar } from "./i18n/ar";
import { en } from "./i18n/en";
import { llmsFullTxt, llmsTxt } from "./llms";
import { ALLOWED_BOTS, PUBLIC_PAGES, siteUrl, alternates, breadcrumbLd, breadcrumbs, faqPageLd, isPrivatePath, jsonLdText, localizedUrl, robotsRules, sitemapEntries, softwareApplicationLd } from "./seo";

describe("URLs and hreflang", () => {
  it("the site address is set per deployment, at request time", () => {
    const before = process.env.SENTINEL_SITE_URL;
    process.env.SENTINEL_SITE_URL = "https://qalaa.test/";
    expect(localizedUrl("/scan", "ar")).toBe("https://qalaa.test/scan?lang=ar");
    if (before === undefined) delete process.env.SENTINEL_SITE_URL;
    else process.env.SENTINEL_SITE_URL = before;
  });

  it("English is the plain path, Arabic adds ?lang=ar, x-default is English", () => {
    expect(localizedUrl("/scan/", "en")).toBe(`${siteUrl()}/scan`);
    expect(localizedUrl("/", "ar")).toBe(`${siteUrl()}/?lang=ar`);
    expect(alternates("/download", "ar")).toEqual({
      canonical: `${siteUrl()}/download?lang=ar`,
      languages: { en: `${siteUrl()}/download`, ar: `${siteUrl()}/download?lang=ar`, "x-default": `${siteUrl()}/download` },
    });
  });

  it("private routes are recognised", () => {
    for (const path of ["/dashboard", "/dashboard/vault", "/sign-in", "/scans/123", "/shared/abc", "/api/v1/scans"]) expect(isPrivatePath(path)).toBe(true);
    for (const path of ["/", "/scan", "/learn/parcel-delivery-fees", "/download"]) expect(isPrivatePath(path)).toBe(false);
    for (const page of PUBLIC_PAGES) expect(isPrivatePath(page.path)).toBe(false);
  });
});

describe("robots and sitemap", () => {
  it("names the search and AI citation bots, blocks private routes for everyone", () => {
    const robots = robotsRules();
    expect(robots.rules.map((r) => r.userAgent)).toEqual([...ALLOWED_BOTS, "*"]);
    expect(ALLOWED_BOTS).toEqual(["Googlebot", "Bingbot", "OAI-SearchBot", "ClaudeBot", "PerplexityBot"]);
    for (const rule of robots.rules) {
      expect(rule.allow).toBe("/");
      expect(rule.disallow).toContain("/dashboard");
      expect(rule.disallow).toContain("/api/");
    }
    expect(robots.sitemap).toBe(`${siteUrl()}/sitemap.xml`);
  });

  it("lists every public page and article with both languages", () => {
    const entries = sitemapEntries(["parcel-delivery-fees"], new Date("2026-11-24"));
    expect(entries).toHaveLength(PUBLIC_PAGES.length + 1);
    expect(entries.at(-1)).toMatchObject({ url: `${siteUrl()}/learn/parcel-delivery-fees`, alternates: { languages: { ar: `${siteUrl()}/learn/parcel-delivery-fees?lang=ar` } } });
    expect(entries.every((e) => !isPrivatePath(new URL(e.url).pathname))).toBe(true);
  });
});

describe("JSON-LD", () => {
  it("breadcrumbs follow the path, in the page's language", () => {
    expect(breadcrumbs("/help/scammed", "en").map((c) => c.name)).toEqual(["Home", "If you've been scammed"]);
    expect(breadcrumbs("/learn/x", "ar", "عنوان").map((c) => c.name)).toEqual(["الرئيسية", "تعلّم كشف الاحتيال", "عنوان"]);
    const ld = breadcrumbLd(breadcrumbs("/download", "en"));
    expect(ld.itemListElement.map((i) => i.position)).toEqual([1, 2]);
  });

  it("the FAQ markup is exactly the FAQ shown on the home page, in both languages", () => {
    for (const dict of [en, ar]) {
      const ld = faqPageLd(dict.home.faq);
      expect(ld.mainEntity.map((q) => q.name)).toEqual(dict.home.faq.map((f) => f.q));
      expect(ld.mainEntity.map((q) => q.acceptedAnswer.text)).toEqual(dict.home.faq.map((f) => f.a));
    }
  });

  it("the app is free and names its platforms; text is safe inside a script element", () => {
    const app = softwareApplicationLd();
    expect(app).toMatchObject({ "@type": "SoftwareApplication", applicationCategory: "SecurityApplication", offers: { price: "0" }, isAccessibleForFree: true });
    expect(app.operatingSystem).toBe("Windows, macOS, Linux, Android");
    expect(jsonLdText({ a: "</script><script>alert(1)</script>" })).not.toContain("</script>");
    expect(JSON.parse(jsonLdText({ a: "<b>" }))).toEqual({ a: "<b>" });
  });
});

describe("llms.txt", () => {
  it("links every public page and states its limits", () => {
    const short = llmsTxt();
    expect(short.startsWith("# Qalaa\n\n> ")).toBe(true);
    for (const page of PUBLIC_PAGES) expect(short).toContain(page.en);
    expect(short).toContain(`${siteUrl()}/llms-full.txt`);
    const full = llmsFullTxt();
    for (const platform of ["Windows", "macOS", "Linux", "Android", "Thunderbird", "iOS"]) expect(full).toContain(platform);
    expect(full).toMatch(/## Limits/);
    expect(full).toMatch(/not a guarantee/);
    // Honest wording: never calls anything safe.
    expect(`${short}\n${full}`).not.toMatch(/\bis safe\b|100%|guarantee(?!:)(?! it)(?=d)/i);
  });
});
