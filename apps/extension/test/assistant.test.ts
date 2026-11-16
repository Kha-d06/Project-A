import { describe, expect, it } from "vitest";

import { builtInAnswer, describeCookie, intentOf, toAssistantContext, type PageSummary } from "../src/lib/assistant-core";
import { buildRules } from "../src/lib/blocklist";
import { dictionary, resolveLanguage, setLanguage } from "../src/lib/i18n";
import { DEFAULT_SETTINGS } from "../src/lib/settings";
import { detectTrackers, siteOf, trackerFor } from "../src/lib/trackers";
import type { Verdict } from "../src/lib/types";
import { VERDICTS } from "../src/lib/verdicts";

const summary = (verdict: Verdict): PageSummary => ({
  host: "paypa1-secure.example.com",
  result: {
    verdict,
    host: "paypa1-secure.example.com",
    reasons: [{ severity: "high", title: "Look-alike of paypal.com", explanation: "", source: "SENTINEL" }],
    sources: [],
    limitations: [],
    checkedAt: new Date().toISOString(),
    cacheSeconds: 60,
  },
  cookies: [
    { name: "sid", domain: "paypa1-secure.example.com", thirdParty: false, session: true, days: null },
    { name: "_fbp", domain: "facebook.com", thirdParty: true, session: false, days: 90 },
  ],
  trackers: [{ name: "Meta Pixel", category: "advertising" }],
  cookiesAvailable: true,
});

describe("language", () => {
  it("follows the browser unless the user picks one", () => {
    expect(resolveLanguage("auto", "ar-SA")).toBe("ar");
    expect(resolveLanguage(undefined, "en-GB")).toBe("en");
    expect(resolveLanguage("en", "ar")).toBe("en");
  });

  it("has an Arabic string for every English one", () => {
    const keys = (value: unknown, prefix = ""): string[] =>
      value && typeof value === "object" && !Array.isArray(value)
        ? Object.entries(value).flatMap(([key, child]) => keys(child, `${prefix}${key}.`))
        : [prefix];
    expect(keys(dictionary("ar")).sort()).toEqual(keys(dictionary("en")).sort());
  });

  it("switches verdict labels and never calls anything safe", () => {
    setLanguage("ar");
    expect(VERDICTS.dangerous.label).toBe("خطير");
    setLanguage("en");
    expect(VERDICTS.dangerous.label).toBe("Dangerous");
    for (const language of ["en", "ar"] as const) {
      const text = JSON.stringify(dictionary(language).verdicts);
      expect(text.toLowerCase()).not.toMatch(/\bsafe\b(?!ty)/);
      expect(text).not.toContain("آمن ");
    }
  });
});

describe("pre-load blocking rules", () => {
  it("blocks the server list and the user's list, with the allow list winning", () => {
    const rules = buildRules({ ...DEFAULT_SETTINGS, blocklist: ["mine.example"], allowlist: ["ok.example"] }, ["evil.example"]);
    expect(rules.map((r) => [r.id, r.action.type, r.condition.requestDomains])).toEqual([
      [1, "block", ["evil.example"]],
      [2, "block", ["mine.example"]],
      [3, "allow", ["ok.example"]],
    ]);
    const allow = rules.find((r) => r.id === 3)!;
    expect(allow.priority).toBeGreaterThan(rules[0]!.priority!);
    expect(rules[0]!.condition.resourceTypes).toEqual(["main_frame", "sub_frame"]);
  });

  it("installs nothing while paused and skips the server list when turned off", () => {
    expect(buildRules({ ...DEFAULT_SETTINGS, paused: true, blocklist: ["a.example"] }, ["evil.example"])).toEqual([]);
    expect(buildRules({ ...DEFAULT_SETTINGS, preloadBlocking: false }, ["evil.example"])).toEqual([]);
  });
});

describe("trackers", () => {
  it("recognises tracker subdomains and de-duplicates", () => {
    expect(trackerFor("www.google-analytics.com")?.name).toBe("Google Analytics");
    expect(trackerFor("example.com")).toBeNull();
    expect(detectTrackers(["connect.facebook.net", "facebook.net", "static.hotjar.com"]).map((t) => t.name)).toEqual(["Hotjar", "Meta Pixel"]);
  });

  it("tells first from third party", () => {
    expect(siteOf("shop.example.co.uk")).toBe("example.co.uk");
    expect(siteOf(".accounts.example.com")).toBe("example.com");
    expect(siteOf("bank.com.sa")).toBe("bank.com.sa");
  });
});

describe("cookies", () => {
  it("never copies cookie values", () => {
    const cookie = {
      name: "session",
      value: "super-secret-token",
      domain: ".tracker.example",
      session: false,
      expirationDate: Date.now() / 1000 + 86400 * 30,
    } as chrome.cookies.Cookie;
    const info = describeCookie(cookie, "shop.example.org");
    expect(JSON.stringify(info)).not.toContain("super-secret-token");
    expect(info).toMatchObject({ name: "session", domain: "tracker.example", thirdParty: true, days: 30 });
    const context = toAssistantContext({ ...summary("caution"), cookies: [info] }, true);
    expect(JSON.stringify(context)).not.toContain("super-secret-token");
    expect(context.has_password_field).toBe(true);
  });
});

describe("built-in answers", () => {
  it("understands questions in English and Arabic", () => {
    expect(intentOf("Is this site safe?")).toBe("trust");
    expect(intentOf("هل هذا الموقع آمن؟")).toBe("trust");
    expect(intentOf("What are these cookies?")).toBe("cookies");
    expect(intentOf("ما هي ملفات تعريف الارتباط")).toBe("cookies");
    expect(intentOf("how do I stop trackers")).toBe("trackers");
    expect(intentOf("should I type my password")).toBe("password");
  });

  it("repeats the verdict and never reassures on a warning", () => {
    const answer = builtInAnswer("can I trust this?", summary("suspicious"), "en");
    expect(answer).toContain("Suspicious");
    expect(answer).toContain("Look-alike of paypal.com");
    expect(answer).toMatch(/Do not enter passwords/);
    const clear = builtInAnswer("is it safe", summary("no_known_threat"), "en");
    expect(clear).toContain("not a guarantee");
    expect(builtInAnswer("ملفات تعريف الارتباط؟", summary("caution"), "ar")).toContain("2");
  });
});
