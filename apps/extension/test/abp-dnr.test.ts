/** EasyList / EasyPrivacy -> declarativeNetRequest at build time (Wave 4.D). */
import { describe, expect, it } from "vitest";

// @ts-expect-error: plain ES module without type declarations
import { convertLine, convertList } from "../scripts/abp-dnr.mjs";
// @ts-expect-error: plain ES module without type declarations
import { createManifest } from "../scripts/manifest.mjs";
import { AD_RULESETS, RULE_LIST_ALLOW, adRulesetsFor, buildRules, bundledAdRulesets } from "../src/lib/blocklist";
import { DEFAULT_SETTINGS } from "../src/lib/settings";

type Rule = { id: number; priority: number; action: { type: string }; condition: Record<string, unknown> };

describe("converting filter rules", () => {
  it("carries patterns and supported options over", () => {
    expect(convertLine("||ads.example^").rule).toEqual({ priority: 1, action: { type: "block" }, condition: { urlFilter: "||ads.example^" } });
    expect(convertLine("||t.example^$third-party,script,~image,domain=news.example|~sub.news.example").rule.condition).toEqual({
      urlFilter: "||t.example^",
      domainType: "thirdParty",
      resourceTypes: ["script"],
      excludedResourceTypes: ["image"],
      initiatorDomains: ["news.example"],
      excludedInitiatorDomains: ["sub.news.example"],
    });
    expect(convertLine("/banner/*/ad_$subdocument,match-case").rule.condition).toMatchObject({ resourceTypes: ["sub_frame"], isUrlFilterCaseSensitive: true });
    expect(convertLine("||x.example^$important").rule.priority).toBe(3);
  });

  it("turns exceptions into allow rules, and $document exceptions into allowAllRequests", () => {
    expect(convertLine("@@||cdn.example^").rule).toMatchObject({ priority: 2, action: { type: "allow" } });
    expect(convertLine("@@||shop.example^$document").rule).toMatchObject({ action: { type: "allowAllRequests" }, condition: { resourceTypes: ["main_frame", "sub_frame"] } });
  });

  it("skips what DNR can't express instead of guessing", () => {
    expect(convertLine("example.com##.ad-banner")).toEqual({ skip: "cosmetic" });
    expect(convertLine("example.com#@#.ad")).toEqual({ skip: "cosmetic" });
    expect(convertLine("example.com##+js(nobab)")).toEqual({ skip: "cosmetic" });
    expect(convertLine("/^https?:\\/\\/ad[0-9]+\\./")).toEqual({ skip: "regex" });
    expect(convertLine("||x.example^$redirect=noopjs")).toEqual({ skip: "option:redirect" });
    expect(convertLine("||x.example^$csp=script-src 'none'")).toEqual({ skip: "option:csp" });
    expect(convertLine("*$third-party")).toEqual({ skip: "too_broad" });
    expect(convertLine("||пример.рф^")).toEqual({ skip: "non_ascii" });
    expect(convertLine("! comment")).toBeNull();
    expect(convertLine("[Adblock Plus 2.0]")).toBeNull();
  });

  it("honours $badfilter, puts exceptions and whole-host rules first, and caps the list", () => {
    const text = ["||keep.example/path/", "||gone.example^", "||gone.example^$badfilter", "@@||ok.example^", "||host.example^", "example.org##.x"].join("\n");
    const { rules, report } = convertList(text, { cap: 3 });
    const filters = (rules as Rule[]).map((r) => r.condition.urlFilter);
    expect(filters).toEqual(["||ok.example^", "||host.example^", "||keep.example/path/"]);
    expect((rules as Rule[]).map((r) => r.id)).toEqual([1, 2, 3]);
    expect(report).toMatchObject({ badfilter: 1, skipped: { cosmetic: 1 }, capped: 0, converted: 3 });
    expect(convertList(text, { cap: 2 }).report.capped).toBe(1);
  });
});

describe("the rulesets in the extension", () => {
  it("are declared, disabled, only when the build has them", () => {
    const resources = [{ id: "easylist", enabled: false, path: "rules/easylist.json" }];
    const m = createManifest({ version: "1.0.0", serverOrigin: "https://q.example", ruleResources: resources });
    expect(m.declarative_net_request.rule_resources).toEqual(resources);
    expect(createManifest({ version: "1.0.0", serverOrigin: "https://q.example" })).not.toHaveProperty("declarative_net_request");
    expect(m.permissions).not.toContain("declarativeNetRequestWithHostAccess");
  });

  it("are switched on only with ad blocking on and checks not paused", () => {
    const bundled = bundledAdRulesets({ declarative_net_request: { rule_resources: [{ id: "easylist" }, { id: "easyprivacy" }, { id: "other" }] } } as never);
    expect(bundled).toEqual(AD_RULESETS);
    expect(adRulesetsFor({ ...DEFAULT_SETTINGS }, bundled)).toEqual({ enable: [], disable: bundled });
    expect(adRulesetsFor({ ...DEFAULT_SETTINGS, blockAds: true }, bundled)).toEqual({ enable: bundled, disable: [] });
    expect(adRulesetsFor({ ...DEFAULT_SETTINGS, blockAds: true, paused: true }, bundled)).toEqual({ enable: [], disable: bundled });
    expect(DEFAULT_SETTINGS.blockAds).toBe(false);
  });

  it("leave sites on the allow list alone", () => {
    const rules = buildRules({ ...DEFAULT_SETTINGS, blockAds: true, allowlist: ["news.example"] }, []) as Rule[];
    expect(rules.find((r) => r.id === RULE_LIST_ALLOW)).toMatchObject({ action: { type: "allowAllRequests" }, condition: { requestDomains: ["news.example"] } });
    expect((buildRules({ ...DEFAULT_SETTINGS, blockAds: false, allowlist: ["news.example"] }, []) as Rule[]).some((r) => r.id === RULE_LIST_ALLOW)).toBe(false);
  });
});
