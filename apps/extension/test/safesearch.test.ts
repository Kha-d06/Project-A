import { describe, expect, it } from "vitest";

import { buildRules } from "../src/lib/blocklist";
import { RULE_SAFE_GOOGLE, RULE_SAFE_YOUTUBE, SAFE_SEARCH_ORIGINS, safeSearchRules } from "../src/lib/safesearch";
import { DEFAULT_SETTINGS } from "../src/lib/settings";

describe("SafeSearch family rule", () => {
  it("adds the strict-search parameters and the YouTube header", () => {
    const rules = safeSearchRules();
    const google = rules.find((r) => r.id === RULE_SAFE_GOOGLE)!;
    expect(google.action.redirect?.transform?.queryTransform?.addOrReplaceParams).toEqual([{ key: "safe", value: "active" }]);
    expect(google.condition.requestDomains).toContain("google.ae");
    const youtube = rules.find((r) => r.id === RULE_SAFE_YOUTUBE)!;
    expect(youtube.action.requestHeaders).toEqual([{ header: "YouTube-Restrict", operation: "set", value: "Moderate" }]);
    expect(SAFE_SEARCH_ORIGINS).toContain("https://www.google.com/*");
  });

  it("applies only when the family rule is on and the person granted site access", () => {
    const ids = (rules: chrome.declarativeNetRequest.Rule[]) => rules.map((r) => r.id).sort();
    expect(ids(buildRules({ ...DEFAULT_SETTINGS, safeSearch: false }, [], true))).not.toContain(RULE_SAFE_GOOGLE);
    expect(ids(buildRules({ ...DEFAULT_SETTINGS, safeSearch: true }, [], false))).not.toContain(RULE_SAFE_GOOGLE);
    expect(ids(buildRules({ ...DEFAULT_SETTINGS, safeSearch: true }, [], true))).toEqual(expect.arrayContaining([6, 7, 8, 9]));
    // It stays on even while checks are paused.
    expect(ids(buildRules({ ...DEFAULT_SETTINGS, safeSearch: true, paused: true }, ["evil.example"], true))).toEqual([6, 7, 8, 9]);
  });
});
