/**
 * SafeSearch for family groups that turned it on (and only for members who chose
 * to follow the group's rules).
 *
 * - Google: adds safe=active to searches.
 * - Bing: adds adlt=strict.
 * - DuckDuckGo: adds kp=1 (strict).
 * - YouTube: sends the "YouTube-Restrict: Moderate" header (restricted mode).
 *
 * Redirect and header rules need access to those sites, which only the person can
 * grant (Options → Allow SafeSearch). A redirect that would not change the address
 * is ignored by the browser, so the rules cannot loop.
 */
export const RULE_SAFE_GOOGLE = 6;
export const RULE_SAFE_BING = 7;
export const RULE_SAFE_DDG = 8;
export const RULE_SAFE_YOUTUBE = 9;
export const SAFE_SEARCH_RULE_IDS = [RULE_SAFE_GOOGLE, RULE_SAFE_BING, RULE_SAFE_DDG, RULE_SAFE_YOUTUBE];

const GOOGLE_DOMAINS = [
  "google.com", "google.ae", "google.com.sa", "google.com.qa", "google.com.kw", "google.com.om",
  "google.com.bh", "google.com.eg", "google.jo", "google.co.uk", "google.fr", "google.de", "google.co.in",
];
const YOUTUBE_DOMAINS = ["youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube-nocookie.com"];

export const SAFE_SEARCH_ORIGINS = [
  ...GOOGLE_DOMAINS.map((d) => `https://www.${d}/*`),
  "https://www.bing.com/*",
  "https://duckduckgo.com/*",
  ...YOUTUBE_DOMAINS.map((d) => `https://*.${d.replace(/^m\./, "")}/*`),
  "https://youtube.com/*",
];

type Rule = chrome.declarativeNetRequest.Rule;
const MAIN = ["main_frame"] as chrome.declarativeNetRequest.ResourceType[];

function addParam(id: number, domains: string[], path: string, key: string, value: string): Rule {
  return {
    id,
    priority: 3,
    action: {
      type: "redirect" as chrome.declarativeNetRequest.RuleActionType,
      redirect: { transform: { queryTransform: { addOrReplaceParams: [{ key, value }] } } },
    },
    condition: { requestDomains: domains, urlFilter: path, resourceTypes: MAIN },
  };
}

export function safeSearchRules(): Rule[] {
  return [
    addParam(RULE_SAFE_GOOGLE, GOOGLE_DOMAINS, "/search?", "safe", "active"),
    addParam(RULE_SAFE_BING, ["bing.com"], "/search?", "adlt", "strict"),
    addParam(RULE_SAFE_DDG, ["duckduckgo.com"], "?q=", "kp", "1"),
    {
      id: RULE_SAFE_YOUTUBE,
      priority: 3,
      action: {
        type: "modifyHeaders" as chrome.declarativeNetRequest.RuleActionType,
        requestHeaders: [
          { header: "YouTube-Restrict", operation: "set" as chrome.declarativeNetRequest.HeaderOperation, value: "Moderate" },
        ],
      },
      condition: {
        requestDomains: YOUTUBE_DOMAINS,
        resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"] as chrome.declarativeNetRequest.ResourceType[],
      },
    },
  ];
}

export async function hasSafeSearchAccess(): Promise<boolean> {
  try {
    return await chrome.permissions.contains({ origins: SAFE_SEARCH_ORIGINS });
  } catch {
    return false;
  }
}
