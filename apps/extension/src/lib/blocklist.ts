/**
 * Blocking known dangerous domains before they load, with declarativeNetRequest.
 *
 * The extension downloads the whole list (so nothing about browsing is sent) and
 * installs it as a few dynamic "block" rules matched inside the browser. A
 * blocked navigation fails with ERR_BLOCKED_BY_CLIENT; the background then shows
 * SENTINEL's warning page in that tab. "Continue anyway" adds a session-scoped
 * allow rule for that domain only.
 *
 * Block rules need no host permissions. Rule IDs:
 *   1      server blocklist (feeds + verified community reports)
 *   2      the user's own block list
 *   3      the user's allow list (higher priority, so it wins)
 *   4      optional tracker blocking (third-party requests only)
 *   5      a family or organisation group's list, when the user applies it
 *   1000+  session allowances from "Continue anyway"
 */
import { fetchBlocklist } from "./api";
import { TRACKER_DOMAINS } from "./trackers";
import type { Settings } from "./settings";

export const RULE_SERVER = 1;
export const RULE_USER_BLOCK = 2;
export const RULE_USER_ALLOW = 3;
export const RULE_TRACKERS = 4;
export const RULE_FAMILY = 5;
const TRACKER_TYPES = ["script", "xmlhttprequest", "image", "ping", "sub_frame"] as chrome.declarativeNetRequest.ResourceType[];
const SESSION_RULE_BASE = 1000;
const STORE_KEY = "blocklist";
export const REFRESH_MINUTES = 6 * 60;
const FRAME_TYPES = ["main_frame", "sub_frame"] as chrome.declarativeNetRequest.ResourceType[];

export interface StoredBlocklist {
  version: string;
  hosts: string[];
  fetchedAt: string;
  sources: string[];
}

export function hasDnr(): boolean {
  return typeof chrome !== "undefined" && !!chrome.declarativeNetRequest?.updateDynamicRules;
}

export async function storedBlocklist(): Promise<StoredBlocklist | null> {
  const stored = await chrome.storage.local.get(STORE_KEY);
  return (stored[STORE_KEY] as StoredBlocklist | undefined) ?? null;
}

function rule(id: number, priority: number, type: "block" | "allow", domains: string[]): chrome.declarativeNetRequest.Rule {
  return {
    id,
    priority,
    action: { type: type as chrome.declarativeNetRequest.RuleActionType },
    condition: { requestDomains: domains, resourceTypes: FRAME_TYPES },
  };
}

/** The dynamic rules for the current settings and blocklist. Exported for tests. */
export function buildRules(settings: Settings, serverHosts: string[]): chrome.declarativeNetRequest.Rule[] {
  const rules: chrome.declarativeNetRequest.Rule[] = [];
  if (settings.paused) return rules;
  if (settings.preloadBlocking && serverHosts.length) rules.push(rule(RULE_SERVER, 1, "block", serverHosts));
  if (settings.blocklist.length) rules.push(rule(RULE_USER_BLOCK, 1, "block", settings.blocklist));
  if (settings.familyBlocklist.length) rules.push(rule(RULE_FAMILY, 1, "block", settings.familyBlocklist));
  if (settings.blockTrackers) {
    rules.push({
      id: RULE_TRACKERS,
      priority: 1,
      action: { type: "block" as chrome.declarativeNetRequest.RuleActionType },
      condition: {
        requestDomains: TRACKER_DOMAINS,
        resourceTypes: TRACKER_TYPES,
        domainType: "thirdParty" as chrome.declarativeNetRequest.DomainType,
      },
    });
  }
  if (settings.allowlist.length) rules.push(rule(RULE_USER_ALLOW, 2, "allow", settings.allowlist));
  return rules;
}

export async function applyRules(settings: Settings): Promise<void> {
  if (!hasDnr()) return;
  const list = await storedBlocklist();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [RULE_SERVER, RULE_USER_BLOCK, RULE_USER_ALLOW, RULE_TRACKERS, RULE_FAMILY],
    addRules: buildRules(settings, list?.hosts ?? []),
  });
}

/** Downloads the list if it is missing or older than REFRESH_MINUTES. */
export async function refreshBlocklist(settings: Settings, force = false): Promise<StoredBlocklist | null> {
  const current = await storedBlocklist();
  const fresh = current && Date.now() - new Date(current.fetchedAt).getTime() < REFRESH_MINUTES * 60_000;
  if (!settings.preloadBlocking || (fresh && !force)) return current;
  try {
    const response = await fetchBlocklist(settings.serverUrl);
    const next: StoredBlocklist = {
      version: response.version,
      hosts: response.hosts,
      sources: response.sources,
      fetchedAt: new Date().toISOString(),
    };
    await chrome.storage.local.set({ [STORE_KEY]: next });
    await applyRules(settings);
    return next;
  } catch {
    return current; // keep using the previous list
  }
}

function matches(host: string, domains: string[]): boolean {
  const lower = host.toLowerCase();
  return domains.some((domain) => lower === domain || lower.endsWith(`.${domain}`));
}

/** True when the downloaded list covers this host (used for the warning page). */
export async function onServerBlocklist(host: string): Promise<boolean> {
  const list = await storedBlocklist();
  return !!list && matches(host, list.hosts);
}

/** Lets one domain through for this browser session after "Continue anyway". */
export async function allowDomainForSession(host: string): Promise<void> {
  if (!hasDnr()) return;
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  if (existing.some((r) => r.condition.requestDomains?.includes(host))) return;
  const id = Math.max(SESSION_RULE_BASE - 1, ...existing.map((r) => r.id)) + 1;
  await chrome.declarativeNetRequest.updateSessionRules({ addRules: [rule(id, 3, "allow", [host])] });
}
