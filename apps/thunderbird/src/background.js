/**
 * Checks each email when it is opened, on this computer. The rule pack is
 * downloaded once a day and the threat list's hash prefixes every 6 hours.
 * Nothing from a message is sent: links are matched by hash prefix
 * (lib/threat-prefix.js), and only on a prefix hit are a few 4-byte prefixes,
 * mixed with random ones, sent to fetch the full hashes for a local compare.
 */
import { analyzeLocally, compilePack, linksIn, verdict } from "./lib/analysis.js";
import { LIST_REFRESH_MS, createLinkChecker } from "./lib/threat-prefix.js";
import { language, t } from "./lib/i18n.js";
import { badgeFor, toCheckRequest } from "./lib/mail.js";

const PACK_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const results = new Map(); // message id -> { state, result?, error? }
let compiled = null;

async function config() {
  return messenger.storage.local.get({ serverUrl: "", autoCheck: true });
}

/** The cached rule pack, refreshed when older than a day. Never sends anything about mail. */
async function rulePack(serverUrl) {
  const { pack, packFetchedAt = 0 } = await messenger.storage.local.get(["pack", "packFetchedAt"]);
  if (pack && Date.now() - packFetchedAt < PACK_MAX_AGE_MS) {
    if (!compiled || compiled.version !== pack.version) compiled = compilePack(pack);
    return compiled;
  }
  try {
    const response = await fetch(`${serverUrl}/api/v1/email/rules`);
    if (!response.ok) throw new Error(String(response.status));
    const fresh = await response.json();
    await messenger.storage.local.set({ pack: fresh, packFetchedAt: Date.now() });
    compiled = compilePack(fresh);
  } catch {
    compiled = pack ? compilePack(pack) : null;
  }
  return compiled;
}

/** The downloaded prefix list, refreshed when older than 6 hours (kept if a refresh fails). */
async function threatList(serverUrl) {
  const { threatList: stored } = await messenger.storage.local.get("threatList");
  if (stored && stored.serverUrl === serverUrl && Date.now() - stored.fetchedAt < LIST_REFRESH_MS) return stored;
  try {
    const response = await fetch(`${serverUrl}/api/v1/email/threat-prefixes`);
    if (!response.ok) throw new Error(String(response.status));
    const body = await response.json();
    const fresh = { serverUrl, prefixes: body.prefixes, sources: body.sources, fetchedAt: Date.now() };
    await messenger.storage.local.set({ threatList: fresh });
    return fresh;
  } catch {
    return stored?.serverUrl === serverUrl ? stored : null;
  }
}

let checker = null;
function linkChecker(serverUrl) {
  if (checker?.serverUrl !== serverUrl) {
    checker = {
      serverUrl,
      check: createLinkChecker({
        getList: () => threatList(serverUrl),
        fetchHashes: async (prefixes) => {
          const response = await fetch(`${serverUrl}/api/v1/email/threat-hashes`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prefixes }),
          });
          if (!response.ok) throw new Error("lookup failed");
          return (await response.json()).matches;
        },
      }),
    };
  }
  return checker.check;
}

async function setBadge(tabId, risk) {
  const badge = badgeFor(risk);
  await messenger.messageDisplayAction.setBadgeText({ tabId, text: badge.text });
  if (badge.text) await messenger.messageDisplayAction.setBadgeBackgroundColor({ tabId, color: badge.color });
}

export async function checkMessage(message) {
  const { serverUrl } = await config();
  if (!serverUrl) return { state: "setup" };
  if (!(await messenger.permissions.contains({ origins: [`${serverUrl}/*`] }))) return { state: "setup" };
  const cached = results.get(message.id);
  if (cached && cached.state !== "error") return cached;
  results.set(message.id, { state: "checking" });
  try {
    const lang = language();
    const s = t();
    const email = toCheckRequest(await messenger.messages.getFull(message.id), message);
    const pack = await rulePack(serverUrl);
    const links = await linkChecker(serverUrl)(linksIn(email), lang);
    const result = verdict([...analyzeLocally(email, pack, lang), ...links.findings], lang);
    const limitations = [...links.limitations];
    if (!pack) limitations.push(s.rulesUnavailable);
    const entry = { state: "done", result: { ...result, limitations } };
    results.set(message.id, entry);
    if (results.size > 500) results.delete(results.keys().next().value);
    return entry;
  } catch (error) {
    const entry = { state: "error", error: error instanceof Error ? error.message : String(error) };
    results.set(message.id, entry);
    return entry;
  }
}

messenger.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
  await setBadge(tab.id, null);
  const { autoCheck } = await config();
  if (!autoCheck || !message) return;
  const entry = await checkMessage(message);
  if (entry.state === "done") await setBadge(tab.id, entry.result.risk);
});

messenger.runtime.onMessage.addListener(async (request) => {
  if (request?.type !== "result") return undefined;
  const message = await messenger.messageDisplay.getDisplayedMessage(request.tabId);
  if (!message) return { state: "none" };
  const entry = await checkMessage(message);
  if (entry.state === "done") await setBadge(request.tabId, entry.result.risk);
  return entry;
});
