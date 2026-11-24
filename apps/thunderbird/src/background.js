/**
 * Checks each email when it is opened, on this computer. The rule pack is
 * downloaded from the Qalaa server once a day; the only thing sent about a
 * message is its bare links (no query strings), for a reputation lookup.
 */
import { analyzeLocally, compilePack, linkReputationFindings, linksToCheck, verdict } from "./lib/analysis.js";
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

async function linkResults(serverUrl, urls) {
  if (!urls.length) return { findings: [], checked: true };
  try {
    const response = await fetch(`${serverUrl}/api/v1/email/links`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    if (!response.ok) throw new Error(String(response.status));
    const body = await response.json();
    return { findings: linkReputationFindings(body.results), checked: true };
  } catch {
    return { findings: [], checked: false };
  }
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
    const links = await linkResults(serverUrl, linksToCheck(email));
    const result = verdict([...analyzeLocally(email, pack, lang), ...links.findings], lang);
    const limitations = [];
    if (!pack) limitations.push(s.rulesUnavailable);
    if (!links.checked) limitations.push(s.linksUnchecked);
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
