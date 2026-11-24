/**
 * Checks each email when it is opened, if the person set a Qalaa server and
 * allowed the add-on to reach it. Results are kept in memory for the popup.
 */
import { badgeFor, toCheckRequest } from "./lib/mail.js";

const results = new Map(); // message id -> { state, result?, error? }

async function config() {
  const stored = await messenger.storage.local.get({ serverUrl: "", autoCheck: true });
  return stored;
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
    const full = await messenger.messages.getFull(message.id);
    const response = await fetch(`${serverUrl}/api/v1/email/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept-Language": messenger.i18n.getUILanguage() },
      body: JSON.stringify(toCheckRequest(full, message)),
    });
    if (!response.ok) throw new Error(`the server answered ${response.status}`);
    const entry = { state: "done", result: await response.json() };
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
