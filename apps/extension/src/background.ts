import { installNoise, isBypassed, originSeed } from "./lib/fingerprint";
import { isBankingHost, safePayLink } from "./lib/safepay";
import * as api from "./lib/api";
import { clearAlerts, listAlerts, recordAlert } from "./lib/alerts";
import { builtInAnswer, describeCookie, toAssistantContext, type CookieInfo, type PageSummary } from "./lib/assistant-core";
import {
  REFRESH_MINUTES,
  allowDomainForSession,
  applyRules,
  onServerBlocklist,
  refreshBlocklist,
  storedBlocklist,
} from "./lib/blocklist";
import { clearCache } from "./lib/cache";
import { initLanguage, language, t } from "./lib/i18n";
import { WrongMasterPassword, type VaultDoc, unlockVault } from "../../web/src/lib/vault";
import { fillLoginForm, loginsFor, refusal } from "./lib/autofill";
import { parseOtpauth, secondsRemaining, totpCode } from "../../web/src/lib/totp";
import type { Request, Response, Status, VaultStatus } from "./lib/messages";
import { refreshThreatList } from "./lib/local-check";
import { allowForSession, assessDownload, assessUrl, assessUrlOnServer, isAllowedForSession } from "./lib/protection";
import { DEFAULT_SETTINGS, SEARCH_ORIGINS, loadSettings, saveSettings, type Settings, normalizeHostEntry } from "./lib/settings";
import type { CheckResult, ProtectionState, Verdict } from "./lib/types";
import { detectTrackers, siteOf } from "./lib/trackers";
import {
  SCREEN_TIME_ALARM,
  USAGE_KEY,
  addMinute,
  blockReason,
  sameRule,
  shouldReport,
  usageFor,
  type ScreenTimeUsage,
} from "./lib/screentime";
import { checkableUrl } from "./lib/urls";
import { BADGE_COLORS, VERDICTS, shouldInterrupt } from "./lib/verdicts";

declare const __TARGET_BROWSER__: string;
const IS_FIREFOX = typeof __TARGET_BROWSER__ === "string" && __TARGET_BROWSER__ === "firefox";
// Extensions cannot open Firefox's new-tab page, so a blank page is the fallback there.
const NEW_TAB_URL = IS_FIREFOX ? "about:blank" : "chrome://newtab/";

const ACCOUNT_KEY = "account";
const HOVER_SCRIPT_ID = "sentinel-hover";
const ASSISTANT_SCRIPT_ID = "sentinel-assistant";
const SEARCH_SCRIPT_ID = "sentinel-search";

const BLOCKLIST_ALARM = "sentinel-blocklist";
const MAX_COOKIE_SITES = 20;
const MENU_LINK = "sentinel-scan-link";
const MENU_PAGE = "sentinel-scan-page";
const WARNING_VERDICTS = new Set(["dangerous", "suspicious", "caution", "blocked_by_you", "blocked_by_family"]);

// Settings live in one stored object that several flows read, change and write back:
// messages from the options page and popup, account refreshes (sent by every options
// page as it opens), the screen-time and blocklist alarms. Each flow also applies the
// result (network rules, content scripts). If two of them interleave, one writes back
// a stale copy over the other's change (for example turning the assistant back off),
// or applies rules from an out-of-date copy. So they run one at a time, in order.
let settingsQueue: Promise<unknown> = Promise.resolve();
function serialized<T>(task: () => Promise<T>): Promise<T> {
  const run = settingsQueue.then(task, task);
  settingsQueue = run.catch(() => undefined);
  return run;
}
/** Messages that change settings, the account or the rules applied from them. */
const SERIALIZED_MESSAGES = new Set(["settings", "refresh-account", "enroll", "link", "unlink", "apply-rules"]);

/** Last result per tab, for the popup. Lost if the worker restarts; the popup then re-checks. */
const tabResults = new Map<number, { url: string; result: CheckResult | null }>();
/** The assistant's last page summary per tab, so questions can be answered from it. */
const tabSummaries = new Map<number, { url: string; summary: PageSummary }>();

// --- Helpers --------------------------------------------------------------------------

async function cachedAccount(): Promise<api.AccountLink | null> {
  const stored = await chrome.storage.local.get(ACCOUNT_KEY);
  return (stored[ACCOUNT_KEY] as api.AccountLink | undefined) ?? null;
}

async function refreshAccount(settings: Settings): Promise<api.AccountLink | null> {
  try {
    const account = await api.accountLink(settings.serverUrl);
    await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
    await applyFamilyList(account);
    return account;
  } catch {
    return cachedAccount();
  }
}

/** Maps local outcomes onto the verdicts the API records; null means "nothing to record". */
function eventVerdict(verdict: Verdict): string | null {
  if (verdict === "blocked_by_you" || verdict === "blocked_by_family") return "dangerous";
  if (verdict === "skipped" || verdict === "allowed_by_you") return null;
  return verdict;
}

/** Events leave the browser only for a linked account that opted in to syncing them. */
async function syncEvent(settings: Settings, kind: string, url: string, verdict: Verdict) {
  const recorded = eventVerdict(verdict);
  const account = await cachedAccount();
  if (recorded && account?.linked && account.sync_events) {
    await api.reportEvent(settings.serverUrl, { kind, url, verdict: recorded });
  }
}

async function protectionState(settings: Settings): Promise<ProtectionState> {
  if (settings.paused) return "paused";
  return (await api.getCredentials()) ? "active" : "not_enrolled";
}

async function setBadge(tabId: number, result: CheckResult | null) {
  const presentation = result ? VERDICTS[result.verdict] : null;
  await chrome.action.setBadgeText({ tabId, text: presentation?.badge ?? "" });
  if (presentation) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[presentation.tone] });
  }
}

async function refreshGlobalBadge(settings: Settings) {
  await chrome.action.setBadgeText({ text: settings.paused ? "off" : "" });
  await chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.neutral });
}

function warningPageUrl(target: string): string {
  return chrome.runtime.getURL(`warning.html?u=${encodeURIComponent(target)}`);
}

async function notify(id: string, title: string, message: string, buttons?: { title: string }[]) {
  const options: chrome.notifications.NotificationCreateOptions = {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
    title,
    message,
    priority: 1,
  };
  // Firefox does not support notification buttons; the message then says where to act.
  if (buttons && !IS_FIREFOX) options.buttons = buttons;
  else if (buttons) options.message = `${message} ${t().notifications.downloadsPanel}`;
  await chrome.notifications.create(id, options);
}

/** A group's block list is applied only because the account holder chose to. */
async function applyFamilyList(account: api.AccountLink | null) {
  const familyBlocklist = account?.linked ? (account.family_blocklist ?? []) : [];
  const familyGroups = account?.linked ? (account.family_groups ?? []) : [];
  const safeSearch = Boolean(account?.linked && account.safe_search);
  const lockProtection = Boolean(account?.linked && account.lock_protection);
  const screenTime = account?.linked ? (account.screen_time ?? null) : null;
  const current = await loadSettings();
  if (!sameRule(current.screenTime, screenTime)) {
    await saveSettings({ screenTime });
    await updateScreenTime(false);
  }
  const unchanged =
    JSON.stringify([current.familyBlocklist, current.familyGroups, current.safeSearch, current.lockProtection]) ===
    JSON.stringify([familyBlocklist, familyGroups, safeSearch, lockProtection]);
  if (unchanged) return;
  // A locked group turns protection back on if it was paused.
  const next = await saveSettings({ familyBlocklist, familyGroups, safeSearch, lockProtection, ...(lockProtection ? { paused: false } : {}) });
  await refreshGlobalBadge(next);
  await syncContentScripts(next);
  await clearCache();
  await applyRules(next);
}

// --- Family screen time ---------------------------------------------------------------

function timeUpUrl(reason: string): string {
  return chrome.runtime.getURL(`timeup.html?r=${encodeURIComponent(reason)}`);
}

/** A minute counts only while the person is at the computer and a web page has focus. */
async function browsingNow(): Promise<boolean> {
  const state = await chrome.idle?.queryState(60).catch(() => "active" as const);
  if (state && state !== "active") return false;
  const window = await chrome.windows.getLastFocused().catch(() => null);
  if (!window?.focused) return false;
  const [tab] = await chrome.tabs.query({ active: true, windowId: window.id });
  return Boolean(tab?.url && /^https?:/.test(tab.url));
}

/** Runs every minute: counts use, reports the day's total, and blocks or unblocks. */
async function updateScreenTime(count: boolean) {
  const settings = await loadSettings();
  const rule = settings.screenTime;
  const now = new Date();
  const stored = await chrome.storage.local.get(USAGE_KEY);
  let usage = usageFor(stored[USAGE_KEY] as ScreenTimeUsage | undefined, now);
  if (rule && count && !blockReason(rule, usage, now) && (await browsingNow())) {
    usage = addMinute(usage, now);
  }
  if (rule && shouldReport(usage, rule) && (await api.reportScreenTime(settings.serverUrl, usage.day, usage.minutes))) {
    usage = { ...usage, reported: usage.minutes };
  }
  await chrome.storage.local.set({ [USAGE_KEY]: usage });

  const reason = blockReason(rule, usage, now);
  if (reason === settings.screenTimeBlocked) return;
  const next = await saveSettings({ screenTimeBlocked: reason });
  await applyRules(next);
  if (!reason) return;
  // Pages already open stop at the time's-up page too.
  for (const tab of await chrome.tabs.query({})) {
    if (tab.id !== undefined && tab.url && /^https?:/.test(tab.url) && !tab.url.startsWith(settings.serverUrl)) {
      await chrome.tabs.update(tab.id, { url: timeUpUrl(reason) }).catch(() => undefined);
    }
  }
}

// --- Page navigation ------------------------------------------------------------------

// The last page each tab opened without a warning: where "Go back to safety" goes.
// Browser history is not reliable for this, because a blocked page may already have
// been added to it before the warning replaced it.
const SAFE_PREFIX = "safe:";

async function rememberSafePage(tabId: number, url: string) {
  await chrome.storage.session.set({ [SAFE_PREFIX + tabId]: url });
}

async function safePageFor(tabId: number): Promise<string> {
  const stored = await chrome.storage.session.get(SAFE_PREFIX + tabId);
  return (stored[SAFE_PREFIX + tabId] as string | undefined) ?? NEW_TAB_URL;
}

// If enrollment failed (server down at install time), retry quietly on later
// navigations, at most every few minutes.
const ENROLL_RETRY_MS = 5 * 60 * 1000;
let lastEnrollAttempt = 0;

async function ensureEnrolled(settings: Settings) {
  if (settings.paused || (await api.getCredentials())) return;
  if (Date.now() - lastEnrollAttempt < ENROLL_RETRY_MS) return;
  lastEnrollAttempt = Date.now();
  await api.enroll(settings.serverUrl).catch(() => undefined);
}

async function handleNavigation(tabId: number, url: string, committed = false) {
  const settings = await loadSettings();
  await ensureEnrolled(settings);
  const result = await assessUrl(url, settings);
  tabResults.set(tabId, { url, result });
  await setBadge(tabId, result);
  const interrupt = result !== null && shouldInterrupt(result.verdict, settings.warnOnSuspicious);
  if (!result || !interrupt || (result.verdict !== "blocked_by_you" && result.verdict !== "blocked_by_family" && (await isAllowedForSession(result.host)))) {
    if (committed && url.startsWith("http")) await rememberSafePage(tabId, url);
    return;
  }

  await chrome.tabs.update(tabId, { url: warningPageUrl(url) });
  await recordAlert({ host: result.host, verdict: result.verdict, kind: "page", at: new Date().toISOString() }, settings.keepLocalAlerts);
  await syncEvent(settings, "warning_shown", url, result.verdict);
}

// Checked as early as possible, and again once the navigation commits, because a
// server-side redirect may have changed the destination in between.
chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, frameId, url }) => {
  if (frameId === 0) void handleNavigation(tabId, url);
});
chrome.webNavigation.onCommitted.addListener(({ tabId, frameId, url }) => {
  if (frameId === 0) void handleNavigation(tabId, url, true);
});
// A navigation stopped by a declarativeNetRequest block rule fails inside the
// browser before any request leaves it. Show Qalaa's warning page instead of
// the browser's generic error.
chrome.webNavigation.onErrorOccurred.addListener(({ tabId, frameId, url, error }) => {
  if (frameId !== 0 || !url.startsWith("http")) return;
  void (async () => {
    const settings = await loadSettings();
    const host = checkableUrl(url)?.hostname;
    if (!host) return;
    const blockedByRule = /BLOCKED_BY_CLIENT|NS_ERROR_ABORT/i.test(error);
    if (blockedByRule && settings.screenTime && settings.screenTimeBlocked) {
      await chrome.tabs.update(tabId, { url: timeUpUrl(settings.screenTimeBlocked) });
      return;
    }
    const listed = settings.blocklist.some((d) => host === d || host.endsWith(`.${d}`)) || (await onServerBlocklist(host));
    if (!blockedByRule || !listed) return;
    // The navigation check may already have shown the warning page.
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab?.url?.startsWith(chrome.runtime.getURL("warning.html")) || tab?.pendingUrl?.startsWith(chrome.runtime.getURL("warning.html"))) return;
    await chrome.tabs.update(tabId, { url: warningPageUrl(url) });
    const result = await verdictFor(url, settings);
    if (result) {
      await recordAlert({ host, verdict: result.verdict, kind: "page", at: new Date().toISOString() }, settings.keepLocalAlerts);
      await syncEvent(settings, "warning_shown", url, result.verdict);
    }
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
  tabSummaries.delete(tabId);
  void chrome.storage.session.remove(SAFE_PREFIX + tabId);
});

// --- Downloads ------------------------------------------------------------------------

function fileNameOf(item: chrome.downloads.DownloadItem): string {
  const fromPath = item.filename.split(/[\\/]/).pop();
  if (fromPath) return fromPath;
  try {
    return decodeURIComponent(new URL(item.finalUrl || item.url).pathname.split("/").pop() ?? "") || "download";
  } catch {
    return "download";
  }
}

chrome.downloads.onCreated.addListener((item) => {
  void (async () => {
    const settings = await loadSettings();
    const source = item.finalUrl || item.url;
    const result = await assessDownload(source, fileNameOf(item), settings);
    if (!result || !["dangerous", "suspicious", "blocked_by_you", "blocked_by_family"].includes(result.verdict)) return;

    // Pausing is best effort: small files may already be complete.
    await chrome.downloads.pause(item.id).catch(() => undefined);
    const reason = result.reasons[0]?.title ?? VERDICTS[result.verdict].detail;
    await initLanguage();
    const n = t().notifications;
    await notify(`download:${item.id}`, n.downloadPaused(VERDICTS[result.verdict].label), `${fileNameOf(item)} · ${result.host}: ${reason}`, [
      { title: n.cancel },
      { title: n.keep },
    ]);
    await recordAlert({ host: result.host, verdict: result.verdict, kind: "download", at: new Date().toISOString() }, settings.keepLocalAlerts);
    await syncEvent(settings, "download_warning", source, result.verdict);
  })();
});

// --- Fingerprint noise -------------------------------------------------------------

const NOISE_SECRET = "fingerprint-secret";
const seeds = new Map<string, Promise<number>>();
const readySeeds = new Map<string, number>();
/** Kept in memory so the injection at commit doesn't wait on storage. */
let noise: { on: boolean; bypass: string[] } = { on: false, bypass: [] };

function updateNoise(settings: Settings) {
  noise = { on: settings.fingerprintNoise && !settings.paused, bypass: settings.fingerprintBypass };
  void applyWebRtcPolicy(noise.on);
}

/**
 * WebRTC can reveal the computer's local network addresses to any page. With
 * fingerprint noise on, only the public interface is used (calls keep working).
 */
async function applyWebRtcPolicy(on: boolean) {
  const policy = chrome.privacy?.network?.webRTCIPHandlingPolicy;
  if (!policy) return; // optional permission not granted
  if (on) await policy.set({ value: "default_public_interface_only" }).catch(() => undefined);
  else await policy.clear({}).catch(() => undefined);
}
void loadSettings().then(updateNoise);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings?.newValue) updateNoise({ ...DEFAULT_SETTINGS, ...(changes.settings.newValue as Partial<Settings>) });
});

/** A secret for this browser session only (session storage is cleared on restart). */
async function noiseSecret(): Promise<Uint8Array> {
  const stored = (await chrome.storage.session.get(NOISE_SECRET))[NOISE_SECRET] as number[] | undefined;
  if (stored?.length === 32) return new Uint8Array(stored);
  const fresh = crypto.getRandomValues(new Uint8Array(32));
  await chrome.storage.session.set({ [NOISE_SECRET]: [...fresh] });
  return fresh;
}

function seedFor(origin: string): Promise<number> {
  let seed = seeds.get(origin);
  if (!seed) {
    seed = noiseSecret().then((secret) => originSeed(secret, origin));
    seeds.set(origin, seed);
    void seed.then((value) => readySeeds.set(origin, value));
  }
  return seed;
}

function noiseTarget(url: string): { origin: string } | null {
  if (!noise.on || !chrome.scripting || !/^https?:/.test(url)) return null;
  const { origin, hostname } = new URL(url);
  return isBypassed(hostname, noise.bypass) ? null : { origin };
}

// The seed is worked out while the request is in flight, so it's ready at commit.
chrome.webNavigation.onBeforeNavigate.addListener(({ url }) => {
  const target = noiseTarget(url);
  if (target) void seedFor(target.origin);
});

// Injected as each document starts, into every frame, with the site's seed as an argument.
chrome.webNavigation.onCommitted.addListener(({ tabId, frameId, url }) => {
  const target = noiseTarget(url);
  if (!target) return;
  const inject = (seed: number) =>
    chrome.scripting
      .executeScript({ target: { tabId, frameIds: [frameId] }, world: "MAIN", injectImmediately: true, func: installNoise, args: [seed] })
      .catch(() => undefined); // pages the browser doesn't let extensions touch
  const ready = readySeeds.get(target.origin);
  if (ready !== undefined) void inject(ready);
  else void seedFor(target.origin).then(inject);
});

// --- SafePay offer -----------------------------------------------------------------

const SAFEPAY_OFFERED = "safepay-offered";

/** Once per site per browser session, on a banking page that finished loading. */
chrome.webNavigation.onCompleted.addListener(({ tabId, frameId, url }) => {
  if (frameId !== 0 || !url.startsWith("https://")) return;
  void (async () => {
    const settings = await loadSettings();
    if (!settings.safePayOffer || settings.paused) return;
    const host = new URL(url).hostname;
    if (!isBankingHost(host) || !safePayLink(url)) return;
    const offered = ((await chrome.storage.session.get(SAFEPAY_OFFERED))[SAFEPAY_OFFERED] as string[] | undefined) ?? [];
    if (offered.includes(host)) return;
    await chrome.storage.session.set({ [SAFEPAY_OFFERED]: [...offered, host].slice(-200) });
    await initLanguage();
    const n = t().notifications;
    const options: chrome.notifications.NotificationCreateOptions = {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
      title: n.safePayTitle,
      message: IS_FIREFOX ? `${n.safePayBody(host)} ${n.safePayFirefox}` : n.safePayBody(host),
      priority: 0,
    };
    if (!IS_FIREFOX) options.buttons = [{ title: n.safePayOpen }, { title: n.safePayLater }];
    await chrome.notifications.create(`safepay:${tabId}:${url}`, options);
  })();
});

/** Hands the page to Qalaa Desktop; the browser asks the person first. */
async function openInSafePay(notificationId: string) {
  const [, tab, ...rest] = notificationId.split(":");
  const link = safePayLink(rest.join(":"));
  if (link) await chrome.tabs.update(Number(tab), { url: link }).catch(() => undefined);
}

chrome.notifications.onClicked.addListener((notificationId) => {
  if (!notificationId.startsWith("safepay:")) return;
  void openInSafePay(notificationId).finally(() => chrome.notifications.clear(notificationId));
});

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  if (notificationId.startsWith("safepay:")) {
    void (buttonIndex === 0 ? openInSafePay(notificationId) : Promise.resolve()).finally(() => chrome.notifications.clear(notificationId));
    return;
  }
  if (!notificationId.startsWith("download:")) return;
  const id = Number(notificationId.split(":")[1]);
  const action = buttonIndex === 0 ? chrome.downloads.cancel(id) : chrome.downloads.resume(id);
  void action.catch(() => undefined).finally(() => chrome.notifications.clear(notificationId));
});

// --- Context menu ---------------------------------------------------------------------

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU_LINK, title: t().notifications.scanLink, contexts: ["link"] });
    chrome.contextMenus.create({ id: MENU_PAGE, title: t().notifications.checkPage, contexts: ["page"] });
  });
}

chrome.contextMenus.onClicked.addListener((info) => {
  const target = info.menuItemId === MENU_LINK ? info.linkUrl : info.pageUrl;
  if (!target) return;
  void (async () => {
    const settings = await loadSettings();
    // Asked for by the person, so this one goes to the server with the full address.
    const result = await assessUrlOnServer(target, settings);
    if (!result) {
      await notify(`link:${Date.now()}`, t().notifications.notChecked, t().notifications.notCheckedBody);
      return;
    }
    const presentation = VERDICTS[result.verdict];
    const detail = result.reasons[0]?.title ?? result.limitations[0] ?? presentation.detail;
    await notify(`link:${Date.now()}`, `${presentation.label}: ${result.host}`, detail);
    if (WARNING_VERDICTS.has(result.verdict)) {
      await recordAlert({ host: result.host, verdict: result.verdict, kind: "link", at: new Date().toISOString() }, settings.keepLocalAlerts);
    }
    await syncEvent(settings, "link_checked", target, result.verdict);
  })();
});

// --- Hover checks (optional content script) -------------------------------------------

async function syncScript(id: string, file: string, wanted: boolean, matches = ["http://*/*", "https://*/*"]) {
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
  if (wanted && registered.length === 0) {
    await chrome.scripting.registerContentScripts([{ id, js: [file], matches, runAt: "document_idle" }]);
  } else if (!wanted && registered.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: [id] });
  }
}

async function syncContentScripts(settings: Settings) {
  if (!chrome.scripting) return; // optional permission not granted
  await syncScript(HOVER_SCRIPT_ID, "hover.js", settings.hoverChecks && !settings.paused);
  await syncScript(ASSISTANT_SCRIPT_ID, "assistant.js", settings.assistant && !settings.paused);
  await syncScript(SEARCH_SCRIPT_ID, "search.js", settings.searchBadges && !settings.paused, SEARCH_ORIGINS);
}

// --- Verdicts that also know about the in-browser blocklist ---------------------------

/** Like assessUrl, but a domain on the downloaded blocklist is reported as dangerous
 * even when the server cannot be reached (it was blocked before loading). */
async function verdictFor(url: string, settings: Settings): Promise<CheckResult | null> {
  const result = await assessUrl(url, { ...settings, paused: false });
  if (!result || result.verdict === "dangerous" || result.verdict === "blocked_by_you" || result.verdict === "blocked_by_family") return result;
  if (!(await onServerBlocklist(result.host))) return result;
  await initLanguage();
  const w = t().warning;
  return {
    ...result,
    verdict: "dangerous",
    reasons: [{ severity: "high", title: w.preloadReason, explanation: w.preloadExplanation, source: w.preloadSource }, ...result.reasons],
  };
}

// --- On-screen assistant --------------------------------------------------------------

async function cookiesFor(pageUrl: string, pageHost: string, otherHosts: string[]): Promise<CookieInfo[] | null> {
  if (!chrome.cookies?.getAll) return null; // optional permission not granted
  const sites = [...new Set(otherHosts.map(siteOf))].filter((site) => site !== siteOf(pageHost)).slice(0, MAX_COOKIE_SITES);
  const batches = await Promise.all([
    chrome.cookies.getAll({ url: pageUrl }).catch(() => []),
    ...sites.map((domain) => chrome.cookies.getAll({ domain }).catch(() => [])),
  ]);
  const seen = new Set<string>();
  const cookies: CookieInfo[] = [];
  for (const cookie of batches.flat()) {
    const key = `${cookie.domain}|${cookie.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    cookies.push(describeCookie(cookie, pageHost)); // names and lifetimes only, never values
  }
  return cookies.sort((a, b) => Number(a.thirdParty) - Number(b.thirdParty) || a.name.localeCompare(b.name));
}

async function pageSummary(url: string, resourceHosts: string[], settings: Settings): Promise<PageSummary | null> {
  const parsed = checkableUrl(url);
  if (!parsed) return null;
  const hosts = resourceHosts.filter((host) => typeof host === "string" && host.length < 256).slice(0, 200);
  const [result, cookies] = await Promise.all([verdictFor(url, settings), cookiesFor(parsed.toString(), parsed.hostname, hosts)]);
  return {
    host: parsed.hostname,
    result,
    cookies: cookies ?? [],
    cookiesAvailable: cookies !== null,
    trackers: detectTrackers(hosts),
  };
}

// --- Password vault (autofill) ---------------------------------------------------------
// The decrypted vault lives only in this worker's memory: never in storage. It is
// dropped after 10 minutes without use, and whenever the browser stops the worker.

const VAULT_IDLE_MS = 10 * 60 * 1000;
let vault: { doc: VaultDoc; timer: ReturnType<typeof setTimeout> } | null = null;

function fromPopup(sender: chrome.runtime.MessageSender): boolean {
  return Boolean(sender.url?.startsWith(chrome.runtime.getURL("popup.html")));
}

function lockVault() {
  if (vault) clearTimeout(vault.timer);
  vault = null;
}

function touchVault() {
  if (!vault) return;
  clearTimeout(vault.timer);
  vault.timer = setTimeout(lockVault, VAULT_IDLE_MS);
}

async function vaultStatus(url: string | undefined, settings: Settings): Promise<VaultStatus> {
  const account = await cachedAccount();
  if (!account?.linked) return { linked: false, unlocked: false, logins: [], refusal: null };
  if (!vault || !url) return { linked: true, unlocked: Boolean(vault), logins: [], refusal: null };
  touchVault();
  const logins = loginsFor(vault.doc.items, url);
  const verdict = (await verdictFor(url, settings))?.verdict ?? null;
  const why = refusal(url, verdict, logins.length);
  return {
    linked: true,
    unlocked: true,
    logins: logins.map((item) => ({ id: item.id, title: item.title, username: item.username, hasTotp: Boolean(item.totp && parseOtpauth(item.totp)) })),
    refusal: why === "not_https" || why === "dangerous_site" ? why : null,
  };
}

/** The login, only if it belongs to this page and the page is safe to fill. */
async function loginForPage(url: string, itemId: string, settings: Settings) {
  if (!vault) throw new Error(t().vault.lock);
  touchVault();
  const matches = loginsFor(vault.doc.items, url);
  const verdict = (await verdictFor(url, settings))?.verdict ?? null;
  const why = refusal(url, verdict, matches.length);
  if (why === "not_https") throw new Error(t().vault.notHttps);
  if (why === "dangerous_site") throw new Error(t().vault.dangerous);
  const item = matches.find((entry) => entry.id === itemId);
  if (!item) throw new Error(t().vault.none);
  return item;
}

// --- Messages from extension pages -----------------------------------------------------

async function handle(request: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const settings = await loadSettings();
  switch (request.type) {
    case "status": {
      const page =
        request.tabId !== undefined && request.url
          ? tabResults.get(request.tabId)?.url === request.url
            ? tabResults.get(request.tabId)!
            : { url: request.url, result: await assessUrl(request.url, settings) }
          : null;
      const status: Status = {
        state: await protectionState(settings),
        settings,
        page,
        alerts: await listAlerts(),
        account: await cachedAccount(),
        preloadedCount: settings.preloadBlocking && !settings.paused ? ((await storedBlocklist())?.hosts.length ?? 0) : 0,
      };
      return status;
    }
    case "check":
      return assessUrl(request.url, { ...settings, paused: false });
    case "verdict-for":
      return verdictFor(request.url, settings);
    case "assistant-summary": {
      const tabId = sender.tab?.id;
      if (tabId === undefined || !settings.assistant) return null;
      const summary = await pageSummary(request.url, Array.isArray(request.resourceHosts) ? request.resourceHosts : [], settings);
      if (summary) tabSummaries.set(tabId, { url: request.url, summary });
      return summary;
    }
    case "assistant-ask": {
      const tabId = sender.tab?.id;
      if (tabId === undefined || !settings.assistant) return null;
      const question = String(request.question).slice(0, 500);
      const cached = tabSummaries.get(tabId);
      const summary = cached?.url === request.url ? cached.summary : await pageSummary(request.url, [], settings);
      if (!summary) return null;
      await initLanguage();
      try {
        const reply = await api.askAssistant(settings.serverUrl, question, language(), toAssistantContext(summary, !!request.hasPasswordField));
        return { answer: reply.answer, source: "ai" };
      } catch {
        // No AI provider on this server, or it failed: answer from what Qalaa knows.
        return { answer: builtInAnswer(question, summary, language()), source: "builtin" };
      }
    }
    case "search-check": {
      if (!sender.tab || !Array.isArray(request.urls)) return [];
      // Cached and throttled like page checks; only warnings are shown.
      return Promise.all(
        request.urls.slice(0, 20).map((url) => (typeof url === "string" ? assessUrl(url, settings) : Promise.resolve(null))),
      );
    }
    case "hover": {
      // Hover lookups must never be slower than the hover itself; cached or quick only.
      const result = await assessUrl(request.href, settings);
      return result && WARNING_VERDICTS.has(result.verdict) ? result : null;
    }
    case "proceed": {
      const host = new URL(request.url).hostname;
      const result = await assessUrl(request.url, { ...settings, paused: false });
      await allowForSession(host);
      await allowDomainForSession(host);
      if (result) await syncEvent(settings, "proceeded", request.url, result.verdict);
      const tabId = request.tabId ?? sender.tab?.id;
      if (tabId !== undefined) await chrome.tabs.update(tabId, { url: request.url });
      return null;
    }
    case "go-back": {
      await syncEvent(settings, "went_back", request.url, request.verdict);
      const tabId = sender.tab?.id;
      if (tabId !== undefined) await chrome.tabs.update(tabId, { url: await safePageFor(tabId) });
      return null;
    }
    case "enroll":
      await api.enroll(settings.serverUrl, request.linkCode);
      return refreshAccount(settings);
    case "link": {
      const account = await api.link(settings.serverUrl, request.code);
      await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
      await applyFamilyList(account);
      return account;
    }
    case "new-alias": {
      // Only the toolbar popup may create aliases: never a script running in a page.
      if (!fromPopup(sender)) throw new Error("Not allowed.");
      // Labelled with the site's host only, so the account shows what each alias is for.
      const host = checkableUrl(request.url)?.hostname;
      if (!host) throw new Error(t().popup.aliasNoSite);
      return api.createAlias(settings.serverUrl, host);
    }
    case "unlink": {
      const account = await api.unlink(settings.serverUrl);
      await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
      await applyFamilyList(account);
      return account;
    }
    case "refresh-account":
      return refreshAccount(settings);
    case "apply-rules":
      await applyRules(settings);
      return null;
    case "settings": {
      // Family rules come from the account, never from a page or the popup.
      const { safeSearch: _s, lockProtection: _l, familyBlocklist: _b, familyGroups: _g, screenTime: _t, screenTimeBlocked: _tb, ...changes } = request.changes;
      if (settings.lockProtection && changes.paused) delete changes.paused;
      if (changes.fingerprintBypass !== undefined) {
        const hosts = Array.isArray(changes.fingerprintBypass) ? changes.fingerprintBypass : [];
        changes.fingerprintBypass = [...new Set(hosts.map((h) => (typeof h === "string" ? normalizeHostEntry(h) : null)).filter((h): h is string => h !== null))].slice(0, 500);
      }
      request.changes = changes;
      const next = await saveSettings(request.changes);
      if (request.changes.serverUrl && request.changes.serverUrl !== settings.serverUrl) {
        // Credentials belong to one server; a new server needs a new enrollment.
        await api.forgetCredentials();
        await chrome.storage.local.remove(ACCOUNT_KEY);
        await clearCache();
      }
      if (request.changes.allowlist || request.changes.blocklist) await clearCache();
      await refreshGlobalBadge(next);
      await syncContentScripts(next);
      await applyRules(next);
      if (request.changes.preloadBlocking) await refreshBlocklist(next, true);
      if (request.changes.language) {
        await initLanguage();
        createMenus();
      }
      return next;
    }
    case "clear-alerts":
      await clearAlerts();
      return null;
    case "clear-cache":
      await clearCache();
      return null;
    case "vault-status":
      return vaultStatus(request.url, settings);
    case "vault-lock":
      lockVault();
      return null;
    case "vault-unlock": {
      const account = await cachedAccount();
      if (!account?.linked) throw new Error(t().vault.linkFirst);
      const stored = await api.fetchVault(settings.serverUrl);
      if (!stored) throw new Error(t().vault.noVault);
      try {
        const { doc } = await unlockVault(stored, request.master, stored.user_id);
        lockVault();
        vault = { doc, timer: setTimeout(lockVault, VAULT_IDLE_MS) };
      } catch (error) {
        if (error instanceof WrongMasterPassword) throw new Error(t().vault.wrong);
        throw error;
      }
      return null;
    }
    case "vault-secret": {
      // Only the extension's own popup may read a password, never a content script.
      if (!fromPopup(sender)) throw new Error("Not allowed.");
      const item = await loginForPage(request.url, request.itemId, settings);
      return { username: item.username, password: item.password };
    }
    case "vault-totp": {
      // The secret never leaves the background; only the generated code is returned.
      if (!fromPopup(sender)) throw new Error("Not allowed.");
      const item = await loginForPage(request.url, request.itemId, settings);
      const config = item.totp ? parseOtpauth(item.totp) : null;
      if (!config) throw new Error(t().vault.none);
      return { code: await totpCode(config), seconds: secondsRemaining(config) };
    }
    case "vault-fill": {
      if (!fromPopup(sender)) throw new Error("Not allowed.");
      const tab = await chrome.tabs.get(request.tabId);
      // The tab must still be on the page the popup was showing.
      if (!tab.url || tab.url !== request.url) throw new Error(t().vault.none);
      const item = await loginForPage(tab.url, request.itemId, settings);
      if (!chrome.scripting) throw new Error(t().vault.needPermission);
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: request.tabId, allFrames: false },
        func: fillLoginForm,
        args: [item.username, item.password, new URL(tab.url).origin],
      });
      const outcome = result?.result as { filled: boolean } | undefined;
      if (!outcome?.filled) throw new Error(t().vault.noField);
      return outcome;
    }
  }
}

chrome.runtime.onMessage.addListener((request: Request, sender, sendResponse) => {
  // Only this extension's own pages and content scripts may ask; web pages cannot
  // message it because the manifest declares no externally_connectable.
  if (sender.id !== chrome.runtime.id) return false;
  const work = SERIALIZED_MESSAGES.has(request.type) ? serialized(() => handle(request, sender)) : handle(request, sender);
  work.then(
    (data) => sendResponse({ ok: true, data } satisfies Response),
    (error: unknown) => sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) } satisfies Response),
  );
  return true;
});

// Granting or removing site access changes which rules can run (SafeSearch).
chrome.permissions.onAdded.addListener(() => {
  void serialized(() => loadSettings().then(applyRules));
});

chrome.permissions.onRemoved.addListener(() => {
  void serialized(async () => {
    const settings = await loadSettings();
    await applyRules(settings);
    const changes: Partial<Settings> = {};
    if (settings.hoverChecks && !chrome.scripting) changes.hoverChecks = false;
    if (settings.assistant && (!chrome.scripting || !chrome.cookies)) changes.assistant = false;
    if (Object.keys(changes).length) await syncContentScripts(await saveSettings(changes));
  });
});

chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name === SCREEN_TIME_ALARM) void serialized(() => updateScreenTime(true));
  if (alarm.name === BLOCKLIST_ALARM) {
    void serialized(async () => {
      const settings = await loadSettings();
      await refreshBlocklist(settings, true);
      await refreshThreatList(settings.serverUrl);
      await refreshAccount(settings);
    });
  }
});

// --- Startup --------------------------------------------------------------------------

async function start(reason?: string) {
  await initLanguage();
  createMenus();
  const settings = await loadSettings();
  await refreshGlobalBadge(settings);
  await syncContentScripts(settings).catch(() => undefined);
  // Anonymous enrollment shares nothing about the user. If the server is not
  // reachable yet, navigation retries it and the popup offers to connect.
  await ensureEnrolled(settings);
  await applyRules(settings).catch(() => undefined);
  await refreshBlocklist(settings).catch(() => undefined);
  await refreshThreatList(settings.serverUrl).catch(() => undefined);
  await chrome.alarms?.create(BLOCKLIST_ALARM, { periodInMinutes: REFRESH_MINUTES });
  await chrome.alarms?.create(SCREEN_TIME_ALARM, { periodInMinutes: 1 });
  await updateScreenTime(false).catch(() => undefined);
  if (reason === "install") await chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
}

chrome.runtime.onInstalled.addListener(({ reason }) => void serialized(() => start(reason)));
chrome.runtime.onStartup.addListener(() => void serialized(() => start()));
