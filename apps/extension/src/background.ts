import * as api from "./lib/api";
import { clearAlerts, listAlerts, recordAlert } from "./lib/alerts";
import { clearCache } from "./lib/cache";
import type { Request, Response, Status } from "./lib/messages";
import { allowForSession, assessDownload, assessUrl, isAllowedForSession } from "./lib/protection";
import { loadSettings, saveSettings, type Settings } from "./lib/settings";
import type { CheckResult, ProtectionState, Verdict } from "./lib/types";
import { BADGE_COLORS, VERDICTS, shouldInterrupt } from "./lib/verdicts";

declare const __TARGET_BROWSER__: string;
const IS_FIREFOX = typeof __TARGET_BROWSER__ === "string" && __TARGET_BROWSER__ === "firefox";
// Extensions cannot open Firefox's new-tab page, so a blank page is the fallback there.
const NEW_TAB_URL = IS_FIREFOX ? "about:blank" : "chrome://newtab/";

const ACCOUNT_KEY = "account";
const HOVER_SCRIPT_ID = "sentinel-hover";
const MENU_LINK = "sentinel-scan-link";
const MENU_PAGE = "sentinel-scan-page";
const WARNING_VERDICTS = new Set(["dangerous", "suspicious", "caution", "blocked_by_you"]);

/** Last result per tab, for the popup. Lost if the worker restarts; the popup then re-checks. */
const tabResults = new Map<number, { url: string; result: CheckResult | null }>();

// --- Helpers --------------------------------------------------------------------------

async function cachedAccount(): Promise<api.AccountLink | null> {
  const stored = await chrome.storage.local.get(ACCOUNT_KEY);
  return (stored[ACCOUNT_KEY] as api.AccountLink | undefined) ?? null;
}

async function refreshAccount(settings: Settings): Promise<api.AccountLink | null> {
  try {
    const account = await api.accountLink(settings.serverUrl);
    await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
    return account;
  } catch {
    return cachedAccount();
  }
}

/** Maps local outcomes onto the verdicts the API records; null means "nothing to record". */
function eventVerdict(verdict: Verdict): string | null {
  if (verdict === "blocked_by_you") return "dangerous";
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
  else if (buttons) options.message = `${message} Open the downloads panel to cancel or resume it.`;
  await chrome.notifications.create(id, options);
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
  if (!result || !interrupt || (result.verdict !== "blocked_by_you" && (await isAllowedForSession(result.host)))) {
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
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
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
    if (!result || !["dangerous", "suspicious", "blocked_by_you"].includes(result.verdict)) return;

    // Pausing is best effort: small files may already be complete.
    await chrome.downloads.pause(item.id).catch(() => undefined);
    const reason = result.reasons[0]?.title ?? VERDICTS[result.verdict].detail;
    await notify(`download:${item.id}`, `${VERDICTS[result.verdict].label} download paused`, `${fileNameOf(item)} from ${result.host}: ${reason}`, [
      { title: "Cancel download" },
      { title: "Keep it anyway" },
    ]);
    await recordAlert({ host: result.host, verdict: result.verdict, kind: "download", at: new Date().toISOString() }, settings.keepLocalAlerts);
    await syncEvent(settings, "download_warning", source, result.verdict);
  })();
});

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  if (!notificationId.startsWith("download:")) return;
  const id = Number(notificationId.split(":")[1]);
  const action = buttonIndex === 0 ? chrome.downloads.cancel(id) : chrome.downloads.resume(id);
  void action.catch(() => undefined).finally(() => chrome.notifications.clear(notificationId));
});

// --- Context menu ---------------------------------------------------------------------

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU_LINK, title: "Scan link with SENTINEL", contexts: ["link"] });
    chrome.contextMenus.create({ id: MENU_PAGE, title: "Check this page with SENTINEL", contexts: ["page"] });
  });
}

chrome.contextMenus.onClicked.addListener((info) => {
  const target = info.menuItemId === MENU_LINK ? info.linkUrl : info.pageUrl;
  if (!target) return;
  void (async () => {
    const settings = await loadSettings();
    const result = await assessUrl(target, { ...settings, paused: false });
    if (!result) {
      await notify(`link:${Date.now()}`, "Not checked", "Only web addresses (http and https) on the public internet can be checked.");
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

async function syncHoverScript(settings: Settings) {
  if (!chrome.scripting) return; // optional permission not granted
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [HOVER_SCRIPT_ID] });
  const wanted = settings.hoverChecks && !settings.paused;
  if (wanted && registered.length === 0) {
    await chrome.scripting.registerContentScripts([
      { id: HOVER_SCRIPT_ID, js: ["hover.js"], matches: ["http://*/*", "https://*/*"], runAt: "document_idle" },
    ]);
  } else if (!wanted && registered.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: [HOVER_SCRIPT_ID] });
  }
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
      };
      return status;
    }
    case "check":
      return assessUrl(request.url, { ...settings, paused: false });
    case "verdict-for":
      return assessUrl(request.url, { ...settings, paused: false });
    case "hover": {
      // Hover lookups must never be slower than the hover itself; cached or quick only.
      const result = await assessUrl(request.href, settings);
      return result && WARNING_VERDICTS.has(result.verdict) ? result : null;
    }
    case "proceed": {
      const host = new URL(request.url).hostname;
      const result = await assessUrl(request.url, { ...settings, paused: false });
      await allowForSession(host);
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
      return account;
    }
    case "unlink": {
      const account = await api.unlink(settings.serverUrl);
      await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
      return account;
    }
    case "refresh-account":
      return refreshAccount(settings);
    case "settings": {
      const next = await saveSettings(request.changes);
      if (request.changes.serverUrl && request.changes.serverUrl !== settings.serverUrl) {
        // Credentials belong to one server; a new server needs a new enrollment.
        await api.forgetCredentials();
        await chrome.storage.local.remove(ACCOUNT_KEY);
        await clearCache();
      }
      if (request.changes.privacyMode || request.changes.allowlist || request.changes.blocklist) await clearCache();
      await refreshGlobalBadge(next);
      await syncHoverScript(next);
      return next;
    }
    case "clear-alerts":
      await clearAlerts();
      return null;
    case "clear-cache":
      await clearCache();
      return null;
  }
}

chrome.runtime.onMessage.addListener((request: Request, sender, sendResponse) => {
  // Only this extension's own pages and content scripts may ask; web pages cannot
  // message it because the manifest declares no externally_connectable.
  if (sender.id !== chrome.runtime.id) return false;
  handle(request, sender).then(
    (data) => sendResponse({ ok: true, data } satisfies Response),
    (error: unknown) => sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) } satisfies Response),
  );
  return true;
});

chrome.permissions.onRemoved.addListener(() => {
  void loadSettings().then(async (settings) => {
    if (settings.hoverChecks) await saveSettings({ hoverChecks: false });
  });
});

// --- Startup --------------------------------------------------------------------------

async function start(reason?: string) {
  createMenus();
  const settings = await loadSettings();
  await refreshGlobalBadge(settings);
  await syncHoverScript(settings).catch(() => undefined);
  // Anonymous enrollment shares nothing about the user. If the server is not
  // reachable yet, navigation retries it and the popup offers to connect.
  await ensureEnrolled(settings);
  if (reason === "install") await chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
}

chrome.runtime.onInstalled.addListener(({ reason }) => void start(reason));
chrome.runtime.onStartup.addListener(() => void start());
