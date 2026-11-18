import type { AccountLink } from "../lib/api";
import { byId, el } from "../lib/dom";
import { applyTheme } from "../lib/theme";
import { initLanguage, localizeDocument, t, type LanguageSetting } from "../lib/i18n";
import { ask, type Status } from "../lib/messages";
import { SAFE_SEARCH_ORIGINS, hasSafeSearchAccess } from "../lib/safesearch";
import { SEARCH_ORIGINS, normalizeHostEntry, type Settings } from "../lib/settings";

const SWITCHES = ["paused", "warnOnSuspicious", "preloadBlocking", "blockTrackers", "searchBadges", "downloadChecks", "keepLocalAlerts", "hoverChecks", "assistant"] as const;
// Optional permissions, requested from the click that turns a feature on.
const PAGE_ORIGINS = ["http://*/*", "https://*/*"];
const FEATURE_PERMISSIONS: Partial<Record<(typeof SWITCHES)[number], chrome.permissions.Permissions>> = {
  hoverChecks: { permissions: ["scripting"], origins: PAGE_ORIGINS },
  assistant: { permissions: ["scripting", "cookies"], origins: PAGE_ORIGINS },
  searchBadges: { permissions: ["scripting"], origins: SEARCH_ORIGINS },
};

function flash(message: string) {
  const saved = byId("saved");
  saved.textContent = message;
  window.setTimeout(() => {
    if (saved.textContent === message) saved.textContent = "";
  }, 3000);
}

async function save(changes: Partial<Settings>, message = t().options.saved) {
  try {
    await ask<Settings>({ type: "settings", changes });
    flash(message);
  } catch (error) {
    flash(error instanceof Error ? error.message : String(error));
  }
}

function parseList(text: string): { hosts: string[]; rejected: string[] } {
  const hosts = new Set<string>();
  const rejected: string[] = [];
  for (const line of text.split(/\n|,/)) {
    if (!line.trim()) continue;
    const host = normalizeHostEntry(line);
    if (host) hosts.add(host);
    else rejected.push(line.trim());
  }
  return { hosts: [...hosts], rejected };
}

function renderAccount(status: Status) {
  const box = byId("account");
  box.replaceChildren();
  const error = el("p", { class: "faint", role: "alert" });
  const run = async (action: () => Promise<unknown>) => {
    error.textContent = "";
    try {
      await action();
      renderAccount(await ask<Status>({ type: "status" }));
    } catch (caught) {
      error.textContent = caught instanceof Error ? caught.message : String(caught);
    }
  };

  if (status.state === "not_enrolled") {
    box.append(
      el("p", { class: "muted" }, t().options.notEnrolled),
      el("div", {}, el("button", { type: "button", onclick: () => run(() => ask({ type: "enroll" })) }, t().options.connectNow)),
      error,
    );
    return;
  }
  const account: AccountLink | null = status.account;
  if (account?.linked) {
    box.append(
      el("p", {}, t().options.linkedTo, el("strong", {}, account.account_email ?? t().options.yourAccount), "."),
      el(
        "p",
        { class: "muted" },
        account.sync_events ? t().options.syncOn : t().options.syncOff,
      ),
      el("div", {}, el("button", { type: "button", class: "secondary", onclick: () => run(() => ask({ type: "unlink" })) }, t().options.unlink)),
      error,
    );
    void renderFamilyRules(box, status.settings);
    return;
  }
  const input = el("input", { type: "text", id: "link-code", placeholder: "ABCD-1234", autocomplete: "off", spellcheck: "false", "aria-label": t().options.linkCode });
  box.append(
    el("p", { class: "muted" }, t().options.linkIntro),
    el("p", { class: "muted" }, t().options.linkHow),
    el(
      "div",
      { class: "row" },
      input,
      el(
        "button",
        {
          type: "button",
          onclick: () =>
            run(async () => {
              if (!input.value.trim()) throw new Error(t().options.enterCode);
              await ask({ type: "link", code: input.value });
            }),
        },
        t().options.link,
      ),
    ),
    error,
  );
}

/** Family rules the person chose to follow. SafeSearch needs access to the search
 * sites, which only the person can grant, from this click. */
async function renderFamilyRules(box: HTMLElement, settings: Settings) {
  if (!settings.safeSearch && !settings.lockProtection) return;
  const f = t().options.family;
  const panel = el("div", { class: "stack", id: "family-rules" }, el("h3", {}, f.title), el("p", { class: "muted" }, f.intro(settings.familyGroups.join(", "))));
  if (settings.lockProtection) panel.append(el("p", {}, f.locked));
  if (settings.safeSearch) {
    if (await hasSafeSearchAccess()) {
      panel.append(el("p", { class: "good" }, f.safeSearchOn));
    } else {
      panel.append(
        el("p", {}, f.safeSearchNeedsAccess),
        el("div", {}, el("button", {
          type: "button",
          id: "allow-safe-search",
          onclick: async () => {
            if (await chrome.permissions.request({ origins: SAFE_SEARCH_ORIGINS })) {
              await ask({ type: "apply-rules" });
              location.reload();
            } else {
              flash(t().options.permissionDenied);
            }
          },
        }, f.allowSafeSearch)),
      );
    }
  }
  box.append(panel);
}

async function main() {
  await Promise.all([initLanguage(), applyTheme()]);
  localizeDocument();
  // Refresh the account state before rendering, so the form is not replaced while
  // someone is typing a link code into it.
  await ask<AccountLink>({ type: "refresh-account" }).catch(() => undefined);
  const status = await ask<Status>({ type: "status" });
  const { settings } = status;

  for (const key of SWITCHES) {
    const input = byId<HTMLInputElement>(key);
    input.checked = settings[key];
    if (key === "paused" && settings.lockProtection) {
      input.disabled = true;
      input.title = t().options.family.locked;
    }
    input.addEventListener("change", async () => {
      const needed = FEATURE_PERMISSIONS[key];
      if (needed && input.checked) {
        // Must be requested from the click handler, as a direct user gesture.
        const granted = await chrome.permissions.request(needed);
        if (!granted) {
          input.checked = false;
          flash(t().options.permissionDenied);
          return;
        }
      }
      if (needed && !input.checked) {
        // Keep permissions another enabled feature still needs.
        const stillUsed = (Object.keys(FEATURE_PERMISSIONS) as (keyof typeof FEATURE_PERMISSIONS)[]).filter(
          (other) => other !== key && byId<HTMLInputElement>(other).checked,
        );
        const keep = new Set(stillUsed.flatMap((other) => FEATURE_PERMISSIONS[other]?.permissions ?? []));
        const permissions = (needed.permissions ?? []).filter((name) => !keep.has(name));
        // Never take away the search-site access a family SafeSearch rule relies on.
        const origins = stillUsed.length ? [] : (needed.origins ?? []).filter((o) => !(settings.safeSearch && SAFE_SEARCH_ORIGINS.includes(o)));
        await chrome.permissions.remove({ permissions, origins });
      }
      await save({ [key]: input.checked });
    });
  }

  const themeSelect = byId<HTMLSelectElement>("theme");
  themeSelect.value = settings.theme;
  themeSelect.addEventListener("change", async () => {
    const choice = themeSelect.value as Settings["theme"];
    // Reflect the choice on the page at once, so it doesn't wait on the save
    // round-trip to the (possibly asleep) background service worker.
    if (choice === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = choice;
    await save({ theme: choice });
    await applyTheme();
  });

  const languageSelect = byId<HTMLSelectElement>("language");
  languageSelect.value = settings.language;
  languageSelect.addEventListener("change", async () => {
    await save({ language: languageSelect.value as LanguageSetting });
    location.reload();
  });

  for (const radio of document.querySelectorAll<HTMLInputElement>("input[name=privacyMode]")) {
    radio.checked = radio.value === settings.privacyMode;
    radio.addEventListener("change", () => save({ privacyMode: radio.value as Settings["privacyMode"] }));
  }

  const allow = byId<HTMLTextAreaElement>("allowlist");
  const block = byId<HTMLTextAreaElement>("blocklist");
  allow.value = settings.allowlist.join("\n");
  block.value = settings.blocklist.join("\n");
  byId("save-lists").addEventListener("click", async () => {
    const allowed = parseList(allow.value);
    const blocked = parseList(block.value);
    allow.value = allowed.hosts.join("\n");
    block.value = blocked.hosts.join("\n");
    const rejected = [...allowed.rejected, ...blocked.rejected];
    await save(
      { allowlist: allowed.hosts, blocklist: blocked.hosts },
      rejected.length ? t().options.ignored(rejected.join(", ")) : t().options.listsSaved,
    );
  });

  const server = byId<HTMLInputElement>("serverUrl");
  server.value = settings.serverUrl;
  byId("save-server").addEventListener("click", async () => {
    let origin: string;
    try {
      const parsed = new URL(server.value.trim());
      if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
        flash(t().options.useHttps);
        return;
      }
      origin = parsed.origin;
    } catch {
      flash(t().options.fullAddress);
      return;
    }
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) {
      flash(t().options.serverPermission);
      return;
    }
    await save({ serverUrl: origin }, t().options.serverChanged);
    try {
      await ask({ type: "enroll" });
      flash(t().options.connected);
    } catch (error) {
      flash(t().options.serverUnreachable(error instanceof Error ? error.message : String(error)));
    }
    renderAccount(await ask<Status>({ type: "status" }));
  });

  byId("clear-alerts").addEventListener("click", async () => {
    await ask({ type: "clear-alerts" });
    flash(t().options.alertsCleared);
  });
  byId("clear-cache").addEventListener("click", async () => {
    await ask({ type: "clear-cache" });
    flash(t().options.cacheCleared);
  });

  renderAccount(status);
}

void main();
