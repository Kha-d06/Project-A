import type { AccountLink } from "../lib/api";
import { byId, el, relativeTime } from "../lib/dom";
import { applyTheme } from "../lib/theme";
import { initLanguage, localizeDocument, t } from "../lib/i18n";
import { ask, type Status, type VaultStatus } from "../lib/messages";
import type { CheckResult } from "../lib/types";
import { isBankingHost, safePayLink } from "../lib/safepay";
import { VERDICTS } from "../lib/verdicts";

declare const __TEST_BUILD__: boolean;

function stateText(state: Status["state"]): string {
  const p = t().popup;
  return { active: p.protectionOn, paused: p.protectionPaused, not_enrolled: p.notConnected }[state];
}

let activeTab: chrome.tabs.Tab | undefined;

function verdictBlock(result: CheckResult) {
  const presentation = VERDICTS[result.verdict];
  const reason = result.reasons[0];
  return el(
    "div",
    { class: `verdict fade-in tone-${presentation.tone}` },
    el("span", { class: "dot", "aria-hidden": "true" }),
    el(
      "div",
      { class: "stack" },
      el("strong", {}, presentation.label),
      el("p", {}, reason ? reason.title : presentation.detail),
      result.limitations[0] ? el("p", { class: "faint" }, result.limitations[0]) : null,
      result.verdict !== "skipped" && result.verdict !== "allowed_by_you" && result.verdict !== "blocked_by_you" && result.verdict !== "blocked_by_family"
        ? el("p", { class: "faint" }, t().popup.checked(relativeTime(result.checkedAt)))
        : null,
    ),
  );
}

function fullScanLink(url: string, serverUrl: string) {
  const target = `${serverUrl.replace(/\/$/, "")}/scan?type=url&url=${encodeURIComponent(url)}`;
  return el("a", { class: "button secondary", href: target, target: "_blank", rel: "noopener" }, t().popup.fullScan);
}

function renderPage(status: Status) {
  const section = byId("page");
  section.replaceChildren();
  const url = status.page?.url;
  if (!url) {
    section.append(el("p", { class: "muted" }, t().popup.openSite));
    return;
  }
  let host = url;
  try {
    host = new URL(url).hostname || url;
  } catch {
    // keep raw value
  }
  section.append(el("p", { class: "mono" }, host));

  const result = status.page?.result;
  if (status.state === "paused") {
    section.append(el("p", { class: "muted" }, t().popup.pausedNotChecked));
  } else if (!result) {
    section.append(el("p", { class: "muted" }, t().popup.onlyWeb));
  } else {
    section.append(verdictBlock(result));
  }
  if (url.startsWith("http")) {
    const actions = el("div", { class: "actions" }, fullScanLink(url, status.settings.serverUrl));
    const link = isBankingHost(host) ? safePayLink(url) : null;
    if (link) {
      const open = el("button", { class: "button", type: "button", title: t().popup.safePayHint }, t().notifications.safePayOpen);
      open.addEventListener("click", () => {
        // The browser asks before handing the page to Qalaa Desktop.
        if (activeTab?.id !== undefined) void chrome.tabs.update(activeTab.id, { url: link }).then(() => window.close());
      });
      actions.prepend(open);
    }
    section.append(actions);
    if (status.settings.fingerprintNoise) section.append(noiseRow(host, status.settings.fingerprintBypass));
    if (status.account?.linked) section.append(aliasRow(url));
  }
}

/** One click: a fresh disposable address for this site, copied to the clipboard. */
function aliasRow(url: string) {
  const p = t().popup;
  const note = el("p", { class: "faint", role: "status" });
  const button = el("button", { class: "button secondary", type: "button" }, p.aliasNew);
  button.addEventListener("click", async () => {
    button.setAttribute("disabled", "");
    try {
      const alias = await ask<{ address: string }>({ type: "new-alias", url });
      await navigator.clipboard.writeText(alias.address).catch(() => undefined);
      note.textContent = p.aliasCopied(alias.address);
    } catch (error) {
      note.textContent = error instanceof Error ? error.message : String(error);
      button.removeAttribute("disabled");
    }
  });
  return el("div", { class: "stack alias" }, button, note);
}

/** Fingerprint noise for this site: on, or skipped because the person turned it off here. */
function noiseRow(host: string, bypass: string[]) {
  const p = t().popup;
  const off = bypass.some((d) => host === d || host.endsWith(`.${d}`));
  const button = el("button", { class: "button secondary", type: "button" }, off ? p.noiseTurnOn : p.noiseTurnOff);
  button.addEventListener("click", async () => {
    const next = off ? bypass.filter((d) => host !== d && !host.endsWith(`.${d}`)) : [...bypass, host];
    await ask({ type: "settings", changes: { fingerprintBypass: next } });
    // The change applies from the next page load.
    if (activeTab?.id !== undefined) await chrome.tabs.reload(activeTab.id);
    await refresh();
  });
  return el("div", { class: "row noise" }, el("span", { class: "faint" }, off ? p.noiseOff : p.noiseOn), button);
}

function renderSetup(status: Status) {
  const setup = byId("setup");
  setup.replaceChildren();
  setup.hidden = status.state !== "not_enrolled";
  if (setup.hidden) return;
  const error = el("p", { class: "faint", role: "alert" });
  const retry = el(
    "button",
    {
      type: "button",
      onclick: async () => {
        retry.setAttribute("disabled", "");
        error.textContent = "";
        try {
          await ask<AccountLink>({ type: "enroll" });
          await refresh();
        } catch (caught) {
          error.textContent = caught instanceof Error ? caught.message : String(caught);
          retry.removeAttribute("disabled");
        }
      },
    },
    t().popup.connect,
  );
  setup.append(
    el("strong", {}, t().popup.notConnectedTitle),
    el("p", { class: "muted" }, t().popup.notConnectedBody(status.settings.serverUrl)),
    el("div", { class: "actions" }, retry),
    error,
  );
}

function renderAlerts(status: Status) {
  const list = byId("alerts");
  list.replaceChildren();
  byId("clear-alerts").hidden = status.alerts.length === 0;
  if (status.alerts.length === 0) {
    list.append(el("li", { class: "muted" }, t().popup.noAlerts));
    return;
  }
  for (const alert of status.alerts.slice(0, 5)) {
    const presentation = VERDICTS[alert.verdict];
    list.append(
      el(
        "li",
        {},
        el("span", { class: "host mono" }, alert.host),
        el("span", { class: "row" }, el("span", { class: `tag tone-${presentation.tone}` }, presentation.label), el("span", { class: "faint" }, relativeTime(alert.at))),
      ),
    );
  }
}

function vaultMessage(text: string, tone: "muted" | "error" = "muted") {
  return el("p", { class: tone === "error" ? "error" : "muted", role: tone === "error" ? "alert" : "status" }, text);
}

async function renderVault() {
  const section = byId("vault");
  const v = t().vault;
  const url = activeTab?.url;
  let state: VaultStatus;
  try {
    state = await ask<VaultStatus>({ type: "vault-status", url });
  } catch {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  const title = el("h2", { class: "section-title" }, v.title);
  if (!state.linked) {
    section.replaceChildren(title, vaultMessage(v.linkFirst));
    return;
  }
  if (!state.unlocked) {
    const input = el("input", { type: "password", id: "vault-master", autocomplete: "current-password", "aria-label": v.master, placeholder: v.master });
    const status = el("div", {});
    const form = el(
      "form",
      { class: "row" },
      input,
      el("button", { type: "submit", id: "vault-unlock" }, v.unlock),
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      status.replaceChildren(vaultMessage(v.unlocking));
      try {
        await ask({ type: "vault-unlock", master: (input as HTMLInputElement).value });
        await renderVault();
      } catch (error) {
        status.replaceChildren(vaultMessage(error instanceof Error ? error.message : String(error), "error"));
      }
    });
    section.replaceChildren(title, form, status, el("p", { class: "faint" }, v.autoLock));
    return;
  }
  const feedback = el("div", { id: "vault-feedback" });
  const lock = el("button", { type: "button", class: "ghost", id: "vault-lock" }, v.lock);
  lock.addEventListener("click", async () => {
    await ask({ type: "vault-lock" });
    await renderVault();
  });
  const header = el("div", { class: "row spread" }, title, lock);
  if (state.refusal) {
    section.replaceChildren(header, vaultMessage(state.refusal === "not_https" ? v.notHttps : v.dangerous, "error"));
    return;
  }
  if (!state.logins.length || !url || activeTab?.id === undefined) {
    section.replaceChildren(header, vaultMessage(v.none));
    return;
  }
  const tabId = activeTab.id;
  const list = el("ul", { class: "stack", id: "vault-logins" });
  for (const login of state.logins) {
    const fill = el("button", { type: "button", "data-fill": login.id }, v.fill);
    fill.addEventListener("click", async () => {
      try {
        // Filling uses the optional "scripting" permission; ask the first time.
        const granted = await chrome.permissions.request({ permissions: ["scripting"] });
        if (!granted) throw new Error(v.needPermission);
        await ask({ type: "vault-fill", tabId, url, itemId: login.id });
        feedback.replaceChildren(vaultMessage(v.filled));
      } catch (error) {
        feedback.replaceChildren(vaultMessage(error instanceof Error ? error.message : String(error), "error"));
      }
    });
    const copy = el("button", { type: "button", class: "secondary" }, v.copyPassword);
    copy.addEventListener("click", async () => {
      try {
        const secret = await ask<{ password: string }>({ type: "vault-secret", url, itemId: login.id });
        await navigator.clipboard.writeText(secret.password);
        feedback.replaceChildren(vaultMessage(v.copied));
      } catch (error) {
        feedback.replaceChildren(vaultMessage(error instanceof Error ? error.message : String(error), "error"));
      }
    });
    const actions = [fill, copy];
    if (login.hasTotp) {
      const code = el("button", { type: "button", class: "secondary" }, v.copyCode);
      code.addEventListener("click", async () => {
        try {
          const result = await ask<{ code: string; seconds: number }>({ type: "vault-totp", url, itemId: login.id });
          await navigator.clipboard.writeText(result.code);
          feedback.replaceChildren(vaultMessage(v.codeCopied(result.code, result.seconds)));
        } catch (error) {
          feedback.replaceChildren(vaultMessage(error instanceof Error ? error.message : String(error), "error"));
        }
      });
      actions.push(code);
    }
    list.append(
      el(
        "li",
        { class: "row spread" },
        el("span", { class: "stack" }, el("strong", {}, login.title), el("span", { class: "faint mono" }, login.username)),
        el("span", { class: "row" }, ...actions),
      ),
    );
  }
  section.replaceChildren(header, list, feedback);
}

function render(status: Status) {
  const toggle = byId<HTMLInputElement>("protection");
  toggle.checked = !status.settings.paused;
  toggle.disabled = status.state === "not_enrolled" || (status.settings.lockProtection && !status.settings.paused);
  if (status.settings.lockProtection) toggle.title = t().options.family.locked;
  byId("state-label").textContent = stateText(status.state);
  const blocked = byId("preloaded");
  blocked.hidden = !status.preloadedCount;
  blocked.textContent = status.preloadedCount ? t().popup.preloaded(status.preloadedCount) : "";
  byId<HTMLAnchorElement>("dashboard").href = `${status.settings.serverUrl.replace(/\/$/, "")}/dashboard`;
  renderPage(status);
  renderSetup(status);
  renderAlerts(status);
}

async function refresh() {
  render(await ask<Status>({ type: "status", tabId: activeTab?.id, url: activeTab?.url }));
}

async function main() {
  await Promise.all([initLanguage(), applyTheme()]);
  localizeDocument();
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  // Test builds only: open the popup as popup.html?tab=<id> to act on that tab.
  const testTab = __TEST_BUILD__ ? new URLSearchParams(location.search).get("tab") : null;
  if (testTab) activeTab = await chrome.tabs.get(Number(testTab));
  // Show "checking" immediately; the first status may wait for a network check.
  byId("page").replaceChildren(el("div", { class: "checking", "aria-hidden": "true" }), el("p", { class: "muted" }, t().popup.checking));
  byId("protection").addEventListener("change", async (event) => {
    const paused = !(event.target as HTMLInputElement).checked;
    await ask({ type: "settings", changes: { paused } });
    await refresh();
  });
  byId("clear-alerts").addEventListener("click", async () => {
    await ask({ type: "clear-alerts" });
    await refresh();
  });
  byId("options").addEventListener("click", (event) => {
    event.preventDefault();
    void chrome.runtime.openOptionsPage();
  });
  try {
    await refresh();
    await renderVault();
  } catch (error) {
    byId("page").replaceChildren(el("p", { class: "muted", role: "alert" }, error instanceof Error ? error.message : String(error)));
  }
}

void main();
