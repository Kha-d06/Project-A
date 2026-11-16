import type { AccountLink } from "../lib/api";
import { byId, el, relativeTime } from "../lib/dom";
import { initLanguage, localizeDocument, t } from "../lib/i18n";
import { ask, type Status } from "../lib/messages";
import type { CheckResult } from "../lib/types";
import { VERDICTS } from "../lib/verdicts";

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
      result.verdict !== "skipped" && result.verdict !== "allowed_by_you" && result.verdict !== "blocked_by_you"
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
    section.append(el("div", { class: "actions" }, fullScanLink(url, status.settings.serverUrl)));
  }
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

function render(status: Status) {
  const toggle = byId<HTMLInputElement>("protection");
  toggle.checked = !status.settings.paused;
  toggle.disabled = status.state === "not_enrolled";
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
  await initLanguage();
  localizeDocument();
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
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
  } catch (error) {
    byId("page").replaceChildren(el("p", { class: "muted", role: "alert" }, error instanceof Error ? error.message : String(error)));
  }
}

void main();
