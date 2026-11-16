import type { AccountLink } from "../lib/api";
import { byId, el, relativeTime } from "../lib/dom";
import { ask, type Status } from "../lib/messages";
import type { CheckResult } from "../lib/types";
import { VERDICTS } from "../lib/verdicts";

const STATE_TEXT = { active: "Protection on", paused: "Protection paused", not_enrolled: "Not connected" } as const;

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
        ? el("p", { class: "faint" }, `Checked ${relativeTime(result.checkedAt)}`)
        : null,
    ),
  );
}

function fullScanLink(url: string, serverUrl: string) {
  const target = `${serverUrl.replace(/\/$/, "")}/scan?type=url&url=${encodeURIComponent(url)}`;
  return el("a", { class: "button secondary", href: target, target: "_blank", rel: "noopener" }, "Run a full scan");
}

function renderPage(status: Status) {
  const section = byId("page");
  section.replaceChildren();
  const url = status.page?.url;
  if (!url) {
    section.append(el("p", { class: "muted" }, "Open a website to see its status here."));
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
    section.append(el("p", { class: "muted" }, "Protection is paused, so this page was not checked."));
  } else if (!result) {
    section.append(el("p", { class: "muted" }, "SENTINEL only checks web pages (http and https)."));
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
    "Connect",
  );
  setup.append(
    el("strong", {}, "Not connected to a SENTINEL server"),
    el("p", { class: "muted" }, `Sites are not being checked. The server at ${status.settings.serverUrl} could not be reached when the extension started.`),
    el("div", { class: "actions" }, retry),
    error,
  );
}

function renderAlerts(status: Status) {
  const list = byId("alerts");
  list.replaceChildren();
  byId("clear-alerts").hidden = status.alerts.length === 0;
  if (status.alerts.length === 0) {
    list.append(el("li", { class: "muted" }, "No alerts. Warnings you see will be listed here."));
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
  byId("state-label").textContent = STATE_TEXT[status.state];
  byId<HTMLAnchorElement>("dashboard").href = `${status.settings.serverUrl.replace(/\/$/, "")}/dashboard`;
  renderPage(status);
  renderSetup(status);
  renderAlerts(status);
}

async function refresh() {
  render(await ask<Status>({ type: "status", tabId: activeTab?.id, url: activeTab?.url }));
}

async function main() {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  // Show "checking" immediately; the first status may wait for a network check.
  byId("page").replaceChildren(el("div", { class: "checking", "aria-hidden": "true" }), el("p", { class: "muted" }, "Checking this page…"));
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
