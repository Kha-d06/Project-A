import { byId, el } from "../lib/dom";
import { initLanguage, localizeDocument, t } from "../lib/i18n";
import { ask } from "../lib/messages";
import type { CheckResult } from "../lib/types";
import { VERDICTS } from "../lib/verdicts";

const ICON_PATH = "M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z";

function icon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", ICON_PATH);
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "2");
  path.setAttribute("stroke-linecap", "round");
  svg.append(path);
  return svg;
}

function headline(verdict: CheckResult["verdict"]): string | undefined {
  const w = t().warning;
  return { dangerous: w.headlineDangerous, suspicious: w.headlineSuspicious, blocked_by_you: w.headlineBlocked }[verdict as string];
}

function advice(verdict: CheckResult["verdict"]): string {
  const w = t().warning;
  return { dangerous: w.adviceDangerous, suspicious: w.adviceSuspicious, blocked_by_you: w.adviceBlocked }[verdict as string] ?? "";
}

function goBack(target: string, verdict: CheckResult["verdict"]) {
  // The background knows the last page this tab opened without a warning.
  void ask({ type: "go-back", url: target, verdict }).catch(() => history.back());
}

function render(target: string, result: CheckResult) {
  const presentation = VERDICTS[result.verdict];
  const w = t().warning;
  document.title = `${w.stopped}: ${result.host}`;
  const proceedAllowed = result.verdict !== "blocked_by_you";

  const sections: (HTMLElement | null)[] = [
    el(
      "div",
      { class: "headline" },
      el("span", { class: `icon tone-${presentation.tone}` }, icon()),
      el(
        "div",
        { class: "stack" },
        el("h1", {}, headline(result.verdict) ?? presentation.label),
        el("p", { class: "host mono" }, result.host),
        el("p", { class: "muted" }, `${w.riskLevel(presentation.label)} ${advice(result.verdict)}`),
      ),
    ),
    result.reasons.length
      ? el(
          "section",
          { class: "stack" },
          el("h2", { class: "faint" }, w.why),
          el(
            "ul",
            { class: "reasons" },
            ...result.reasons.map((reason) =>
              el("li", {}, el("strong", {}, reason.title), el("p", { class: "muted" }, reason.explanation), el("p", { class: "faint" }, w.source(reason.source))),
            ),
          ),
        )
      : null,
    el(
      "div",
      { class: "primary-actions" },
      el("button", { type: "button", id: "back", onclick: () => goBack(target, result.verdict) }, w.goBack),
    ),
    proceedAllowed
      ? el(
          "details",
          {},
          el("summary", {}, w.understand),
          el(
            "div",
            { class: "stack" },
            el("p", { class: "muted" }, result.verdict === "dangerous" ? w.proceedDangerous : w.proceedSuspicious),
            el("button", { type: "button", class: "danger", onclick: () => void ask({ type: "proceed", url: target }) }, w.continueTo(result.host)),
          ),
        )
      : null,
    result.limitations.length ? el("p", { class: "faint" }, result.limitations.join(" ")) : null,
  ];
  byId("content").replaceChildren(...sections.filter((section) => section !== null));
  byId("back").focus();
}

async function main() {
  await initLanguage();
  localizeDocument();
  const w = t().warning;
  const target = new URLSearchParams(location.search).get("u");
  if (!target) {
    byId("content").replaceChildren(el("p", { class: "muted" }, w.noAddress));
    return;
  }
  try {
    const result = await ask<CheckResult | null>({ type: "verdict-for", url: target });
    if (!result) throw new Error(w.notChecked);
    render(target, result);
  } catch (error) {
    byId("content").replaceChildren(
      el("h1", {}, w.stopped),
      el("p", { class: "muted" }, error instanceof Error ? error.message : String(error)),
      el("div", { class: "primary-actions" }, el("button", { type: "button", onclick: () => history.back() }, w.back)),
    );
  }
}

void main();
