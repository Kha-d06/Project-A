import { byId, el } from "../lib/dom";
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

const HEADLINES: Partial<Record<CheckResult["verdict"], string>> = {
  dangerous: "This site is known to be dangerous",
  suspicious: "This site looks like an imitation",
  blocked_by_you: "You blocked this site",
};

const ADVICE: Partial<Record<CheckResult["verdict"], string>> = {
  dangerous: "Do not enter passwords, payment details or personal information, and do not download anything from it.",
  suspicious: "If you were expecting a well-known service, type its address yourself or use its official app instead.",
  blocked_by_you: "You can remove it from your block list in the extension settings.",
};

function goBack(target: string, verdict: CheckResult["verdict"]) {
  // The background knows the last page this tab opened without a warning.
  void ask({ type: "go-back", url: target, verdict }).catch(() => history.back());
}

function render(target: string, result: CheckResult) {
  const presentation = VERDICTS[result.verdict];
  document.title = `Warning: ${result.host}`;
  const proceedAllowed = result.verdict !== "blocked_by_you";

  const sections: (HTMLElement | null)[] = [
    el(
      "div",
      { class: "headline" },
      el("span", { class: `icon tone-${presentation.tone}` }, icon()),
      el(
        "div",
        { class: "stack" },
        el("h1", {}, HEADLINES[result.verdict] ?? presentation.label),
        el("p", { class: "host mono" }, result.host),
        el("p", { class: "muted" }, `Risk level: ${presentation.label}. ${ADVICE[result.verdict] ?? ""}`),
      ),
    ),
    result.reasons.length
      ? el(
          "section",
          { class: "stack" },
          el("h2", { class: "faint" }, "WHY SENTINEL STOPPED THIS PAGE"),
          el(
            "ul",
            { class: "reasons" },
            ...result.reasons.map((reason) =>
              el("li", {}, el("strong", {}, reason.title), el("p", { class: "muted" }, reason.explanation), el("p", { class: "faint" }, `Source: ${reason.source}`)),
            ),
          ),
        )
      : null,
    el(
      "div",
      { class: "primary-actions" },
      el("button", { type: "button", id: "back", onclick: () => goBack(target, result.verdict) }, "Go back to safety"),
    ),
    proceedAllowed
      ? el(
          "details",
          {},
          el("summary", {}, "I understand the risk"),
          el(
            "div",
            { class: "stack" },
            el("p", { class: "muted" }, result.verdict === "dangerous"
              ? "Threat intelligence lists this address as malicious. Continuing could expose your device or accounts. SENTINEL will not warn about this site again until you restart the browser."
              : "These are warning signs, not proof. If you are sure this is the site you meant to visit, you can continue. SENTINEL will not warn about it again until you restart the browser."),
            el("button", { type: "button", class: "danger", onclick: () => void ask({ type: "proceed", url: target }) }, `Continue to ${result.host}`),
          ),
        )
      : null,
    result.limitations.length ? el("p", { class: "faint" }, result.limitations.join(" ")) : null,
  ];
  byId("content").replaceChildren(...sections.filter((section) => section !== null));
  byId("back").focus();
}

async function main() {
  const target = new URLSearchParams(location.search).get("u");
  if (!target) {
    byId("content").replaceChildren(el("p", { class: "muted" }, "No address was given."));
    return;
  }
  try {
    const result = await ask<CheckResult | null>({ type: "verdict-for", url: target });
    if (!result) throw new Error("This address could not be checked.");
    render(target, result);
  } catch (error) {
    byId("content").replaceChildren(
      el("h1", {}, "SENTINEL stopped this page"),
      el("p", { class: "muted" }, error instanceof Error ? error.message : String(error)),
      el("div", { class: "primary-actions" }, el("button", { type: "button", onclick: () => history.back() }, "Go back")),
    );
  }
}

void main();
