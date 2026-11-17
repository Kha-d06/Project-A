/**
 * Optional content script for Google, Bing and DuckDuckGo result pages: puts a
 * small SENTINEL badge next to results with warning signs. It reads only the
 * result links' addresses; results without warnings are left untouched.
 */
import { initLanguage, t } from "./lib/i18n";
import type { CheckResult } from "./lib/types";

const SELECTORS = [
  "#search a[href^='http']:has(h3)", // Google
  "#b_results h2 a[href^='http']", // Bing
  "a[data-testid='result-title-a']", // DuckDuckGo
];
const MAX_RESULTS = 20;
const MARK = "data-sentinel-checked";
const COLORS: Record<string, [string, string]> = {
  dangerous: ["#b42318", "#fdecea"],
  blocked_by_you: ["#b42318", "#fdecea"],
  blocked_by_family: ["#b42318", "#fdecea"],
  suspicious: ["#a15c07", "#fdf3e2"],
  caution: ["#a15c07", "#fdf3e2"],
};

/** Google wraps some results in redirect links; use the real destination. */
function destination(anchor: HTMLAnchorElement): string {
  try {
    const url = new URL(anchor.href);
    if (/(^|\.)google\./.test(url.hostname) && url.pathname === "/url") return url.searchParams.get("q") ?? url.searchParams.get("url") ?? anchor.href;
  } catch {
    // keep the raw link
  }
  return anchor.href;
}

function badge(result: CheckResult): HTMLElement {
  const host = document.createElement("span");
  const root = host.attachShadow({ mode: "closed" });
  const [ink, background] = COLORS[result.verdict] ?? ["#4f5878", "#eef0f6"];
  const label = document.createElement("span");
  label.textContent = `⚠ ${t().verdicts[result.verdict].label}`;
  label.title = result.reasons[0]?.title ?? t().verdicts[result.verdict].detail;
  label.setAttribute("role", "note");
  label.style.cssText = `display:inline-block;margin-inline-start:8px;padding:1px 8px;border-radius:999px;font:600 12px/1.6 system-ui,sans-serif;color:${ink};background:${background};border:1px solid ${ink};vertical-align:middle`;
  root.append(label);
  return host;
}

async function annotate() {
  const anchors = SELECTORS.flatMap((selector) => [...document.querySelectorAll<HTMLAnchorElement>(selector)])
    .filter((anchor) => !anchor.hasAttribute(MARK))
    .slice(0, MAX_RESULTS);
  if (!anchors.length) return;
  for (const anchor of anchors) anchor.setAttribute(MARK, "");
  let results: (CheckResult | null)[] = [];
  try {
    const response = (await chrome.runtime.sendMessage({ type: "search-check", urls: anchors.map(destination) })) as { ok: boolean; data: (CheckResult | null)[] } | undefined;
    results = response?.ok ? response.data : [];
  } catch {
    return; // extension reloaded
  }
  anchors.forEach((anchor, index) => {
    const result = results[index];
    if (result && COLORS[result.verdict]) (anchor.querySelector("h3") ?? anchor).after(badge(result));
  });
}

void initLanguage().then(() => {
  void annotate();
  // Results load in pages as the user scrolls; check new ones as they appear.
  let pending: number | undefined;
  new MutationObserver(() => {
    window.clearTimeout(pending);
    pending = window.setTimeout(() => void annotate(), 500);
  }).observe(document.body, { childList: true, subtree: true });
});
