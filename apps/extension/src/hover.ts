/**
 * Optional content script (registered only when the user enables hover checks).
 * It reads link addresses on hover and nothing else from the page: no text, no
 * form values. Results appear only for links with warning signs.
 */
import type { CheckResult } from "./lib/types";

const HOVER_DELAY_MS = 600;
const TOOLTIP_ID = "sentinel-hover-warning";
let timer: number | undefined;
let lastHref = "";

function removeTooltip() {
  document.getElementById(TOOLTIP_ID)?.remove();
}

function showTooltip(anchor: HTMLAnchorElement, result: CheckResult) {
  removeTooltip();
  const host = document.createElement("div");
  host.id = TOOLTIP_ID;
  // Shadow DOM keeps the page's styles out and our styles in.
  const root = host.attachShadow({ mode: "closed" });
  const box = document.createElement("div");
  box.setAttribute("role", "status");
  const danger = result.verdict === "dangerous" || result.verdict === "blocked_by_you" || result.verdict === "blocked_by_family";
  box.style.cssText = `position:fixed;z-index:2147483647;max-width:320px;padding:8px 12px;border-radius:8px;font:13px/1.4 system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.2);background:${danger ? "#fdecea" : "#fdf3e2"};color:#0c1424;border:1px solid ${danger ? "#b42318" : "#a15c07"}`;
  const title = document.createElement("strong");
  title.textContent = `Qalaa: ${danger ? "Dangerous link" : "Suspicious link"} (${result.host})`;
  const reason = document.createElement("div");
  reason.textContent = result.reasons[0]?.title ?? "";
  box.append(title, reason);
  root.append(box);
  const rect = anchor.getBoundingClientRect();
  box.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - 330))}px`;
  box.style.top = `${rect.bottom + 6 > window.innerHeight - 60 ? rect.top - 60 : rect.bottom + 6}px`;
  document.documentElement.append(host);
}

document.addEventListener(
  "mouseover",
  (event) => {
    const anchor = (event.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
    window.clearTimeout(timer);
    if (!anchor || !anchor.href.startsWith("http")) return;
    timer = window.setTimeout(async () => {
      if (anchor.href === lastHref) return;
      lastHref = anchor.href;
      try {
        const response = (await chrome.runtime.sendMessage({ type: "hover", href: anchor.href })) as { ok: boolean; data: CheckResult | null } | undefined;
        if (response?.ok && response.data && anchor.matches(":hover")) showTooltip(anchor, response.data);
      } catch {
        // Extension reloaded or unavailable: stay silent rather than break the page.
      }
    }, HOVER_DELAY_MS);
  },
  { passive: true },
);
document.addEventListener("mouseout", () => {
  window.clearTimeout(timer);
  lastHref = "";
  removeTooltip();
}, { passive: true });
