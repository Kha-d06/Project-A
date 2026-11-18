/**
 * The on-screen assistant: a small Qalaa button in the corner of web pages.
 * Registered only when the user turns it on (optional permissions).
 *
 * What it reads from the page: the page address, the host names of resources the
 * page loaded (to spot trackers) and whether a password field is focused. Never
 * page text, form values or cookie values. Everything is drawn inside a closed
 * shadow root, with textContent only, so the page cannot style or script it and
 * nothing from the page is ever interpreted as markup.
 */
import type { PageSummary } from "./lib/assistant-core";
import { isWarning } from "./lib/assistant-core";
import { initLanguage, language, t } from "./lib/i18n";
import type { Verdict } from "./lib/types";

declare const __TEST_BUILD__: boolean;
const HOST_ID = "sentinel-assistant-root";
const TONE: Record<string, string> = {
  dangerous: "#b42318",
  blocked_by_you: "#b42318",
  blocked_by_family: "#b42318",
  suspicious: "#a15c07",
  caution: "#a15c07",
  no_known_threat: "#1d6b52",
};

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", "Noto Sans Arabic", sans-serif; }
.wrap { position: fixed; bottom: 18px; inset-inline-end: 18px; z-index: 2147483646; display: flex; flex-direction: column; align-items: flex-end; gap: 10px; color: #0c1424; }
.fab { width: 48px; height: 48px; border-radius: 50%; border: 0; cursor: pointer; background: #0c1424; color: #fff; display: grid; place-items: center; box-shadow: 0 6px 20px rgba(12,20,36,.28); position: relative; transition: transform .15s; }
.fab:hover { transform: translateY(-2px); }
.fab:focus-visible, button:focus-visible, input:focus-visible { outline: 3px solid #4c7cf0; outline-offset: 2px; }
.fab svg { width: 26px; height: 26px; }
.dot { position: absolute; top: 2px; inset-inline-end: 2px; width: 13px; height: 13px; border-radius: 50%; border: 2px solid #fff; }
.card { width: min(360px, calc(100vw - 36px)); max-height: min(560px, calc(100vh - 100px)); overflow: auto; background: #fff; border: 1px solid #d7dce8; border-radius: 14px; box-shadow: 0 14px 40px rgba(12,20,36,.25); padding: 14px 16px; font-size: 13px; line-height: 1.45; }
.bubble { width: min(340px, calc(100vw - 36px)); background: #fff; border-radius: 12px; border: 1px solid; border-inline-start-width: 5px; padding: 12px 14px; font-size: 13px; line-height: 1.45; box-shadow: 0 10px 30px rgba(12,20,36,.22); }
.row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
h2 { font-size: 15px; margin: 0; }
h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #4f5878; margin: 14px 0 6px; }
p { margin: 4px 0; }
.muted { color: #4f5878; }
.faint { color: #6b7391; font-size: 12px; }
.verdict { display: flex; gap: 10px; align-items: flex-start; padding: 10px; border-radius: 10px; background: #f4f6fb; margin-top: 10px; }
.verdict .mark { width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; flex: none; }
ul { list-style: none; padding: 0; margin: 0; display: grid; gap: 4px; }
li.cookie { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; padding: 4px 0; border-bottom: 1px solid #eef0f6; }
li.cookie code { font-family: ui-monospace, Menlo, monospace; font-size: 12px; overflow-wrap: anywhere; }
.tag { font-size: 11px; padding: 1px 6px; border-radius: 999px; background: #eef0f6; color: #4f5878; white-space: nowrap; }
.tag.third { background: #fdf3e2; color: #7a4504; }
button.ghost { background: none; border: 0; color: #4f5878; cursor: pointer; font-size: 18px; line-height: 1; padding: 4px; }
button.chip { background: #eef2fd; color: #23408f; border: 0; border-radius: 999px; padding: 5px 10px; cursor: pointer; font-size: 12px; }
button.primary { background: #0c1424; color: #fff; border: 0; border-radius: 8px; padding: 8px 12px; cursor: pointer; font-size: 13px; }
button.secondary { background: #eef0f6; color: #0c1424; border: 0; border-radius: 8px; padding: 7px 10px; cursor: pointer; font-size: 12px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0; }
form { display: flex; gap: 6px; margin-top: 6px; }
input { flex: 1; min-width: 0; border: 1px solid #c9cfdd; border-radius: 8px; padding: 8px 10px; font-size: 13px; color: inherit; background: #fff; }
.answer { margin-top: 8px; padding: 10px; border-radius: 10px; background: #f4f6fb; white-space: pre-wrap; }
@media (prefers-color-scheme: dark) {
  .wrap { color: #e8ecf6; }
  .card, .bubble { background: #141b2d; border-color: #2a3350; }
  .verdict, .answer { background: #1c2540; }
  .muted, h3 { color: #a9b2cc; } .faint { color: #8d96b3; }
  li.cookie { border-color: #222b45; } .tag { background: #222b45; color: #c3cae0; }
  .tag.third { background: #3a2a0e; color: #f3c27a; }
  input { background: #0f1526; border-color: #2a3350; }
  button.chip { background: #1f2b4f; color: #b9c9ff; } button.secondary { background: #222b45; color: #e8ecf6; }
  button.primary { background: #e8ecf6; color: #0c1424; } .fab { background: #1f2b4f; }
}
@media (prefers-reduced-motion: reduce) { .fab { transition: none; } }
`;

const SHIELD =
  "M16 2.5 4.5 6.8v8.4c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V6.8L16 2.5Z";

type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Record<string, string | ((event: Event) => void)> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === "function") element.addEventListener(key.slice(2), value);
    else element.setAttribute(key, value);
  }
  for (const child of children) if (child) element.append(child);
  return element;
}

function shieldIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", SHIELD);
  path.setAttribute("fill", "currentColor");
  svg.append(path);
  return svg;
}

async function send<T>(message: object): Promise<T | null> {
  try {
    const response = (await chrome.runtime.sendMessage(message)) as { ok: boolean; data: T } | undefined;
    return response?.ok ? response.data : null;
  } catch {
    return null; // extension reloaded: stay silent rather than break the page
  }
}

function resourceHosts(): string[] {
  const hosts = new Set<string>();
  const add = (raw: string | null | undefined) => {
    if (!raw) return;
    try {
      const url = new URL(raw, location.href);
      if (url.protocol.startsWith("http")) hosts.add(url.hostname);
    } catch {
      // ignore malformed addresses
    }
  };
  for (const entry of performance.getEntriesByType("resource")) add(entry.name);
  for (const node of document.querySelectorAll<HTMLScriptElement | HTMLIFrameElement>("script[src], iframe[src]")) add(node.src);
  hosts.delete(location.hostname);
  return [...hosts].slice(0, 200);
}

class Assistant {
  private root: ShadowRoot;
  private wrap: HTMLDivElement;
  private fab: HTMLButtonElement;
  private dot: HTMLSpanElement;
  private card: HTMLDivElement | null = null;
  private bubble: HTMLDivElement | null = null;
  private summary: PageSummary | null = null;
  private passwordWarned = false;
  private warningDismissed = false;

  constructor() {
    const host = document.createElement("div");
    host.id = HOST_ID;
    this.root = host.attachShadow({ mode: typeof __TEST_BUILD__ !== "undefined" && __TEST_BUILD__ ? "open" : "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.wrap = h("div", { class: "wrap", dir: language() === "ar" ? "rtl" : "ltr", lang: language() });
    this.dot = h("span", { class: "dot", "aria-hidden": "true" });
    this.dot.style.background = "#8d96b3";
    this.fab = h(
      "button",
      { class: "fab", type: "button", "aria-label": t().assistant.open, "aria-expanded": "false", onclick: () => this.toggle() },
      shieldIcon(),
      this.dot,
    );
    this.wrap.append(this.fab);
    this.root.append(style, this.wrap);
    document.documentElement.append(host);
  }

  async load(attempt = 0) {
    this.summary = await send<PageSummary>({ type: "assistant-summary", url: location.href, resourceHosts: resourceHosts() });
    // No answer yet (the extension's worker was starting, or the check failed): try again a few times.
    if (!this.summary?.result && attempt < 3) {
      window.setTimeout(() => void this.load(attempt + 1), 2000 * (attempt + 1));
      if (!this.summary) return;
    }
    const verdict = this.summary?.result?.verdict;
    if (verdict) this.dot.style.background = TONE[verdict] ?? "#8d96b3";
    if (this.card) this.renderCard();
    if (isWarning(verdict) && verdict !== "caution" && !this.warningDismissed) this.showSiteWarning();
  }

  private verdictLabel(verdict: Verdict | undefined): string {
    return t().verdicts[verdict ?? "unavailable"].label;
  }

  private showBubble(title: string, body: string, tone: string, withOpen = true) {
    this.bubble?.remove();
    const a = t().assistant;
    const bubble = h(
      "div",
      { class: "bubble", role: "alert" },
      h("strong", {}, title),
      h("p", {}, body),
      h(
        "div",
        { class: "row" },
        withOpen ? h("button", { class: "secondary", type: "button", onclick: () => { this.bubble?.remove(); this.bubble = null; this.open(); } }, a.open) : null,
        h("button", { class: "secondary", type: "button", onclick: () => { this.warningDismissed = true; this.bubble?.remove(); this.bubble = null; } }, a.dismiss),
      ),
    );
    bubble.style.borderColor = tone;
    this.bubble = bubble;
    this.wrap.prepend(bubble);
  }

  private showSiteWarning() {
    const result = this.summary?.result;
    if (!result) return;
    this.showBubble(
      t().assistant.warningTitle(this.verdictLabel(result.verdict)),
      result.reasons[0]?.title ?? t().verdicts[result.verdict].detail,
      TONE[result.verdict] ?? "#a15c07",
    );
  }

  async onPasswordFocus() {
    if (!this.summary) await this.load();
    const verdict = this.summary?.result?.verdict;
    if (this.passwordWarned || !isWarning(verdict)) return;
    this.passwordWarned = true;
    const a = t().assistant;
    this.showBubble(a.passwordTitle, a.passwordBody(this.verdictLabel(verdict)), TONE[verdict!] ?? "#a15c07");
  }

  private toggle() {
    if (this.card) this.close();
    else this.open();
  }

  private open() {
    this.bubble?.remove();
    this.bubble = null;
    this.card = h("div", { class: "card", role: "dialog", "aria-label": t().assistant.title });
    this.wrap.insertBefore(this.card, this.fab);
    this.fab.setAttribute("aria-expanded", "true");
    this.renderCard();
    this.card.querySelector<HTMLInputElement>("input")?.focus();
  }

  private close() {
    this.card?.remove();
    this.card = null;
    this.fab.setAttribute("aria-expanded", "false");
    this.fab.focus();
  }

  private renderCard() {
    if (!this.card) return;
    const a = t().assistant;
    const summary = this.summary;
    const result = summary?.result ?? null;

    const header = h(
      "div",
      { class: "row" },
      h("h2", {}, a.title),
      h("button", { class: "ghost", type: "button", "aria-label": a.close, onclick: () => this.close() }, "×"),
    );

    const mark = h("span", { class: "mark", "aria-hidden": "true" });
    mark.style.background = result ? TONE[result.verdict] ?? "#8d96b3" : "#8d96b3";
    const verdict = h(
      "div",
      { class: "verdict" },
      mark,
      h(
        "div",
        {},
        h("strong", {}, summary ? `${summary.host}: ${this.verdictLabel(result?.verdict)}` : a.checking),
        result ? h("p", { class: "muted" }, result.reasons[0]?.title ?? t().verdicts[result.verdict].detail) : null,
      ),
    );

    const cookies = summary?.cookies ?? [];
    const third = cookies.filter((c) => c.thirdParty).length;
    const cookieSection = h(
      "section",
      {},
      h("h3", {}, a.cookies),
      summary && !summary.cookiesAvailable
        ? h("p", { class: "muted" }, a.notReady)
        : h("p", { class: "muted" }, cookies.length ? a.cookiesSummary(cookies.length, third) : a.cookiesNone),
      cookies.length
        ? h(
            "ul",
            {},
            ...cookies.slice(0, 25).map((cookie) =>
              h(
                "li",
                { class: "cookie" },
                h("span", {}, h("code", {}, cookie.name), h("br"), h("span", { class: "faint" }, `${cookie.domain} · ${cookie.session ? a.session : a.days(cookie.days ?? 0)}`)),
                h("span", { class: cookie.thirdParty ? "tag third" : "tag" }, cookie.thirdParty ? a.thirdParty : a.firstParty),
              ),
            ),
          )
        : null,
      cookies.length ? h("p", { class: "faint" }, a.neverValues) : null,
    );

    const trackers = summary?.trackers ?? [];
    const trackerSection = h(
      "section",
      {},
      h("h3", {}, a.trackers),
      h("p", { class: "muted" }, trackers.length ? a.trackersSummary(trackers.length) : a.trackersNone),
      trackers.length ? h("p", {}, trackers.map((tracker) => tracker.name).join(language() === "ar" ? "، " : ", ")) : null,
    );

    const answer = h("div", { class: "answer", "aria-live": "polite" });
    answer.hidden = true;
    const input = h("input", { type: "text", maxlength: "500", placeholder: a.placeholder, "aria-label": a.ask });
    const ask = async (question: string) => {
      if (question.trim().length < 2) return;
      answer.hidden = false;
      answer.replaceChildren(h("span", { class: "muted" }, a.thinking));
      const hasPassword = !!document.querySelector("input[type=password]");
      const reply = await send<{ answer: string; source: "ai" | "builtin" }>({ type: "assistant-ask", question: question.trim(), url: location.href, hasPasswordField: hasPassword });
      answer.replaceChildren(
        h("div", {}, reply?.answer ?? a.error),
        ...(reply ? [h("p", { class: "faint" }, reply.source === "ai" ? a.aiLabel : a.builtInLabel)] : []),
      );
    };
    const qa = h(
      "section",
      {},
      h("h3", {}, a.ask),
      h("div", { class: "chips" }, ...a.suggestions.map((s) => h("button", { class: "chip", type: "button", onclick: () => { input.value = s; void ask(s); } }, s))),
      h(
        "form",
        { onsubmit: (event: Event) => { event.preventDefault(); void ask(input.value); } },
        input,
        h("button", { class: "primary", type: "submit" }, a.send),
      ),
      answer,
    );

    this.card.replaceChildren(header, verdict, cookieSection, trackerSection, qa);
  }
}

async function main() {
  if (window.top !== window || document.getElementById(HOST_ID)) return;
  await initLanguage();
  const assistant = new Assistant();
  document.addEventListener(
    "focusin",
    (event) => {
      const target = event.target as HTMLElement | null;
      if (target instanceof HTMLInputElement && target.type === "password") assistant.onPasswordFocus();
    },
    { capture: true, passive: true },
  );
  // Let the page settle so its trackers have loaded before they are counted.
  window.setTimeout(() => void assistant.load(), 1500);
}

void main();
