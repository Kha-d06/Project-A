import { localizePage, t } from "./lib/i18n.js";

const BADGE = { known_malicious: "bad", suspicious: "warn", no_known_threat: "ok", inconclusive: "ok" };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  for (const child of children) if (child) node.append(child);
  return node;
}

async function main() {
  localizePage();
  const s = t();
  const content = document.getElementById("content");
  const [tab] = await messenger.tabs.query({ active: true, currentWindow: true });
  const entry = await messenger.runtime.sendMessage({ type: "result", tabId: tab.id });
  if (!entry || entry.state === "none") return content.replaceChildren(el("p", { class: "muted" }, s.notChecked));
  if (entry.state === "setup") return content.replaceChildren(el("p", {}, s.setup));
  if (entry.state === "error") return content.replaceChildren(el("p", { class: "error" }, s.failed(entry.error)));
  const r = entry.result;
  const parts = [
    el("p", {}, el("span", { class: `badge ${BADGE[r.risk] ?? "ok"}` }, s.risk[r.risk] ?? r.risk)),
    el("p", { dir: "auto" }, r.summary),
  ];
  if (r.findings.length) {
    parts.push(el("ul", { class: "findings" }, ...r.findings.slice(0, 6).map((f) => el("li", {}, el("strong", { dir: "auto" }, f.title), el("span", { class: "muted", dir: "auto" }, f.explanation)))));
  }
  if (r.recommendations?.length) parts.push(el("ul", { class: "advice" }, ...r.recommendations.slice(0, 3).map((line) => el("li", { dir: "auto" }, line))));
  if (r.limitations?.length) {
    parts.push(el("details", {}, el("summary", {}, s.limitsTitle), ...r.limitations.map((line) => el("p", { class: "muted", dir: "auto" }, line))));
  }
  parts.push(el("p", { class: "muted small" }, s.privacy));
  content.replaceChildren(...parts);
}

void main();
