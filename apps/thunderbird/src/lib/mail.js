/**
 * Turning a Thunderbird message into the request for the Qalaa email check.
 * Pure functions, so they can be tested without Thunderbird.
 */

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
const MAX_TEXT = 20_000;

function decodeEntities(text) {
  return text
    .replace(/&#(\d+);/g, (_m, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (m, name) => ENTITIES[name.toLowerCase()] ?? m);
}

export function stripHtml(html) {
  return decodeEntities(
    html
      .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?>|<\/(p|div|li|tr|h\d)>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t]+/g, " ")
    .replace(/ ?\n\s*/g, "\n")
    .trim();
}

/** Web links with the text each one shows. */
export function htmlLinks(html) {
  const links = [];
  const anchor = /<a\b[^>]*?\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  for (const match of html.matchAll(anchor)) {
    const href = decodeEntities((match[2] ?? match[3] ?? match[4] ?? "").trim());
    if (!/^https?:\/\//i.test(href)) continue;
    links.push({ href: href.slice(0, 2048), text: stripHtml(match[5] ?? "").slice(0, 300) });
    if (links.length >= 200) break;
  }
  return links;
}

/** The first plain-text and HTML bodies, skipping attachments. */
export function bodies(part, found = { text: "", html: "" }) {
  if (!part) return found;
  const attachment = part.name || /attachment/i.test(String(part.headers?.["content-disposition"]?.[0] ?? ""));
  if (!attachment && typeof part.body === "string") {
    if (part.contentType === "text/plain" && !found.text) found.text = part.body;
    if (part.contentType === "text/html" && !found.html) found.html = part.body;
  }
  for (const child of part.parts ?? []) bodies(child, found);
  return found;
}

function header(full, name) {
  const value = full.headers?.[name];
  return Array.isArray(value) ? value.join("; ") : String(value ?? "");
}

/** Builds the check request from messages.getFull() and the message header. */
export function toCheckRequest(full, message = {}) {
  const { text, html } = bodies(full);
  const replyTo = header(full, "reply-to");
  return {
    from_header: (message.author || header(full, "from")).slice(0, 500),
    reply_to: replyTo ? replyTo.slice(0, 500) : null,
    subject: (message.subject || header(full, "subject")).slice(0, 1000),
    authentication_results: header(full, "authentication-results").slice(0, 4000),
    text: (text.trim() || stripHtml(html)).slice(0, MAX_TEXT),
    links: html ? htmlLinks(html) : [],
  };
}

export function badgeFor(risk) {
  if (risk === "known_malicious") return { text: "!", color: "#b42318" };
  if (risk === "suspicious") return { text: "?", color: "#b54708" };
  return { text: "", color: "#667085" };
}

/** Only https, except a server on this computer. */
export function cleanServerUrl(raw) {
  const url = new URL(String(raw).trim());
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error("Use an https:// address, except for a server on this computer.");
  }
  return url.origin;
}
