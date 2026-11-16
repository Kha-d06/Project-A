/**
 * Decides which scanner should open for content shared from another app.
 * A lone link goes to the link scanner; anything else is treated as a message.
 */
const URL_ONLY = /^\s*(https?:\/\/\S+)\s*$/i;
const MAX_TEXT = 10_000;
const MAX_URL = 2048;

export function shareDestination(params: URLSearchParams): string {
  const sharedUrl = params.get("url")?.trim() ?? "";
  const text = [params.get("title"), params.get("text")].filter(Boolean).join("\n").trim();
  const target = new URLSearchParams();

  const linkOnly = sharedUrl && (!text || text === sharedUrl) ? sharedUrl : URL_ONLY.exec(text)?.[1];
  if (linkOnly) {
    target.set("type", "url");
    target.set("url", linkOnly.slice(0, MAX_URL));
  } else {
    target.set("type", "message");
    target.set("text", [text, sharedUrl].filter(Boolean).join("\n").slice(0, MAX_TEXT));
  }
  return `/scan?${target}`;
}
