/**
 * Mailbox scanning over IMAP.
 *
 * The person connects one mailbox (ideally with an app password). Qalaa opens the
 * inbox read-only, so nothing is moved, deleted or marked as read, and reads new
 * messages since the last check. For each one it sends the sender headers, the
 * mail provider's authentication results, the subject, the text and the links to
 * the Qalaa server's email check, which answers at once and stores nothing.
 * Attachments are never sent. The password stays on this computer, encrypted by
 * the operating system's keychain where one is available.
 */
import { ImapFlow } from "imapflow";
import { type ParsedMail, simpleParser } from "mailparser";

export interface MailAccount {
  host: string;
  port: number;
  user: string;
}

export interface MailState {
  uidValidity: string | null;
  lastUid: number;
  lastCheck: string | null;
  lastError: string | null;
  results: MailResult[];
}

export interface EmailCheckRequest {
  from_header: string;
  reply_to: string | null;
  subject: string;
  authentication_results: string;
  text: string;
  links: { href: string; text: string }[];
}

export interface MailFinding {
  severity: string;
  title: string;
  explanation: string;
}

export interface MailResult {
  uid: number;
  from: string;
  subject: string;
  date: string | null;
  risk: string;
  summary: string;
  findings: MailFinding[];
}

export const EMPTY_STATE: MailState = { uidValidity: null, lastUid: 0, lastCheck: null, lastError: null, results: [] };
/** Messages read the first time, and at most per check after that. */
export const FIRST_SCAN = 25;
export const MAX_PER_CHECK = 50;
/** Only the first part of a very large message is read; attachments are not needed. */
const MAX_SOURCE_BYTES = 1_000_000;
const MAX_TEXT = 20_000;
const KEEP_RESULTS = 100;

const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export function sanitizeAccount(input: Record<string, unknown>): MailAccount {
  const host = String(input.host ?? "").trim().toLowerCase();
  if (!HOST.test(host)) throw new Error("Enter the mail server's name, such as imap.example.com.");
  const port = input.port === undefined || input.port === "" ? 993 : Number(input.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("The port must be a number from 1 to 65535.");
  const user = String(input.user ?? "").trim();
  if (!user || user.length > 320) throw new Error("Enter the mailbox's user name, usually the email address.");
  return { host, port, user };
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

function decodeEntities(text: string): string {
  return text
    .replace(/&#(\d+);/g, (_m, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, n: string) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (m, name: string) => ENTITIES[name.toLowerCase()] ?? m);
}

export function stripHtml(html: string): string {
  return decodeEntities(
    html
      .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?>|<\/(p|div|li|tr|h\d)>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t]+/g, " ")
    .replace(/ ?\n[\s]*/g, "\n")
    .trim();
}

/** Each link with the text it shows. Only web links: mailto and the like are left out. */
export function htmlLinks(html: string): { href: string; text: string }[] {
  const links: { href: string; text: string }[] = [];
  const anchor = /<a\b[^>]*?\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  for (const match of html.matchAll(anchor)) {
    const href = decodeEntities((match[2] ?? match[3] ?? match[4] ?? "").trim());
    if (!/^https?:\/\//i.test(href)) continue;
    links.push({ href: href.slice(0, 2048), text: stripHtml(match[5] ?? "").slice(0, 300) });
    if (links.length >= 200) break;
  }
  return links;
}

function headerText(parsed: ParsedMail, name: string): string {
  const value = parsed.headers.get(name);
  if (value === undefined || value === null) return "";
  if (Array.isArray(value)) return value.map(String).join("; ");
  if (typeof value === "object" && "text" in value) return String((value as { text: string }).text);
  return String(value);
}

export function toCheckRequest(parsed: ParsedMail): EmailCheckRequest {
  const html = typeof parsed.html === "string" ? parsed.html : "";
  const text = (parsed.text?.trim() || stripHtml(html)).slice(0, MAX_TEXT);
  return {
    from_header: (parsed.from?.text ?? "").slice(0, 500),
    reply_to: parsed.replyTo?.text ? parsed.replyTo.text.slice(0, 500) : null,
    subject: (parsed.subject ?? "").slice(0, 1000),
    authentication_results: headerText(parsed, "authentication-results").slice(0, 4000),
    text,
    links: html ? htmlLinks(html) : [],
  };
}

export async function checkEmail(server: string, request: EmailCheckRequest, fetcher: typeof fetch = fetch): Promise<{ risk: string; summary: string; findings: MailFinding[] }> {
  const response = await fetcher(`${server.replace(/\/$/, "")}/api/v1/email/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`The Qalaa server answered ${response.status}`);
  return (await response.json()) as { risk: string; summary: string; findings: MailFinding[] };
}

/** Which UIDs to read: new ones since the last check, or the latest few the first time. */
export function fetchRange(state: MailState, uidValidity: string, uidNext: number): { from: number; fresh: boolean } {
  const fresh = state.uidValidity !== uidValidity || state.lastUid <= 0;
  const from = fresh ? Math.max(1, uidNext - FIRST_SCAN) : Math.max(state.lastUid + 1, uidNext - MAX_PER_CHECK);
  return { from, fresh };
}

export function mergeResults(previous: MailResult[], added: MailResult[]): MailResult[] {
  return [...added.sort((a, b) => b.uid - a.uid), ...previous].slice(0, KEEP_RESULTS);
}

export interface RawMessage {
  uid: number;
  source: Buffer;
}

/** Reads new messages from INBOX without changing anything on the server. */
export async function readNewMessages(account: MailAccount, password: string, state: MailState): Promise<{ messages: RawMessage[]; uidValidity: string; fresh: boolean }> {
  const client = new ImapFlow({
    host: account.host,
    port: account.port,
    secure: account.port !== 143,
    auth: { user: account.user, pass: password },
    logger: false,
    // Never fall back to an unencrypted connection.
    doSTARTTLS: account.port === 143 ? true : undefined,
  });
  await client.connect();
  const messages: RawMessage[] = [];
  try {
    const lock = await client.getMailboxLock("INBOX", { readOnly: true });
    try {
      const box = client.mailbox;
      if (!box) throw new Error("The inbox could not be opened.");
      const uidValidity = String(box.uidValidity);
      const { from, fresh } = fetchRange(state, uidValidity, Number(box.uidNext));
      if (box.exists > 0 && from < Number(box.uidNext)) {
        for await (const message of client.fetch(`${from}:*`, { uid: true, source: { maxLength: MAX_SOURCE_BYTES } }, { uid: true })) {
          if (message.uid >= from && message.source) messages.push({ uid: message.uid, source: message.source });
        }
      }
      return { messages, uidValidity, fresh };
    } finally {
      lock.release();
    }
  } finally {
    await client.logout().catch(() => undefined);
  }
}

/** Checks new mail and returns the updated state. Errors are kept in the state, not thrown. */
export async function scanInbox(
  account: MailAccount,
  password: string,
  state: MailState,
  server: string,
  deps: { read?: typeof readNewMessages; fetcher?: typeof fetch; now?: () => Date } = {},
): Promise<{ state: MailState; added: MailResult[] }> {
  const read = deps.read ?? readNewMessages;
  const now = (deps.now ?? (() => new Date()))().toISOString();
  try {
    const { messages, uidValidity, fresh } = await read(account, password, state);
    const added: MailResult[] = [];
    let lastUid = fresh ? 0 : state.lastUid;
    for (const message of messages.sort((a, b) => a.uid - b.uid)) {
      const parsed = await simpleParser(message.source, { skipImageLinks: true, skipTextToHtml: true });
      const verdict = await checkEmail(server, toCheckRequest(parsed), deps.fetcher);
      added.push({
        uid: message.uid,
        from: parsed.from?.text ?? "",
        subject: parsed.subject ?? "",
        date: parsed.date ? parsed.date.toISOString() : null,
        risk: verdict.risk,
        summary: verdict.summary,
        findings: verdict.findings.slice(0, 6),
      });
      lastUid = Math.max(lastUid, message.uid);
    }
    return {
      state: { uidValidity, lastUid, lastCheck: now, lastError: null, results: mergeResults(fresh ? [] : state.results, added) },
      added,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const friendly = /auth|login|credentials/i.test(message)
      ? "The mail server did not accept the user name or password. Many providers need an app password for this."
      : message;
    return { state: { ...state, lastCheck: now, lastError: friendly }, added: [] };
  }
}

/** Results worth a notification. */
export function worrying(results: MailResult[]): MailResult[] {
  return results.filter((result) => result.risk === "suspicious" || result.risk === "known_malicious");
}
