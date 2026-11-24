import { describe, expect, it } from "vitest";

import { EMPTY_STATE, fetchRange, htmlLinks, sanitizeAccount, scanInbox, stripHtml, worrying } from "../src/engine/mail";

const RAW = [
  "From: PayPal Service <notice@pay-help.example>",
  "Reply-To: claims@elsewhere.example",
  "To: you@example.org",
  "Subject: Your account is limited",
  "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=pay-help.example; dkim=none; dmarc=fail",
  "Date: Thu, 19 Nov 2026 08:00:00 +0000",
  "MIME-Version: 1.0",
  "Content-Type: text/html; charset=utf-8",
  "",
  '<p>Please <a href="https://pay-help.example/login">www.paypal.com</a> &amp; confirm.</p><a href="mailto:x@y.z">mail</a>',
].join("\r\n");

describe("mail engine", () => {
  it("validates the account", () => {
    expect(sanitizeAccount({ host: "IMAP.Example.com", user: "me@example.com" })).toEqual({ host: "imap.example.com", port: 993, user: "me@example.com" });
    expect(() => sanitizeAccount({ host: "imaps://x", user: "a" })).toThrow();
    expect(() => sanitizeAccount({ host: "imap.example.com", port: 70000, user: "a" })).toThrow();
    expect(() => sanitizeAccount({ host: "imap.example.com", user: "" })).toThrow();
  });

  it("reads links and text out of HTML", () => {
    expect(htmlLinks('<a class="x" href="https://a.example/p?q=1&amp;r=2">Go <b>here</b></a> <a href="mailto:a@b.c">m</a>')).toEqual([
      { href: "https://a.example/p?q=1&r=2", text: "Go here" },
    ]);
    expect(stripHtml("<style>p{}</style><p>Hello&nbsp;there</p><p>Bye</p>")).toBe("Hello there\nBye");
  });

  it("reads new messages only, starting over when the mailbox changes", () => {
    expect(fetchRange(EMPTY_STATE, "7", 100)).toEqual({ from: 75, fresh: true });
    expect(fetchRange({ ...EMPTY_STATE, uidValidity: "7", lastUid: 90 }, "7", 100)).toEqual({ from: 91, fresh: false });
    expect(fetchRange({ ...EMPTY_STATE, uidValidity: "7", lastUid: 10 }, "7", 1000)).toEqual({ from: 950, fresh: false });
    expect(fetchRange({ ...EMPTY_STATE, uidValidity: "6", lastUid: 90 }, "7", 100).fresh).toBe(true);
  });

  it("sends the headers, text and links to the server and keeps the verdict", async () => {
    const sent: Record<string, unknown>[] = [];
    const fetcher = (async (_url: string, init: RequestInit) => {
      sent.push(JSON.parse(String(init.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({ risk: "suspicious", summary: "Warning signs", findings: [{ severity: "high", title: "The sender claims to be PayPal", explanation: "" }] }));
    }) as typeof fetch;
    const read = async () => ({ messages: [{ uid: 42, source: Buffer.from(RAW) }], uidValidity: "7", fresh: true });
    const { state, added } = await scanInbox({ host: "imap.example.com", port: 993, user: "me" }, "pw", EMPTY_STATE, "https://qalaa.example", { read, fetcher });

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      from_header: '"PayPal Service" <notice@pay-help.example>',
      reply_to: "claims@elsewhere.example",
      subject: "Your account is limited",
      links: [{ href: "https://pay-help.example/login", text: "www.paypal.com" }],
    });
    expect(String(sent[0]?.authentication_results)).toContain("dmarc=fail");
    expect(String(sent[0]?.text)).toContain("confirm");
    expect(state).toMatchObject({ uidValidity: "7", lastUid: 42, lastError: null });
    expect(worrying(added).map((r) => r.subject)).toEqual(["Your account is limited"]);
  });

  it("keeps a friendly error instead of throwing", async () => {
    const read = async () => {
      throw new Error("Command failed: AUTHENTICATIONFAILED");
    };
    const { state } = await scanInbox({ host: "imap.example.com", port: 993, user: "me" }, "pw", { ...EMPTY_STATE, lastUid: 5 }, "https://q.example", { read });
    expect(state.lastUid).toBe(5);
    expect(state.lastError).toMatch(/app password/);
  });
});
