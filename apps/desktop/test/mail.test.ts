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

  it("checks on the device and sends only bare links", async () => {
    const calls: { url: string; body: string | null }[] = [];
    const pack = {
      version: "v1",
      rules: [{ category: "account_threat", severity: "medium", title: "Threatens that an account will be suspended or closed", explanation: "", title_ar: "تهدّد", explanation_ar: "", patterns: ["\\baccount\\b.{0,30}\\blimited\\b"] }],
      brands: { paypal: { name: "PayPal", domains: ["paypal.com"] } },
      shorteners: [],
    };
    const fetcher = (async (url: string, init?: RequestInit) => {
      calls.push({ url, body: init?.body ? String(init.body) : null });
      if (url.endsWith("/email/rules")) return new Response(JSON.stringify(pack));
      return new Response(JSON.stringify({ results: [{ url: "https://pay-help.example/login", host: "pay-help.example", findings: [] }] }));
    }) as typeof fetch;
    const read = async () => ({ messages: [{ uid: 42, source: Buffer.from(RAW) }], uidValidity: "7", fresh: true });
    const now = () => new Date("2026-11-24T10:00:00Z");
    const { state, added } = await scanInbox({ host: "imap.example.com", port: 993, user: "me" }, "pw", EMPTY_STATE, "https://qalaa.example", { read, fetcher, now });

    expect(calls.map((c) => c.url)).toEqual(["https://qalaa.example/api/v1/email/rules", "https://qalaa.example/api/v1/email/links"]);
    expect(calls[0]?.body).toBeNull();
    // The only thing about the message that leaves the device: its bare links.
    expect(JSON.parse(String(calls[1]?.body))).toEqual({ urls: ["https://pay-help.example/login"] });
    const sent = calls.map((c) => c.body ?? "").join(" ");
    for (const secret of ["Your account is limited", "notice@pay-help.example", "dmarc", "confirm"]) expect(sent).not.toContain(secret);

    expect(state).toMatchObject({ uidValidity: "7", lastUid: 42, lastError: null, packFetchedAt: "2026-11-24T10:00:00.000Z" });
    const [result] = added;
    expect(result?.risk).toBe("suspicious");
    expect(result?.linksChecked).toBe(true);
    expect(result?.findings.map((f) => f.title)).toEqual(
      expect.arrayContaining([
        "The sender's domain says this email is not from it",
        "The sender claims to be PayPal",
        "A link shows one address but opens another",
        "Threatens that an account will be suspended or closed",
      ]),
    );
    expect(worrying(added).map((r) => r.subject)).toEqual(["Your account is limited"]);

    // The next check within a day reuses the pack; an unreachable server still gives a local verdict.
    calls.length = 0;
    const offline = (async (url: string, init?: RequestInit) => {
      calls.push({ url, body: init?.body ? String(init.body) : null });
      throw new Error("offline");
    }) as typeof fetch;
    const again = await scanInbox({ host: "imap.example.com", port: 993, user: "me" }, "pw", { ...state, uidValidity: null }, "https://qalaa.example", { read, fetcher: offline, now });
    expect(calls.map((c) => c.url)).toEqual(["https://qalaa.example/api/v1/email/links"]);
    expect(again.added[0]?.risk).toBe("suspicious");
    expect(again.added[0]?.linksChecked).toBe(false);
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
