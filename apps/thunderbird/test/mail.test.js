import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { dictionaries } from "../src/lib/i18n.js";
import { badgeFor, bodies, cleanServerUrl, htmlLinks, toCheckRequest } from "../src/lib/mail.js";

// The shape messages.getFull() returns in Thunderbird 128.
const FULL = {
  contentType: "message/rfc822",
  headers: {
    from: ['"PayPal Service" <notice@pay-help.example>'],
    "reply-to": ["claims@elsewhere.example"],
    subject: ["Your account is limited"],
    "authentication-results": ["mx.example.org; spf=fail; dkim=none; dmarc=fail"],
  },
  parts: [
    {
      contentType: "multipart/alternative",
      parts: [
        { contentType: "text/plain", body: "Please confirm at www.paypal.com" },
        { contentType: "text/html", body: '<p>Please <a href="https://pay-help.example/login">www.paypal.com</a> confirm</p>' },
      ],
    },
    { contentType: "text/plain", name: "notes.txt", body: "ATTACHMENT TEXT", headers: { "content-disposition": ["attachment"] } },
  ],
};

test("builds the check request without attachments", () => {
  const request = toCheckRequest(FULL, { author: '"PayPal Service" <notice@pay-help.example>', subject: "Your account is limited" });
  assert.equal(request.reply_to, "claims@elsewhere.example");
  assert.match(request.authentication_results, /dmarc=fail/);
  assert.equal(request.text, "Please confirm at www.paypal.com");
  assert.deepEqual(request.links, [{ href: "https://pay-help.example/login", text: "www.paypal.com" }]);
  assert.ok(!JSON.stringify(request).includes("ATTACHMENT TEXT"));
});

test("falls back to the HTML body as text, and to headers when the message header is missing", () => {
  const htmlOnly = { headers: { from: ["a@b.example"], subject: ["Hi"] }, parts: [{ contentType: "text/html", body: "<p>Hello&nbsp;there</p>" }] };
  const request = toCheckRequest(htmlOnly);
  assert.equal(request.text, "Hello there");
  assert.equal(request.from_header, "a@b.example");
  assert.equal(request.reply_to, null);
  assert.deepEqual(bodies(undefined), { text: "", html: "" });
});

test("only web links are kept", () => {
  assert.deepEqual(htmlLinks('<a href="mailto:a@b.c">m</a><a href=\'http://x.example\'>x</a>'), [{ href: "http://x.example", text: "x" }]);
});

test("server address must be https, except on this computer", () => {
  assert.equal(cleanServerUrl("https://qalaa.example.org/path"), "https://qalaa.example.org");
  assert.equal(cleanServerUrl("http://localhost:8080"), "http://localhost:8080");
  assert.throws(() => cleanServerUrl("http://qalaa.example.org"));
});

test("badges and both languages", () => {
  assert.equal(badgeFor("known_malicious").text, "!");
  assert.equal(badgeFor("no_known_threat").text, "");
  assert.deepEqual(Object.keys(dictionaries.ar).sort(), Object.keys(dictionaries.en).sort());
  const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url)));
  assert.deepEqual(manifest.permissions, ["messagesRead", "storage"]);
  assert.equal(manifest.host_permissions, undefined, "server access is asked for only when the person sets it");
});
