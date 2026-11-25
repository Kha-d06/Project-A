import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";

import { analyzeLocally, authResults, bareUrl, compilePack, linkReputationFindings, safePatternSource, linksToCheck, parseAddress, siteOf, verdict } from "../src/lib/analysis.js";

const PACK = compilePack({
  version: "test",
  rules: [
    {
      category: "account_threat",
      severity: "medium",
      title: "Threatens that an account will be suspended or closed",
      explanation: "x",
      title_ar: "تهدّد بإيقاف حساب أو إغلاقه",
      explanation_ar: "y",
      patterns: ["\\b(account|card)\\b.{0,50}\\b(suspend(ed)?|lock(ed)?|clos(ed|ure))\\b", "(broken"],
    },
  ],
  brands: { paypal: { name: "PayPal", domains: ["paypal.com", "paypal.me"] } },
  shorteners: ["bit.ly"],
});

const email = (fields) => ({ from_header: "", reply_to: null, subject: "", authentication_results: "", text: "", links: [], ...fields });
const titles = (fields, lang) => analyzeLocally(email(fields), PACK, lang).map((f) => f.title);

test("helpers", () => {
  assert.equal(siteOf("a.b.example.co.uk"), "example.co.uk");
  assert.equal(siteOf("mail.shop.example"), "shop.example");
  assert.equal(siteOf("login.paypal.com"), "paypal.com");
  assert.deepEqual(parseAddress('"PayPal Service" <Notice@Pay-Help.example>'), { name: "PayPal Service", address: "notice@pay-help.example", domain: "pay-help.example" });
  assert.deepEqual(authResults("mx; spf=pass; dkim=FAIL; dmarc=fail; dmarc=pass"), { spf: "pass", dkim: "fail", dmarc: "fail" });
  assert.equal(bareUrl("https://u:p@a.example:8443/x?token=1#f"), "https://a.example:8443/x");
  assert.equal(bareUrl("mailto:a@b.c"), null);
});

test("only bare links leave the device, at most 50", () => {
  const urls = linksToCheck({
    links: [{ href: "https://pay-help.example/login?email=me@example.org", text: "x" }],
    text: "Also see https://pay-help.example/login?again=1 and http://other.example/a.",
  });
  assert.deepEqual(urls, ["https://pay-help.example/login", "http://other.example/a."]);
  assert.ok(!urls.join(" ").includes("me@example.org"));
  const many = { links: Array.from({ length: 80 }, (_, i) => ({ href: `https://s${i}.example/`, text: "" })), text: "" };
  assert.equal(linksToCheck(many).length, 50);
});

test("sender and header checks", () => {
  assert.ok(titles({ from_header: "a@bank.example", authentication_results: "dmarc=fail" }).includes("The sender's domain says this email is not from it"));
  assert.ok(titles({ from_header: "a@bank.example", authentication_results: "spf=softfail dkim=none" }).includes("This email could not prove where it came from"));
  assert.ok(titles({ from_header: "PayPal Service <n@pay-help.example>" }).includes("The sender claims to be PayPal"));
  assert.deepEqual(titles({ from_header: "PayPal <service@mail.paypal.com>" }), []);
  assert.ok(titles({ from_header: '"support@bank.com" <x@cheap.example>' }).includes("The sender's name shows a different address"));
  assert.ok(titles({ from_header: "a@shop.example", reply_to: "b@elsewhere.example" }).includes("Replies would go to a different domain"));
  assert.deepEqual(titles({ from_header: "a@shop.example", reply_to: "help@mail.shop.example" }), []);
});

test("link text that names another site, and wording rules in both languages", () => {
  const mismatch = { from_header: "a@mybank.com", links: [{ text: "www.mybank.com/login", href: "https://login-check.example/x" }] };
  assert.ok(titles(mismatch).includes("A link shows one address but opens another"));
  assert.deepEqual(titles({ from_header: "a@mybank.com", links: [{ text: "mybank.com", href: "https://www.mybank.com/offers" }] }), []);
  const threat = { from_header: "a@shop.example", subject: "Notice", text: "Your account will be suspended today" };
  const [found] = analyzeLocally(email(threat), PACK, "en");
  assert.equal(found.title, "Threatens that an account will be suspended or closed");
  assert.match(found.excerpt, /account will be suspended/);
  assert.ok(titles(threat, "ar").includes("تهدّد بإيقاف حساب أو إغلاقه"));
  // Without a rule pack the other checks still run.
  assert.deepEqual(analyzeLocally(email(threat), null), []);
});

test("verdict uses the server's thresholds and merges link reputation", () => {
  const listed = linkReputationFindings([{ url: "https://evil.example/", host: "evil.example", findings: [{ severity: "critical", title: "Listed", explanation: "" }] }]);
  assert.equal(verdict(listed).risk, "known_malicious");
  assert.equal(listed[0].link, "https://evil.example/");
  assert.equal(verdict([{ severity: "medium", category: "c", title: "t", explanation: "" }]).risk, "suspicious");
  assert.equal(verdict([]).risk, "no_known_threat");
  assert.match(verdict([], "ar").summary, /لم تُرصد/);
  const sorted = verdict([{ severity: "low", category: "a", title: "a", explanation: "" }, { severity: "high", category: "b", title: "b", explanation: "" }]);
  assert.equal(sorted.findings[0].severity, "high");
});

test("unsafe pattern shapes from a rule pack are refused, every pattern the server sends is accepted", () => {
  const serverPatterns = JSON.parse(readFileSync(new URL("./fixtures/server-patterns.json", import.meta.url), "utf8"));
  assert.ok(serverPatterns.length > 30);
  for (const source of serverPatterns) assert.equal(safePatternSource(source), true, source);
  for (const bad of ["(a+)+$", "(\\w+\\.)*com", "(?:[a-z0-9-]+\\.)+(?:com|net)", "((ab)*)+", "(x+){2,}", "(a)\\1", "(?<n>a)\\k<n>", "a".repeat(501), 42]) {
    assert.equal(safePatternSource(bad), false, String(bad).slice(0, 40));
  }
  for (const ok of ["\\b(pay|send)\\b.{0,50}\\b(bitcoin|usdt)\\b", "[+*(]+", "(will be )?(cut|stopped)", "a{2,8}", "(?:ab){1,8}c+"]) {
    assert.equal(safePatternSource(ok), true, ok);
  }
  // An unsafe pattern in a pack is dropped, the rest still work.
  const pack = compilePack({ version: 1, rules: [{ category: "x", severity: "high", patterns: ["(a+)+$", "bitcoin"], title_en: "t", title_ar: "t", explanation_en: "e", explanation_ar: "e" }] });
  assert.equal(pack.rules[0].compiled.length, 1);
  // And a hostile message doesn't hang the client.
  const started = performance.now();
  for (const rule of compilePack({ version: 1, rules: [{ category: "x", severity: "high", patterns: serverPatterns, title_en: "t", title_ar: "t", explanation_en: "e", explanation_ar: "e" }] }).rules[0].compiled) {
    rule.test("a.".repeat(10_000) + "!");
  }
  assert.ok(performance.now() - started < 2000);
});
