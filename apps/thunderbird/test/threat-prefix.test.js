import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PrefixList, createLinkChecker, hostCandidates, normalizeUrl, sha256Hex } from "../src/lib/threat-prefix.js";

const vectors = JSON.parse(readFileSync(new URL("../../../services/api/tests/fixtures/url-vectors.json", import.meta.url), "utf8")).vectors;

/** A stored prefix list holding these values' prefixes plus filler. */
async function listOf(values, sources = ["URLhaus"]) {
  const prefixes = new Set(["00000001", "7fffffff", "fffffff0", "12345678"]);
  for (const v of values) prefixes.add((await sha256Hex(v)).slice(0, 8));
  const bytes = [...prefixes].sort().flatMap((hex) => hex.match(/../g).map((b) => parseInt(b, 16)));
  return { prefixes: btoa(String.fromCharCode(...bytes)), fetchedAt: Date.now(), sources };
}

test("normalises addresses exactly as the server's threat store (shared vectors)", () => {
  for (const v of vectors) assert.equal(normalizeUrl(v.url)?.normalized, v.normalized, v.url);
  assert.equal(normalizeUrl("https://User:pw@EXAMPLE.org./a?b=1#frag").normalized, "https://example.org/a?b=1");
  assert.equal(normalizeUrl("https://example.org/a?b=1").bare, "https://example.org/a");
  assert.equal(normalizeUrl("mailto:x@example.org"), null);
  assert.equal(normalizeUrl("javascript:alert(1)"), null);
  assert.deepEqual(hostCandidates("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"]);
  assert.deepEqual(hostCandidates("203.0.113.9"), ["203.0.113.9"]);
});

test("a listed link is found, and the request carries prefixes only", async () => {
  const listed = "http://phish.example.net/login?id=7";
  const digest = await sha256Hex(listed);
  const sent = [];
  const check = createLinkChecker({
    getList: async () => listOf([listed]),
    fetchHashes: async (prefixes) => {
      sent.push(JSON.stringify(prefixes));
      return [{ digest, kind: "url", source: "urlhaus", source_name: "URLhaus", threat: "phishing" }];
    },
  });
  const result = await check([listed, "https://example.org/"]);
  assert.equal(result.checked, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, "critical");
  assert.equal(result.findings[0].link, "phish.example.net");
  assert.equal(sent.length, 1);
  const prefixes = JSON.parse(sent[0]);
  assert.ok(prefixes.includes(digest.slice(0, 8)));
  assert.ok(prefixes.length > 1, "decoys are added");
  assert.ok(prefixes.every((p) => /^[0-9a-f]{8}$/.test(p)));
  assert.ok(!sent[0].includes("phish") && !sent[0].includes("example"), "no address in the request");
  // Cached: the same link again doesn't ask the server.
  await check([listed]);
  assert.equal(sent.length, 1);
});

test("an unlisted link sends nothing; a prefix collision with a different full hash isn't a match", async () => {
  const page = "https://shop.example.com/cart";
  const prefix = (await sha256Hex(page)).slice(0, 8);
  let calls = 0;
  const quiet = createLinkChecker({ getList: async () => listOf([]), fetchHashes: async () => (calls++, []) });
  assert.deepEqual((await quiet([page])).findings, []);
  assert.equal(calls, 0);
  const colliding = createLinkChecker({
    getList: async () => listOf([page]),
    fetchHashes: async () => [{ digest: `${prefix}${"0".repeat(56)}`, kind: "url", source: "urlhaus", source_name: "URLhaus", threat: null }],
  });
  assert.deepEqual((await colliding([page])).findings, []);
});

test("a listed domain is found from a subdomain link; community reports are high, not critical", async () => {
  const digest = await sha256Hex("evil.example");
  const check = createLinkChecker({
    getList: async () => listOf(["evil.example"]),
    fetchHashes: async () => [{ digest, kind: "host", source: "community", source_name: "Qalaa community", threat: null }],
  });
  const result = await check(["https://pay.evil.example/x"], "ar");
  assert.equal(result.findings[0].severity, "high");
  assert.match(result.findings[0].title, /قلعة/);
});

test("fails safe: no list, a stale list, or an unreachable server are reported, never as clean", async () => {
  const none = createLinkChecker({ getList: async () => null, fetchHashes: async () => [] });
  const r1 = await none(["https://example.org/"]);
  assert.equal(r1.checked, false);
  assert.equal(r1.limitations.length, 1);

  const stale = await listOf([]);
  stale.fetchedAt = Date.now() - 3 * 86_400_000;
  const r2 = await createLinkChecker({ getList: async () => stale, fetchHashes: async () => [] })(["https://example.org/"]);
  assert.equal(r2.checked, false);

  const listed = "https://bad.example/";
  const failing = createLinkChecker({
    getList: async () => listOf([listed]),
    fetchHashes: async () => {
      throw new Error(`network error for ${listed}`);
    },
  });
  const r3 = await failing([listed]);
  assert.equal(r3.checked, false);
  assert.ok(!JSON.stringify(r3).includes("bad.example"), "the link isn't echoed in the result's messages");
});

test("the prefix list searches and draws decoys from itself", async () => {
  const stored = await listOf(["a", "b", "c"]);
  const list = new PrefixList(stored.prefixes);
  assert.ok(list.has((await sha256Hex("a")).slice(0, 8)));
  assert.ok(!list.has("abcdef01"));
  const decoys = list.decoys(3, new Set(["00000001"]));
  assert.ok(decoys.length >= 1 && decoys.every((d) => list.has(d) && d !== "00000001"));
});

test("links are taken in full for local hashing (nothing is sent)", async () => {
  const { linksIn } = await import("../src/lib/analysis.js");
  const links = linksIn({ links: [{ href: "https://pay.example/x?ref=1", text: "Pay" }], text: "or visit http://site.example/a?b=2, thanks" });
  assert.deepEqual(links, ["https://pay.example/x?ref=1", "http://site.example/a?b=2"]);
});
