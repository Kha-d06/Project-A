import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { analyzeLocally, compilePack, verdict } from "../src/lib/analysis.js";
import { arabicBrandIn, editDistance, impersonatedBrand, unicodeLabel } from "../src/lib/lookalike.js";

// The real address rules the server publishes in the rule pack.
const URL_RULES = JSON.parse(readFileSync(new URL("../../../services/api/app/rules/url_rules.json", import.meta.url), "utf8"));
const brands = Object.fromEntries(Object.entries(URL_RULES.brands).map(([k, v]) => [k, { name: v.name, domains: v.domains }]));
const PACK = compilePack({ version: "t", rules: [], brands, shorteners: URL_RULES.shorteners, url_rules: URL_RULES });

const email = (fields) => ({ from_header: "", reply_to: null, subject: "", authentication_results: "", text: "", links: [], ...fields });
const categories = (fields, lang) => analyzeLocally(email(fields), PACK, lang).map((f) => `${f.severity}:${f.category}`);

test("look-alike domains: typos, digits, other alphabets, Arabic spellings", () => {
  assert.deepEqual(impersonatedBrand("paypa1.com", PACK), { brand: "paypal", kind: "typo" });
  assert.deepEqual(impersonatedBrand("xn--pple-43d.com", PACK), { brand: "apple", kind: "homograph" });
  assert.equal(impersonatedBrand("paypal.com", PACK), null);
  assert.equal(impersonatedBrand("example.org", PACK), null);
  assert.equal(impersonatedBrand("xn--mgbaper7i66b.com", PACK)?.brand, "alrajhi"); // الراجحی.com (Persian yeh)
  assert.equal(unicodeLabel("xn--mgbaper7iyb"), "الراجحي");
  assert.equal(editDistance("alrajhi", "alrajih"), 1);
  assert.equal(arabicBrandIn("مصرف الراجحي - خدمة العملاء", URL_RULES), "alrajhi");
  assert.equal(arabicBrandIn("أحمد محمد", URL_RULES), null);
});

test("English CEO-fraud: a title on a personal account asking for a transfer", () => {
  const found = categories({ from_header: '"Omar Saleh, CEO" <omar.saleh.office@gmail.com>', text: "I need you to process a wire transfer today. Keep it confidential, I'm in a meeting." });
  assert.ok(found.includes("medium:personal_account"));
  assert.ok(found.includes("high:bec"));
  const result = verdict(analyzeLocally(email({ from_header: '"Omar Saleh, CEO" <omar.saleh.office@gmail.com>', text: "process a wire transfer today" }), PACK));
  assert.equal(result.risk, "suspicious");
  assert.deepEqual(result.assessment, { confirmed: false, sender: true, message: true });
});

test("Arabic impersonation: a bank name in the display name, new bank details requested", () => {
  const found = categories({ from_header: '"مصرف الراجحي" <alerts@rajhi-secure.co>', text: "عميلنا العزيز، يرجى تحويل المبلغ إلى رقم الآيبان الجديد" }, "ar");
  assert.ok(found.includes("high:brand_impersonation"));
  assert.ok(found.includes("high:bec"));
});

test("Arabic finance title on a personal account asking for a verification code", () => {
  const found = categories({ from_header: '"المدير المالي" <cfo.office2026@outlook.com>', text: "أرسل لي رمز التحقق الذي وصلك الآن" }, "ar");
  assert.ok(found.includes("medium:personal_account"));
  assert.ok(found.includes("high:bec"));
});

test("look-alike sender and look-alike link domains", () => {
  assert.ok(categories({ from_header: "PayPal <service@paypa1.com>" }).includes("high:lookalike_sender"));
  assert.ok(categories({ from_header: "billing@shop.example", links: [{ href: "https://paypa1.com/login", text: "Sign in" }] }).includes("high:lookalike_link"));
});

test("a reply-to on another domain plus a payment request is BEC", () => {
  const found = categories({ from_header: "Accounts <accounts@supplier.example>", reply_to: "accounts@supplier-payments.example", text: "Please note our new bank account for this invoice." });
  assert.ok(found.includes("medium:reply_to_mismatch"));
  assert.ok(found.includes("high:bec"));
});

test("false positives: genuine invoices, personal mail, and the brand's own domain stay quiet", () => {
  // An invoice from the supplier's own domain: the request is noted, nothing more.
  const invoice = analyzeLocally(email({ from_header: "Accounts <accounts@supplier.example>", text: "Please find attached invoice 1234. Payment by wire transfer within 30 days." }), PACK);
  assert.deepEqual(invoice.map((f) => `${f.severity}:${f.category}`), ["low:sensitive_request"]);
  assert.equal(verdict(invoice).risk, "no_known_threat");
  // A friend on Gmail, no title, no request.
  assert.deepEqual(categories({ from_header: "Sara <sara.k@gmail.com>", text: "Dinner on Thursday?" }), []);
  // PayPal from paypal.com.
  assert.deepEqual(categories({ from_header: "PayPal <service@paypal.com>", text: "Your receipt" }), []);
  // Arabic everyday wording that only resembles the patterns.
  assert.deepEqual(categories({ from_header: "فريق التسويق <news@shop.example>", text: "يرجى تحويل الملف إلى PDF قبل الاجتماع. بيان صحفي مرفق." }, "ar"), []);
});
