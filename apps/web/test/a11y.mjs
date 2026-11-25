/**
 * Accessibility audit with axe-core (WCAG 2.1 A and AA rules) on key pages, in
 * English and Arabic and in light and dark themes, against a running site:
 *   SITE=http://localhost:3000 node test/a11y.mjs
 * Fails on serious or critical violations.
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const axeSource = await readFile(require.resolve("axe-core/axe.min.js"), "utf8");
const site = process.env.SITE ?? "http://localhost:3000";

const PUBLIC = ["/", "/download", "/scan", "/scan?type=message", "/learn", "/learn/parcel-delivery-fees", "/trends", "/help/scammed", "/tools/password", "/privacy", "/sign-in", "/report", "/intelligence"];
const SIGNED_IN = ["/dashboard", "/dashboard/scan", "/dashboard/settings", "/dashboard/groups", "/dashboard/breach", "/dashboard/history", "/dashboard/devices", "/dashboard/passwords", "/dashboard/vpn", "/dashboard/privacy", "/dashboard/assessment"];

const browser = await chromium.launch();
const failures = [];
let checked = 0;

async function audit(context, path, label) {
  const page = await context.newPage();
  await page.goto(`${site}${path}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(300);
  await page.addScriptTag({ content: axeSource });
  const result = await page.evaluate(async () =>
    axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] }, resultTypes: ["violations"] }),
  );
  checked += 1;
  for (const violation of result.violations) {
    if (violation.impact !== "serious" && violation.impact !== "critical") continue;
    failures.push(`${label} ${path}: ${violation.id} (${violation.impact}) ${violation.help}\n    ${violation.nodes.slice(0, 3).map((n) => n.target.join(" ")).join("\n    ")}`);
  }
  await page.close();
}

// One account for every pass: sign-up is rate-limited per address, and other CI steps sign up too.
let sessionCookies = null;
for (const locale of ["en", "ar"]) {
  for (const theme of ["light", "dark"]) {
    const context = await browser.newContext({ colorScheme: theme, viewport: { width: 1280, height: 900 } });
    await context.addCookies([{ name: "sentinel-locale", value: locale, url: site }]);
    for (const path of PUBLIC) await audit(context, path, `[${locale}/${theme}]`);
    // Signed-in pages: sign up on the first pass, then reuse that session.
    if (sessionCookies) {
      await context.addCookies(sessionCookies.filter((cookie) => cookie.name !== "sentinel-locale"));
    } else {
      const page = await context.newPage();
      await page.goto(`${site}/sign-up`);
      await page.fill("input[type=email]", `a11y-${Date.now()}@example.com`);
      await page.fill("input[type=password]", "a-strong-password-123");
      await page.click("button[type=submit]");
      await page.waitForURL(/dashboard/);
      await page.close();
      sessionCookies = await context.cookies();
    }
    for (const path of SIGNED_IN) await audit(context, path, `[${locale}/${theme}]`);
    await context.close();
  }
}
await browser.close();
console.log(`Audited ${checked} page views.`);
if (failures.length) {
  console.log(`${failures.length} serious or critical violation(s):\n${failures.join("\n")}`);
  process.exit(1);
}
console.log("No serious or critical accessibility violations.");
