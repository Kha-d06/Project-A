/**
 * Every pattern that runs on content a stranger controls (clipboard text,
 * scripts and documents being scanned) stays fast on hostile input (P1-6).
 * Inputs are long runs built from each pattern's own words and from the
 * characters its classes accept, the shapes that trigger catastrophic
 * backtracking.
 */
import { describe, expect, it } from "vitest";

import { ENV_LINE, ENV_SECRET_NAME, PATTERNS, classifySecret } from "../src/engine/clipboard";
import { SCRIPT_PATTERNS } from "../src/engine/rules";

const BUDGET_MS = 100;
const LENGTH = 64 * 1024;

function* hostile(source: string): Generator<string> {
  const words = new Set([...(source.match(/[A-Za-z]{2,}/g) ?? []), "a", "A", "1", "-", ".", " ", "_", "=", "/", "+", "XSECRET", "eyJ", "AKIA", "ghp_", "\n"]);
  for (const w of [...words].slice(0, 60)) {
    yield w.repeat(Math.ceil(LENGTH / w.length)).slice(0, LENGTH) + "!";
    yield `${w} `.repeat(Math.ceil(LENGTH / (w.length + 1))).slice(0, LENGTH) + "!";
  }
}

const cases: [string, RegExp][] = [
  ...PATTERNS.map(([kind, re]): [string, RegExp] => [`clipboard:${kind}`, re]),
  ["clipboard:env_line", ENV_LINE],
  ["clipboard:env_name", ENV_SECRET_NAME],
  ...SCRIPT_PATTERNS.map(({ rule, pattern }): [string, RegExp] => [`script:${rule}`, pattern]),
];

describe("regular expressions on hostile input", () => {
  it.each(cases)("%s stays under the time budget", (_name, re) => {
    for (const text of hostile(re.source)) {
      const started = performance.now();
      re.test(text);
      const elapsed = performance.now() - started;
      expect(elapsed, `${re.source.slice(0, 60)} on ${JSON.stringify(text.slice(0, 16))}`).toBeLessThan(BUDGET_MS);
    }
  });

  it("the whole clipboard classifier stays fast, and still finds .env secrets", () => {
    for (const text of ["XSECRET".repeat(9_000), "A".repeat(64_000), `${"API_KEY".repeat(2_000)}=x`]) {
      const started = performance.now();
      classifySecret(text);
      expect(performance.now() - started).toBeLessThan(BUDGET_MS);
    }
    expect(classifySecret("DATABASE_PASSWORD=hunter2hunter2")).toBe("env_secret");
    expect(classifySecret("export STRIPE_API_KEY=sk_test_abcdefgh")).toBe("env_secret");
    expect(classifySecret("  GITHUB_TOKEN = abcdefgh12345")).toBe("env_secret");
    expect(classifySecret("DEBUG=true")).toBeNull();
    expect(classifySecret("PATH=/usr/local/bin:/usr/bin")).toBeNull();
  });
});
