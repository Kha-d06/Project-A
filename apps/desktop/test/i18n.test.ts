import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { FINDINGS_AR } from "../src/renderer/i18n";

describe("Arabic findings", () => {
  it("cover every rule the engine can emit", () => {
    const source = ["scanner.ts", "rules.ts", "formats.ts", "analysis.ts"].map((f) => readFileSync(new URL(`../src/engine/${f}`, import.meta.url), "utf8")).join("\n");
    const rules = new Set([...source.matchAll(/rule: "([a-z0-9_]+)"|finding\(\s*"\w+",\s*"([a-z0-9_]+)"/g)].map((m) => (m[1] ?? m[2])!));
    expect(rules.size).toBeGreaterThan(60);
    for (const rule of rules) expect(FINDINGS_AR, rule).toHaveProperty(rule);
  });
});
