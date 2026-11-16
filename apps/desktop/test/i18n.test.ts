import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { FINDINGS_AR } from "../src/renderer/i18n";

describe("Arabic findings", () => {
  it("cover every rule the engine can emit", () => {
    const source = ["scanner.ts", "rules.ts"].map((f) => readFileSync(new URL(`../src/engine/${f}`, import.meta.url), "utf8")).join("\n");
    const rules = new Set([...source.matchAll(/rule: "([a-z_]+)"/g)].map((m) => m[1]!));
    for (const rule of rules) expect(FINDINGS_AR, rule).toHaveProperty(rule);
  });
});
