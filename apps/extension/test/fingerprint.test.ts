import { describe, expect, it } from "vitest";

import { installNoise, isBypassed, originSeed } from "../src/lib/fingerprint";

describe("fingerprint noise seeds", () => {
  it("are stable for a site within a session and differ between sites and sessions", async () => {
    const session = new Uint8Array(32).fill(7);
    const other = new Uint8Array(32).fill(8);
    const a = await originSeed(session, "https://a.example");
    expect(await originSeed(session, "https://a.example")).toBe(a);
    expect(await originSeed(session, "https://b.example")).not.toBe(a);
    expect(await originSeed(other, "https://a.example")).not.toBe(a);
    expect(Number.isInteger(a) && a >= 0 && a < 2 ** 32).toBe(true);
  });

  it("skips sites the person turned it off for", () => {
    expect(isBypassed("www.bank.example", ["bank.example"])).toBe(true);
    expect(isBypassed("bank.example", ["bank.example"])).toBe(true);
    expect(isBypassed("notbank.example", ["bank.example"])).toBe(false);
  });

  it("is self-contained so it can be injected as a function", () => {
    // executeScript serialises the function's source: it must not use imports or outer variables.
    const source = installNoise.toString();
    expect(source).not.toMatch(/\b__name\b|\bimport\(|require\(/);
    expect(() => new Function(`return (${source})`)()).not.toThrow();
  });
});
