import { describe, expect, it } from "vitest";

import { WORDS, generatePassphrase, generatePassword, passphraseBits, passwordBits } from "./password";

describe("password generator", () => {
  it("honours length and character types", () => {
    for (let i = 0; i < 50; i += 1) {
      const value = generatePassword({ length: 16, upper: true, digits: true, symbols: true });
      expect(value).toHaveLength(16);
      expect(value).toMatch(/[a-z]/);
      expect(value).toMatch(/[A-Z]/);
      expect(value).toMatch(/[0-9]/);
      expect(value).toMatch(/[^A-Za-z0-9]/);
    }
    expect(generatePassword({ length: 20, upper: false, digits: false, symbols: false })).toMatch(/^[a-z]{20}$/);
  });

  it("builds passphrases from the word list and reports strength", () => {
    const phrase = generatePassphrase(5);
    expect(phrase.split("-")).toHaveLength(5);
    expect(phrase.split("-").every((word) => WORDS.includes(word))).toBe(true);
    expect(new Set(WORDS).size).toBe(WORDS.length);
    expect(passphraseBits(6)).toBeGreaterThanOrEqual(45);
    expect(passwordBits({ length: 16, upper: true, digits: true, symbols: true })).toBeGreaterThan(90);
  });
});
