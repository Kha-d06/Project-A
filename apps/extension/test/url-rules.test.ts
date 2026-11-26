import vectorFile from "../../../services/api/tests/fixtures/url-vectors.json";
import { analyzeAddress, arabicFold, editDistance, parseAddress, unicodeLabel, validRules, BUNDLED_RULES } from "../src/lib/url-rules";

interface Vector {
  url: string;
  normalized: string;
  registrableDomain: string;
  findings: { severity: string; category: string; title: string }[];
}

// The same vectors the server's tests use (services/api/tests/test_url_vectors.py).
const vectors = (vectorFile as { vectors: Vector[] }).vectors;

describe("local address checks agree with the server", () => {
  it.each(vectors.map((v) => [v.url, v] as const))("%s", (_, vector) => {
    const url = parseAddress(vector.url);
    expect(url).not.toBeNull();
    expect(url!.normalized).toBe(vector.normalized);
    expect(url!.registrableDomain).toBe(vector.registrableDomain);
    expect(analyzeAddress(url!).map(({ severity, category, title }) => ({ severity, category, title }))).toEqual(vector.findings);
  });
});

describe("helpers", () => {
  it("decodes punycode labels", () => {
    expect(unicodeLabel("xn--mgbaper7iyb")).toBe("الراجحي");
    expect(unicodeLabel("xn--pple-43d")).toBe("аpple");
    expect(unicodeLabel("example")).toBe("example");
    expect(unicodeLabel("xn--!!")).toBe("xn--!!");
  });

  it("counts an adjacent swap as one edit", () => {
    expect(editDistance("paypal", "paypla")).toBe(1);
    expect(editDistance("paypal", "paypal")).toBe(0);
    expect(editDistance("", "abc")).toBe(3);
  });

  it("folds Arabic letter variants like the server", () => {
    expect(arabicFold("إبشـر")).toBe("ابشر");
    expect(arabicFold("٠١٢٣")).toBe("0123");
  });

  it("accepts only a complete rules file", () => {
    expect(validRules(BUNDLED_RULES)).toBe(true);
    expect(validRules({ version: "x" })).toBe(false);
    expect(validRules(null)).toBe(false);
  });
});
