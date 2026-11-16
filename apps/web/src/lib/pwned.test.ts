import { describe, expect, it, vi } from "vitest";

import { ARTICLES } from "@/content/awareness";

import { countInRange, pwnedCount, sha1Hex } from "./pwned";

describe("Pwned Passwords", () => {
  it("hashes with SHA-1 in upper case", async () => {
    expect(await sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  });

  it("sends only the first five characters and matches the rest locally", async () => {
    const fetcher = vi.fn(async () => new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n"));
    expect(await pwnedCount("password", fetcher as unknown as typeof fetch)).toBe(9659365);
    const [url, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.pwnedpasswords.com/range/5BAA6");
    expect(JSON.stringify(init)).not.toContain("password");
  });

  it("returns zero for padding entries and unknown suffixes", () => {
    expect(countInRange("ABC:0\nDEF:12", "XYZ")).toBe(0);
    expect(countInRange("ABC:0\nDEF:12", "DEF")).toBe(12);
  });
});

describe("awareness guides", () => {
  it("have matching English and Arabic content", () => {
    const slugs = new Set<string>();
    for (const article of ARTICLES) {
      expect(slugs.has(article.slug)).toBe(false);
      slugs.add(article.slug);
      expect(article.ar.signs.length).toBe(article.en.signs.length);
      expect(article.ar.steps.length).toBe(article.en.steps.length);
      expect(article.ar.title).toMatch(/[؀-ۿ]/);
      expect(`${article.en.body} ${article.en.steps.join(" ")}`.toLowerCase()).not.toMatch(/\bit is safe\b/);
    }
  });
});
