import { describe, expect, it } from "vitest";

import { HASH_PREFIX_LENGTH, lookupHash } from "../src/engine/server";

const LISTED = `abcdef${"1".repeat(58)}`;
const NEIGHBOUR = `abcdef${"2".repeat(58)}`;

function server(candidates: { sha256: string; source: string }[]) {
  const asked: string[] = [];
  const fetcher = (async (url: string) => {
    asked.push(url);
    return new Response(JSON.stringify({ prefix: "abcdef", candidates, truncated: false, sources: [] }));
  }) as typeof fetch;
  return { asked, fetcher };
}

describe("k-anonymous hash lookup", () => {
  it("sends only a short prefix and matches on this computer", async () => {
    const { asked, fetcher } = server([{ sha256: NEIGHBOUR, source: "MalwareBazaar" }, { sha256: LISTED, source: "ThreatFox" }]);
    expect(await lookupHash("https://q.example/", LISTED.toUpperCase(), fetcher)).toBe("ThreatFox");
    expect(asked).toEqual([`https://q.example/api/v1/intelligence/hash-prefix/${LISTED.slice(0, HASH_PREFIX_LENGTH)}`]);
    expect(asked[0]).not.toContain(LISTED.slice(0, HASH_PREFIX_LENGTH + 1));
  });

  it("a neighbour sharing the prefix is not a match", async () => {
    const { fetcher } = server([{ sha256: NEIGHBOUR, source: "MalwareBazaar" }]);
    expect(await lookupHash("https://q.example", LISTED, fetcher)).toBeNull();
  });

  it("refuses anything that is not a SHA-256", async () => {
    const { asked, fetcher } = server([]);
    await expect(lookupHash("https://q.example", "abc", fetcher)).rejects.toThrow();
    expect(asked).toEqual([]);
  });
});
