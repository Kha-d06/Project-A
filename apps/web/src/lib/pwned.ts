/**
 * Pwned Passwords range query (k-anonymity). Only the first five hex characters
 * of the password's SHA-1 leave the browser; the service answers with every
 * suffix that shares them (padded with decoys), and the match happens here.
 */
export async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function countInRange(body: string, suffix: string): number {
  for (const line of body.split("\n")) {
    const [candidate, count] = line.trim().split(":");
    if (candidate?.toUpperCase() === suffix) return Number(count) || 0;
  }
  return 0;
}

export async function pwnedCount(password: string, fetcher: typeof fetch = fetch): Promise<number> {
  const hash = await sha1Hex(password);
  const response = await fetcher(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { "Add-Padding": "true" },
    credentials: "omit",
    referrerPolicy: "no-referrer",
  });
  if (!response.ok) throw new Error(`Pwned Passwords answered ${response.status}`);
  return countInRange(await response.text(), hash.slice(5));
}
