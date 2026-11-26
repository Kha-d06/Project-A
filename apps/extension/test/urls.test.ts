import { normalizeHostEntry } from "../src/lib/settings";
import { checkableUrl, isLocalHost, matchesHostList } from "../src/lib/urls";
import { VERDICTS, shouldInterrupt } from "../src/lib/verdicts";

describe("which addresses are checked", () => {
  it.each(["localhost", "printer", "nas.local", "192.168.1.10", "10.0.0.1", "172.20.1.1", "127.0.0.1", "[::1]", "router.lan"])(
    "skips %s",
    (host) => expect(isLocalHost(host.replace(/[[\]]/g, ""))).toBe(true),
  );

  it.each(["example.com", "8.8.8.8", "172.32.0.1"])("checks %s", (host) => expect(isLocalHost(host)).toBe(false));

  it("only checks web addresses and strips fragments and credentials", () => {
    expect(checkableUrl("chrome://settings")).toBeNull();
    expect(checkableUrl("file:///etc/passwd")).toBeNull();
    expect(checkableUrl("javascript:alert(1)")).toBeNull();
    expect(checkableUrl("https://user:pw@example.com/a?b=1#c")?.toString()).toBe("https://example.com/a?b=1");
  });

  it("matches list entries and their subdomains only", () => {
    expect(matchesHostList("login.example.com", ["example.com"])).toBe(true);
    expect(matchesHostList("example.com.evil.net", ["example.com"])).toBe(false);
    expect(matchesHostList("notexample.com", ["example.com"])).toBe(false);
  });

  it.each([
    ["Example.com", "example.com"],
    ["https://example.com/path", "example.com"],
    ["*.example.com", "example.com"],
    ["not a domain", null],
    ["localhost", null],
  ])("normalizes list entry %s", (input, expected) => expect(normalizeHostEntry(input)).toBe(expected));
});

describe("verdict wording", () => {
  it("never calls anything safe", () => {
    for (const presentation of Object.values(VERDICTS)) {
      expect(`${presentation.label} ${presentation.detail}`.toLowerCase()).not.toMatch(/\bsafe\b(?!ty)/);
    }
  });

  it("interrupts only meaningful verdicts", () => {
    expect(shouldInterrupt("dangerous", false)).toBe(true);
    expect(shouldInterrupt("blocked_by_you", false)).toBe(true);
    expect(shouldInterrupt("suspicious", true)).toBe(true);
    expect(shouldInterrupt("suspicious", false)).toBe(false);
    for (const verdict of ["caution", "no_known_threat", "unavailable", "skipped"] as const) {
      expect(shouldInterrupt(verdict, true)).toBe(false);
    }
  });
});
