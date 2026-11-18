import { describe, expect, it } from "vitest";

import { detectPlatform, linuxFamily } from "./platform";

describe("detectPlatform", () => {
  it.each([
    ["windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"],
    ["mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"],
    ["linux", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"],
    ["linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"],
    ["android", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36"],
    ["ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"],
    ["chromeos", "Mozilla/5.0 (X11; CrOS x86_64 15917.71.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"],
    ["unknown", "curl/8.5.0"],
  ])("%s", (platform, ua) => {
    expect(detectPlatform(ua)).toBe(platform);
  });

  it("prefers the browser's platform hint, and spots iPads that look like Macs", () => {
    expect(detectPlatform("Mozilla/5.0 (X11; Linux x86_64)", "Windows")).toBe("windows");
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", null, 5)).toBe("ios");
  });

  it("guesses the Linux package family when the browser names the distribution", () => {
    expect(linuxFamily("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0)")).toBe("deb");
    expect(linuxFamily("Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:132.0)")).toBe("rpm");
    expect(linuxFamily("Mozilla/5.0 (X11; Linux x86_64)")).toBeNull();
  });
});
