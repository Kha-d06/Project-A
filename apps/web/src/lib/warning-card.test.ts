import { describe, expect, it } from "vitest";

import { defang } from "./warning-card";

describe("defang", () => {
  it("makes links impossible to tap", () => {
    expect(defang("https://paypa1-login.example.com/verify")).toBe("hxxps://paypa1-login[.]example[.]com/verify");
    expect(defang("HTTP://a.b")).toBe("hxxp://a[.]b");
  });
});
