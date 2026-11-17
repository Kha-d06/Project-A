import { describe, expect, it } from "vitest";

import { feedUrl, installKind, isNewer, versionFromManifest } from "../src/engine/updates";

describe("updates", () => {
  it("comes from the person's own server", () => {
    expect(feedUrl("https://sentinel.example.org/")).toBe("https://sentinel.example.org/downloads/desktop");
  });

  it("knows which installs can update themselves", () => {
    expect(installKind("linux", { APPIMAGE: "/home/me/SENTINEL.AppImage" }, true)).toBe("appimage");
    expect(installKind("linux", {}, true)).toBe("deb-rpm");
    expect(installKind("win32", {}, true)).toBe("installer");
    expect(installKind("darwin", {}, false)).toBe("development");
  });

  it("compares versions numerically", () => {
    expect(isNewer("0.10.0", "0.9.3")).toBe(true);
    expect(isNewer("v0.2.1", "0.2.0")).toBe(true);
    expect(isNewer("0.2.0", "0.2.0")).toBe(false);
    expect(isNewer("0.1.9", "0.2.0")).toBe(false);
  });

  it("reads the version from latest.yml", () => {
    expect(versionFromManifest("version: 0.3.1\nfiles:\n  - url: x.AppImage\n")).toBe("0.3.1");
    expect(versionFromManifest("garbage")).toBeNull();
  });
});
