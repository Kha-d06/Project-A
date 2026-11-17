import { describe, expect, it } from "vitest";

import { linuxPackages, parseAndroid, parseManifest } from "./downloads";

describe("download manifests", () => {
  it("reads electron-builder manifests", () => {
    const yaml = "version: 0.2.0\nfiles:\n  - url: SENTINEL-Desktop-0.2.0-x86_64.AppImage\n    sha512: abc==\n    size: 1\npath: SENTINEL-Desktop-0.2.0-x86_64.AppImage\n";
    expect(parseManifest(yaml)).toEqual({ version: "0.2.0", file: "SENTINEL-Desktop-0.2.0-x86_64.AppImage", sha512: "abc==" });
  });

  it("refuses links that leave the downloads folder", () => {
    expect(parseManifest("version: 1.0.0\nfiles:\n  - url: https://evil.example/x.exe\n")).toBeNull();
    expect(parseManifest("version: 1.0.0\nfiles:\n  - url: ../../etc/passwd\n")).toBeNull();
    expect(parseManifest("nothing here")).toBeNull();
  });

  it("validates the Android manifest", () => {
    expect(parseAndroid({ version: "0.2.0", file: "SENTINEL-0.2.0.apk", sha256: "a".repeat(64) })?.file).toBe("SENTINEL-0.2.0.apk");
    expect(parseAndroid({ version: "0.2.0", file: "x.exe", sha256: "a".repeat(64) })).toBeNull();
    expect(parseAndroid(null)).toBeNull();
  });

  it("names the Linux packages", () => {
    expect(linuxPackages("0.2.0")).toEqual({ deb: "SENTINEL-Desktop-0.2.0-amd64.deb", rpm: "SENTINEL-Desktop-0.2.0-x86_64.rpm" });
  });
});
