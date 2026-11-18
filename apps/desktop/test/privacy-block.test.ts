import { describe, expect, it } from "vitest";

import {
  linuxBlockScript,
  parseWindowsConsent,
  privacyBlockSupported,
  windowsRegQueryArgs,
  windowsRegSetArgs,
} from "../src/engine/privacy-block";

describe("capability", () => {
  it("supports Linux and Windows, not macOS", () => {
    expect(privacyBlockSupported("linux")).toBe(true);
    expect(privacyBlockSupported("win32")).toBe(true);
    expect(privacyBlockSupported("darwin")).toBe(false);
  });
});

describe("Linux block script", () => {
  it("chmods device nodes to 0 to block, 0660 to allow", () => {
    const block = linuxBlockScript(["/dev/video0", "/dev/snd/pcmC0D0c"], true);
    expect(block).toContain("chmod 0 '/dev/video0'");
    expect(block).toContain("chmod 0 '/dev/snd/pcmC0D0c'");
    expect(linuxBlockScript(["/dev/video0"], false)).toContain("chmod 0660 '/dev/video0'");
  });

  it("refuses paths outside /dev", () => {
    expect(() => linuxBlockScript(["/etc/passwd"], true)).toThrow();
    expect(() => linuxBlockScript(["/dev/video0; rm -rf /"], true)).toThrow();
  });
});

describe("Windows consent registry", () => {
  it("builds Deny/Allow set args for the right capability key", () => {
    const deny = windowsRegSetArgs("camera", false).join(" ");
    expect(deny).toContain("webcam");
    expect(deny).toContain("Deny");
    expect(windowsRegSetArgs("microphone", true).join(" ")).toContain("Allow");
    expect(windowsRegSetArgs("microphone", true).join(" ")).toContain("microphone");
    expect(windowsRegQueryArgs("camera").join(" ")).toContain("webcam");
  });

  it("parses the query output", () => {
    expect(parseWindowsConsent("    Value    REG_SZ    Deny")).toBe("blocked");
    expect(parseWindowsConsent("    Value    REG_SZ    Allow")).toBe("allowed");
    expect(parseWindowsConsent("no value here")).toBe("unknown");
  });
});
