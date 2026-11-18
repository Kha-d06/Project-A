import { describe, expect, it } from "vitest";

import { cfaApplyScript, cfaStateFromValue, cfaStatus, onlySupportedOnWindows, parseMpPreference } from "../src/engine/cfa";

describe("CFA state mapping", () => {
  it("maps Defender's values", () => {
    expect(cfaStateFromValue(1)).toBe("on");
    expect(cfaStateFromValue("Enabled")).toBe("on");
    expect(cfaStateFromValue(2)).toBe("audit");
    expect(cfaStateFromValue(0)).toBe("off");
    expect(cfaStateFromValue(null)).toBe("unknown");
  });
});

describe("Get-MpPreference parsing", () => {
  it("reads state, folders and allowed apps", () => {
    const json = JSON.stringify({
      EnableControlledFolderAccess: 1,
      ControlledFolderAccessProtectedFolders: ["C:\\Users\\a\\Documents", "D:\\Photos"],
      ControlledFolderAccessAllowedApplications: "C:\\Tools\\backup.exe",
    });
    const status = parseMpPreference(json);
    expect(status.state).toBe("on");
    expect(status.folders).toHaveLength(2);
    expect(status.allowedApps).toEqual(["C:\\Tools\\backup.exe"]); // a lone string becomes a one-item list
  });

  it("is resilient to empty or bad output", () => {
    expect(parseMpPreference("").state).toBe("unknown");
    expect(parseMpPreference("{}").folders).toEqual([]);
  });
});

describe("apply scripts", () => {
  it("builds the Defender cmdlets and quotes paths safely", () => {
    expect(cfaApplyScript("enable")).toBe("Set-MpPreference -EnableControlledFolderAccess Enabled");
    expect(cfaApplyScript("audit")).toContain("AuditMode");
    expect(cfaApplyScript("add-folder", "C:\\My Docs")).toBe("Add-MpPreference -ControlledFolderAccessProtectedFolders 'C:\\My Docs'");
    expect(cfaApplyScript("allow-app", "C:\\it's\\app.exe")).toContain("'C:\\it''s\\app.exe'"); // doubled quote
    expect(() => cfaApplyScript("add-folder")).toThrow();
  });
});

describe("capability", () => {
  it("is Windows-only", () => {
    expect(onlySupportedOnWindows("win32")).toBe(true);
    expect(onlySupportedOnWindows("linux")).toBe(false);
  });

  it("reports unsupported off Windows without running anything", async () => {
    const status = await cfaStatus("linux", async () => {
      throw new Error("should not run");
    });
    expect(status.supported).toBe(false);
  });

  it("parses a live read on Windows (mocked runner)", async () => {
    const status = await cfaStatus("win32", async () => JSON.stringify({ EnableControlledFolderAccess: 2, ControlledFolderAccessProtectedFolders: [] }));
    expect(status.state).toBe("audit");
  });
});
