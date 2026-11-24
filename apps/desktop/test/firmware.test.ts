import { describe, expect, it } from "vitest";

import { firmwareChecks, lastAptUpdate, lastHotfix, lastMacUpdate, lastRpmInstall, macSecureBoot, secureBootFromEfivar, secureBootFromMokutil, secureBootFromRegistry, tpmFromSysfs, tpmFromTpmtool } from "../src/engine/firmware";

describe("Secure Boot", () => {
  it("reads each system's own source", () => {
    expect(secureBootFromEfivar(Uint8Array.from([6, 0, 0, 0, 1]))).toBe("on");
    expect(secureBootFromEfivar(Uint8Array.from([6, 0, 0, 0, 0]))).toBe("off");
    expect(secureBootFromEfivar(null)).toBe("unknown");
    expect(secureBootFromMokutil("SecureBoot enabled\n")).toBe("on");
    expect(secureBootFromMokutil("SecureBoot disabled\nPlatform is in Setup Mode\n")).toBe("off");
    expect(secureBootFromMokutil("EFI variables are not supported on this system\n")).toBe("unknown");
    expect(secureBootFromRegistry("\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\n    UEFISecureBootEnabled    REG_DWORD    0x1\n")).toBe("on");
    expect(secureBootFromRegistry("    UEFISecureBootEnabled    REG_DWORD    0x0\n")).toBe("off");
    expect(secureBootFromRegistry("ERROR: The system was unable to find the specified registry key or value.")).toBe("unknown");
    expect(macSecureBoot("94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy\t%02\n")).toBe("on");
    expect(macSecureBoot("94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy\t%01\n")).toBe("medium");
    expect(macSecureBoot("nvram: Error getting variable")).toBe("unknown");
  });
});

describe("TPM", () => {
  it("tells 2.0 from 1.2 from none from can't-tell", () => {
    expect(tpmFromSysfs("2\n", true)).toBe("tpm2");
    expect(tpmFromSysfs("1\n", true)).toBe("tpm1");
    expect(tpmFromSysfs(null, true)).toBe("none");
    expect(tpmFromSysfs(null, false)).toBe("unknown");
    expect(tpmFromTpmtool("-TPM Present: true\n-TPM Version: 2.0\n-TPM Manufacturer ID: INTC\n")).toBe("tpm2");
    expect(tpmFromTpmtool("-TPM Present: false\n")).toBe("none");
    expect(tpmFromTpmtool("")).toBe("unknown");
  });
});

describe("patch age", () => {
  it("finds the last install on each system", () => {
    const apt = `Start-Date: 2026-10-01  09:00:00\nCommandline: apt upgrade\nUpgrade: libc6:amd64 (2.39-1, 2.39-2)\nEnd-Date: 2026-10-01  09:01:00\n\nStart-Date: 2026-11-20  10:12:01\nCommandline: apt install curl\nInstall: curl:amd64 (8.5.0)\nEnd-Date: 2026-11-20  10:12:30\n\nStart-Date: 2026-11-22  08:00:00\nCommandline: apt remove foo\nRemove: foo:amd64 (1.0)\n`;
    expect(lastAptUpdate(apt)?.toISOString().slice(0, 10)).toBe("2026-11-20");
    expect(lastAptUpdate("")).toBeNull();
    expect(lastRpmInstall("1795000000\n1790000000\n")?.getTime()).toBe(1_795_000_000_000);
    expect(lastHotfix('[{"InstalledOn":{"value":"/Date(1795000000000)/","DateTime":"x"}},{"InstalledOn":"2026-01-01T00:00:00"},{"InstalledOn":null}]')?.getTime()).toBe(1_795_000_000_000);
    expect(lastHotfix("oops")).toBeNull();
    const mac = JSON.stringify({ SPInstallHistoryDataType: [
      { _name: "macOS 26.1", install_date: "2026-11-10T08:00:00Z", package_source: "package_source_apple" },
      { _name: "Some App", install_date: "2026-11-23T08:00:00Z", package_source: "package_source_other" },
    ] });
    expect(lastMacUpdate(mac)?.toISOString()).toBe("2026-11-10T08:00:00.000Z");
  });
});

describe("checks", () => {
  const now = new Date("2026-11-24T12:00:00Z");
  it("pass, warn, fail and unknown, with fixes only where needed", () => {
    const good = firmwareChecks({ secureBoot: "on", tpm: "tpm2", lastUpdate: new Date("2026-11-20T00:00:00Z") }, "linux", now);
    expect(good.map((c) => [c.id, c.status, c.fix])).toEqual([
      ["secure-boot", "pass", null],
      ["tpm", "pass", null],
      ["patch-age", "pass", null],
    ]);
    expect(good[2]?.detail).toBe("Last updated 4 days ago.");

    const bad = firmwareChecks({ secureBoot: "off", tpm: "none", lastUpdate: new Date("2026-05-01T00:00:00Z") }, "win32", now);
    expect(bad.map((c) => c.status)).toEqual(["fail", "fail", "fail"]);
    expect(bad[0]?.fix).toMatch(/UEFI Firmware Settings/);
    expect(bad[1]?.fix).toMatch(/tpm\.msc/);

    const legacy = firmwareChecks({ secureBoot: "legacy-bios", tpm: "tpm1", lastUpdate: new Date("2026-09-01T00:00:00Z") }, "linux", now);
    expect(legacy.map((c) => c.status)).toEqual(["warn", "warn", "warn"]);
    expect(legacy[0]?.detail).toMatch(/legacy BIOS/);

    const mac = firmwareChecks({ secureBoot: "unknown", tpm: "secure-enclave", lastUpdate: null }, "darwin", now);
    expect(mac.map((c) => c.status)).toEqual(["unknown", "pass", "unknown"]);
    expect(mac[1]?.title).toBe("Secure Enclave protects keys");
  });
});
