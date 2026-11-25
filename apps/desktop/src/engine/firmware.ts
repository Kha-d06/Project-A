/**
 * Firmware and OS patch posture: UEFI Secure Boot, a TPM 2.0 (or Apple's Secure
 * Enclave), and how long ago the operating system last installed updates.
 *
 * Read-only, and only from sources a normal user can read, so no password
 * prompt: efivars and sysfs on Linux, the registry and tpmtool on Windows,
 * nvram and system_profiler on macOS. Anything that can't be read is reported
 * as unknown, never guessed. Each check says how to fix it.
 */
import { execFile } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";

import type { CheckStatus, PostureCheck } from "./posture";

export type Tri = "on" | "off" | "unknown";

// --- Secure Boot -------------------------------------------------------------------

/** Linux efivar `SecureBoot-8be4df61-…`: 4 attribute bytes, then 1 data byte. */
export function secureBootFromEfivar(bytes: Uint8Array | null): Tri {
  if (!bytes || bytes.length < 5) return "unknown";
  return bytes[4] === 1 ? "on" : "off";
}

/** `mokutil --sb-state`. */
export function secureBootFromMokutil(stdout: string): Tri {
  if (/SecureBoot enabled/i.test(stdout)) return "on";
  if (/SecureBoot disabled/i.test(stdout)) return "off";
  return "unknown";
}

/** `reg query HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State /v UEFISecureBootEnabled`. */
export function secureBootFromRegistry(stdout: string): Tri {
  const value = /UEFISecureBootEnabled\s+REG_DWORD\s+0x([0-9a-f]+)/i.exec(stdout)?.[1];
  if (value === undefined) return "unknown";
  return parseInt(value, 16) === 1 ? "on" : "off";
}

/**
 * Intel Macs with a T2 chip: `nvram 94b73556-…:AppleSecureBootPolicy` is %02
 * (full), %01 (medium) or %00 (none). Apple silicon always boots securely
 * unless reduced in Recovery, which a normal user can't read; reported unknown.
 */
export function macSecureBoot(nvramStdout: string): Tri | "medium" {
  const policy = /AppleSecureBootPolicy\s+%0?([0-2])/i.exec(nvramStdout)?.[1];
  if (policy === "2") return "on";
  if (policy === "1") return "medium";
  if (policy === "0") return "off";
  return "unknown";
}

// --- TPM ---------------------------------------------------------------------------

export type TpmState = "tpm2" | "tpm1" | "none" | "unknown";

/**
 * Linux `/sys/class/tpm/tpm0/tpm_version_major`. Kernels before 5.6 have tpm0
 * without that file: a TPM 1.2 then shows "TCG version: 1.2" in device/caps,
 * and anything else is present but of unknown version (never "no TPM").
 */
export function tpmFromSysfs(versionMajor: string | null, tpmClassExists: boolean, tpm0Exists = false, caps: string | null = null): TpmState {
  if (versionMajor === null) {
    if (tpm0Exists) return caps && /TCG version:\s*1\.2/i.test(caps) ? "tpm1" : "unknown";
    return tpmClassExists ? "none" : "unknown";
  }
  const major = versionMajor.trim();
  return major === "2" ? "tpm2" : major === "1" ? "tpm1" : "unknown";
}

/** Windows `tpmtool getdeviceinformation`. */
export function tpmFromTpmtool(stdout: string): TpmState {
  if (/TPM Present:\s*false/i.test(stdout)) return "none";
  const version = /TPM Version:\s*([0-9.]+)/i.exec(stdout)?.[1];
  if (!version) return "unknown";
  return version.startsWith("2") ? "tpm2" : version.startsWith("1") ? "tpm1" : "unknown";
}

// --- Patch age ---------------------------------------------------------------------

/** Debian/Ubuntu `/var/log/apt/history.log`: the last `Start-Date:` of an upgrade or install. */
export function lastAptUpdate(historyLog: string): Date | null {
  let latest: Date | null = null;
  for (const block of historyLog.split(/\n\s*\n/)) {
    const start = /^Start-Date:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/m.exec(block);
    if (!start || !/^(Upgrade|Install):/m.test(block)) continue;
    const when = new Date(`${start[1]}T${start[2]}`);
    if (!Number.isNaN(when.getTime()) && (!latest || when > latest)) latest = when;
  }
  return latest;
}

/** `rpm -qa --last --queryformat '%{INSTALLTIME}\n'`: install times in seconds, newest first or not. */
export function lastRpmInstall(stdout: string): Date | null {
  const times = stdout.split(/\s+/).map(Number).filter((n) => Number.isFinite(n) && n > 0);
  return times.length ? new Date(Math.max(...times) * 1000) : null;
}

/** Windows `Get-HotFix | Select InstalledOn | ConvertTo-Json`: dates like "/Date(1795000000000)/" or ISO. */
export function lastHotfix(json: string): Date | null {
  let rows: unknown;
  try {
    rows = JSON.parse(json || "[]");
  } catch {
    return null;
  }
  let latest: Date | null = null;
  for (const row of (Array.isArray(rows) ? rows : [rows]) as { InstalledOn?: unknown }[]) {
    const raw = row?.InstalledOn;
    const value = typeof raw === "object" && raw && "value" in raw ? (raw as { value: unknown }).value : raw;
    if (typeof value !== "string") continue;
    const ms = /\/Date\((\d+)\)\//.exec(value)?.[1];
    const when = ms ? new Date(Number(ms)) : new Date(value);
    if (!Number.isNaN(when.getTime()) && (!latest || when > latest)) latest = when;
  }
  return latest;
}

/** macOS `system_profiler SPInstallHistoryDataType -json`: Apple installs only. */
export function lastMacUpdate(json: string): Date | null {
  try {
    const items = (JSON.parse(json) as { SPInstallHistoryDataType?: { install_date?: string; package_source?: string }[] }).SPInstallHistoryDataType ?? [];
    let latest: Date | null = null;
    for (const item of items) {
      if (item.package_source !== "package_source_apple" || !item.install_date) continue;
      const when = new Date(item.install_date);
      if (!Number.isNaN(when.getTime()) && (!latest || when > latest)) latest = when;
    }
    return latest;
  } catch {
    return null;
  }
}

// --- Checks ------------------------------------------------------------------------

export interface FirmwareFacts {
  secureBoot: Tri | "medium" | "legacy-bios";
  tpm: TpmState | "secure-enclave";
  lastUpdate: Date | null;
}

const FIX = {
  secureBoot: {
    linux: "Turn on Secure Boot in your firmware (UEFI) settings. Some Linux setups also need a signed kernel or a MOK key enrolled.",
    win32: "Turn on Secure Boot in your firmware (UEFI) settings: restart into Settings → System → Recovery → Advanced startup → UEFI Firmware Settings.",
    darwin: "Restart into Recovery, open Startup Security Utility, and choose Full Security.",
  },
  tpm: {
    linux: "Turn on the TPM in your firmware settings (often called fTPM, PTT or Security Chip).",
    win32: "Turn on the TPM in your firmware settings (fTPM, PTT or Security Chip), then check with tpm.msc.",
    darwin: "",
  },
  updates: {
    linux: "Install updates with your distribution's software updater (for example: sudo apt upgrade).",
    win32: "Settings → Windows Update → Check for updates.",
    darwin: "System Settings → General → Software Update.",
  },
} as const;

type Os = "linux" | "win32" | "darwin";

export function firmwareChecks(f: FirmwareFacts, platform: Os, now: Date = new Date()): PostureCheck[] {
  const sb: CheckStatus =
    f.secureBoot === "on" ? "pass" : f.secureBoot === "medium" ? "warn" : f.secureBoot === "off" ? "fail" : f.secureBoot === "legacy-bios" ? "warn" : "unknown";
  const sbDetail =
    f.secureBoot === "legacy-bios"
      ? "This computer starts in legacy BIOS mode, which has no Secure Boot."
      : f.secureBoot === "medium"
        ? "Medium Security: older or unsigned macOS versions can start."
        : null;
  const tpm: CheckStatus = f.tpm === "tpm2" || f.tpm === "secure-enclave" ? "pass" : f.tpm === "tpm1" ? "warn" : f.tpm === "none" ? "fail" : "unknown";
  const days = f.lastUpdate ? Math.floor((now.getTime() - f.lastUpdate.getTime()) / 86_400_000) : null;
  const patch: CheckStatus = days === null ? "unknown" : days <= 30 ? "pass" : days <= 90 ? "warn" : "fail";
  return [
    { id: "secure-boot", title: "Secure Boot is on", status: sb, detail: sbDetail, fix: sb === "pass" ? null : FIX.secureBoot[platform], weight: 10 },
    {
      id: "tpm",
      title: platform === "darwin" ? "Secure Enclave protects keys" : "TPM 2.0 is available",
      status: tpm,
      detail: f.tpm === "tpm1" ? "Only TPM 1.2 was found; TPM 2.0 is needed for modern disk encryption and Windows 11." : null,
      fix: tpm === "pass" || platform === "darwin" ? null : FIX.tpm[platform],
      weight: 8,
    },
    {
      id: "patch-age",
      title: "System updates installed in the last 30 days",
      status: patch,
      detail: days === null ? null : days === 0 ? "Updated today." : `Last updated ${days} day${days === 1 ? "" : "s"} ago.`,
      fix: patch === "pass" ? null : FIX.updates[platform],
      weight: 10,
    },
  ];
}

// --- Collection --------------------------------------------------------------------

const EFI_SECURE_BOOT = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

function run(command: string, args: string[], timeout = 20_000): Promise<string> {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (_error, stdout) => resolve(String(stdout ?? "")));
  });
}

const exists = (path: string) => stat(path).then(() => true).catch(() => false);

async function linuxFacts(): Promise<FirmwareFacts> {
  const efi = await exists("/sys/firmware/efi");
  let secureBoot: FirmwareFacts["secureBoot"] = efi ? secureBootFromEfivar(await readFile(EFI_SECURE_BOOT).catch(() => null)) : "legacy-bios";
  if (secureBoot === "unknown") secureBoot = secureBootFromMokutil(await run("mokutil", ["--sb-state"]));
  const tpmClass = await readdir("/sys/class/tpm").then(() => true).catch(() => false);
  const tpm = tpmFromSysfs(
    await readFile("/sys/class/tpm/tpm0/tpm_version_major", "utf8").catch(() => null),
    tpmClass,
    await exists("/sys/class/tpm/tpm0"),
    await readFile("/sys/class/tpm/tpm0/device/caps", "utf8").catch(() => null),
  );
  let lastUpdate = lastAptUpdate(await readFile("/var/log/apt/history.log", "utf8").catch(() => ""));
  if (!lastUpdate) lastUpdate = lastRpmInstall(await run("rpm", ["-qa", "--queryformat", "%{INSTALLTIME}\n"]));
  return { secureBoot, tpm, lastUpdate };
}

async function windowsFacts(): Promise<FirmwareFacts> {
  const [sb, tpm, hotfix] = await Promise.all([
    run("reg", ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "/v", "UEFISecureBootEnabled"]),
    run("tpmtool", ["getdeviceinformation"]),
    run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-HotFix | Select-Object InstalledOn | ConvertTo-Json -Compress"], 60_000),
  ]);
  return { secureBoot: secureBootFromRegistry(sb), tpm: tpmFromTpmtool(tpm), lastUpdate: lastHotfix(hotfix) };
}

async function macFacts(): Promise<FirmwareFacts> {
  const [nvram, chip, history] = await Promise.all([
    run("nvram", ["94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy"]),
    run("sysctl", ["-n", "machdep.cpu.brand_string"]),
    run("system_profiler", ["SPInstallHistoryDataType", "-json"], 60_000),
  ]);
  const appleSilicon = /^Apple/i.test(chip.trim());
  const t2 = nvram.includes("AppleSecureBootPolicy");
  return {
    secureBoot: macSecureBoot(nvram),
    tpm: appleSilicon || t2 ? "secure-enclave" : "unknown",
    lastUpdate: lastMacUpdate(history),
  };
}

export async function firmwarePosture(platform: NodeJS.Platform = process.platform): Promise<PostureCheck[]> {
  if (platform === "linux") return firmwareChecks(await linuxFacts(), "linux");
  if (platform === "win32") return firmwareChecks(await windowsFacts(), "win32");
  if (platform === "darwin") return firmwareChecks(await macFacts(), "darwin");
  return [];
}
