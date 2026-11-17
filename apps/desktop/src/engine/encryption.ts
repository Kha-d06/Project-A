/**
 * Is the system disk encrypted? If a laptop is lost or stolen, an encrypted disk
 * keeps its files unreadable.
 *
 * - Linux: the root filesystem sits on a dm-crypt (LUKS) device (`lsblk`).
 * - macOS: FileVault (`fdesetup status`).
 * - Windows: BitLocker protection of C:, read through the Shell (works without
 *   administrator rights, unlike manage-bde).
 *
 * Anything we cannot read is "unknown", never "on".
 */
import { execFile } from "node:child_process";

export type EncryptionState = "on" | "off" | "partial" | "unknown";

export interface EncryptionStatus {
  state: EncryptionState;
  detail: string | null;
  source: string | null;
}

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 15_000, windowsHide: true }, (error, stdout) => {
      if (error && !stdout) reject(error);
      else resolve(String(stdout));
    });
  });
}

interface LsblkDevice {
  name: string;
  type: string;
  mountpoint?: string | null;
  mountpoints?: (string | null)[];
  children?: LsblkDevice[];
}

/** `lsblk -J -o NAME,TYPE,MOUNTPOINTS`: is "/" under a "crypt" device? */
export function parseLsblk(json: string): EncryptionStatus {
  let devices: LsblkDevice[];
  try {
    devices = (JSON.parse(json) as { blockdevices: LsblkDevice[] }).blockdevices ?? [];
  } catch {
    return { state: "unknown", detail: null, source: "lsblk" };
  }
  const mounts = (d: LsblkDevice) => [...(d.mountpoints ?? []), d.mountpoint ?? null].filter(Boolean) as string[];
  const find = (list: LsblkDevice[], crypt: boolean): boolean | null => {
    for (const device of list) {
      const inCrypt = crypt || device.type === "crypt";
      if (mounts(device).includes("/")) return inCrypt;
      const below = find(device.children ?? [], inCrypt);
      if (below !== null) return below;
    }
    return null;
  };
  const root = find(devices, false);
  if (root === null) return { state: "unknown", detail: "Could not find the system disk.", source: "lsblk" };
  return root
    ? { state: "on", detail: "The system disk is encrypted (LUKS).", source: "lsblk" }
    : { state: "off", detail: "The system disk is not encrypted.", source: "lsblk" };
}

export function parseFdesetup(stdout: string): EncryptionStatus {
  if (/FileVault is On/i.test(stdout)) return { state: "on", detail: "FileVault is on.", source: "fdesetup" };
  if (/Encryption in progress/i.test(stdout)) return { state: "partial", detail: "FileVault is still encrypting the disk.", source: "fdesetup" };
  if (/FileVault is Off/i.test(stdout)) return { state: "off", detail: "FileVault is off.", source: "fdesetup" };
  return { state: "unknown", detail: null, source: "fdesetup" };
}

/** System.Volume.BitLockerProtection: 1 or 6 = on, 2 = off, 3 = encrypting, 5 = suspended. */
export function parseBitLocker(stdout: string): EncryptionStatus {
  const value = Number(stdout.trim());
  if (value === 1 || value === 6) return { state: "on", detail: "BitLocker protects drive C:.", source: "BitLocker" };
  if (value === 2) return { state: "off", detail: "BitLocker is off for drive C:.", source: "BitLocker" };
  if (value === 3) return { state: "partial", detail: "BitLocker is still encrypting drive C:.", source: "BitLocker" };
  if (value === 5) return { state: "partial", detail: "BitLocker protection is suspended on drive C:.", source: "BitLocker" };
  return { state: "unknown", detail: null, source: "BitLocker" };
}

export async function diskEncryption(platform = process.platform): Promise<EncryptionStatus> {
  try {
    if (platform === "linux") return parseLsblk(await run("lsblk", ["-J", "-o", "NAME,TYPE,MOUNTPOINTS"]));
    if (platform === "darwin") return parseFdesetup(await run("fdesetup", ["status"]));
    if (platform === "win32") {
      return parseBitLocker(
        await run("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')",
        ]),
      );
    }
  } catch {
    // fall through
  }
  return { state: "unknown", detail: null, source: null };
}
