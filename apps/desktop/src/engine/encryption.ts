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
import { readFile } from "node:fs/promises";

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
  fstype?: string | null;
  mountpoint?: string | null;
  mountpoints?: (string | null)[];
  children?: LsblkDevice[];
}

/**
 * `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS`: is "/" under a "crypt" device
 * (LUKS, also LVM or btrfs on LUKS)? Swap partitions outside dm-crypt leak
 * memory contents (and hibernation images) to disk, so an encrypted root with
 * plain swap is only partial. zram swap lives in memory and is fine.
 * `swapFiles` are swap files from /proc/swaps: they share the root's fate.
 */
export function parseLsblk(json: string, swapFiles: string[] = []): EncryptionStatus {
  let devices: LsblkDevice[];
  try {
    devices = (JSON.parse(json) as { blockdevices: LsblkDevice[] }).blockdevices ?? [];
  } catch {
    return { state: "unknown", detail: null, source: "lsblk" };
  }
  const mounts = (d: LsblkDevice) => [...(d.mountpoints ?? []), d.mountpoint ?? null].filter(Boolean) as string[];
  // Set inside the walk (an object, so the type isn't narrowed to null).
  const found: { root: boolean | null } = { root: null };
  const plainSwap: string[] = [];
  const walk = (list: LsblkDevice[], crypt: boolean) => {
    for (const device of list) {
      const inCrypt = crypt || device.type === "crypt";
      const m = mounts(device);
      if (m.includes("/") && found.root === null) found.root = inCrypt;
      const isSwap = m.includes("[SWAP]") || device.fstype === "swap";
      if (isSwap && !inCrypt && !device.name.startsWith("zram") && (device.children ?? []).length === 0) plainSwap.push(device.name);
      walk(device.children ?? [], inCrypt);
    }
  };
  walk(devices, false);
  const root = found.root;
  if (root === null) return { state: "unknown", detail: "Could not find the system disk.", source: "lsblk" };
  if (!root) return { state: "off", detail: "The system disk is not encrypted.", source: "lsblk" };
  if (plainSwap.length) {
    return {
      state: "partial",
      detail: `The system disk is encrypted (LUKS), but swap on ${plainSwap.join(", ")} is not: memory written to swap, and a hibernation image, can be read from the disk.`,
      source: "lsblk",
    };
  }
  const files = swapFiles.length ? " Swap files on it are encrypted too." : "";
  return { state: "on", detail: `The system disk is encrypted (LUKS).${files}`, source: "lsblk" };
}

/** /proc/swaps: swap files (not partitions, not zram). */
export function parseProcSwaps(text: string): string[] {
  return text
    .split("\n")
    .slice(1)
    .map((l) => l.trim().split(/\s+/))
    .filter((cols) => cols[1] === "file" && cols[0])
    .map((cols) => cols[0]!);
}

/** `findmnt -no FSTYPE,SOURCE /`, for roots lsblk can't see (ZFS datasets). */
export function parseFindmntRoot(stdout: string): { fstype: string; source: string } | null {
  const [fstype, source] = stdout.trim().split(/\s+/);
  return fstype && source ? { fstype, source } : null;
}

/** `zfs get -H -o value encryption <dataset>`: "off" or a cipher such as "aes-256-gcm". */
export function parseZfsEncryption(stdout: string, dataset: string): EncryptionStatus {
  const value = stdout.trim().split("\n")[0]?.trim() ?? "";
  if (!value || value === "-") return { state: "unknown", detail: null, source: "zfs" };
  return value === "off"
    ? { state: "off", detail: `The system dataset ${dataset} is not encrypted.`, source: "zfs" }
    : { state: "on", detail: `The system dataset ${dataset} uses ZFS encryption (${value}).`, source: "zfs" };
}

/** eCryptfs home folders: the system disk may be plain while home is encrypted. */
export function ecryptfsHomes(procMounts: string): string[] {
  return procMounts
    .split("\n")
    .map((l) => l.split(" "))
    .filter((cols) => cols[2] === "ecryptfs" && cols[1])
    .map((cols) => cols[1]!.replace(/\\040/g, " "));
}

export function parseFdesetup(stdout: string, appleSilicon = false): EncryptionStatus {
  if (/Decryption in progress/i.test(stdout)) return { state: "partial", detail: "FileVault is being turned off: the disk is being decrypted.", source: "fdesetup" };
  if (/Encryption in progress/i.test(stdout)) return { state: "partial", detail: "FileVault is still encrypting the disk.", source: "fdesetup" };
  if (/will be enabled after the next restart/i.test(stdout)) return { state: "partial", detail: "FileVault turns on at the next restart. Restart to finish.", source: "fdesetup" };
  if (/FileVault is On/i.test(stdout)) return { state: "on", detail: "FileVault is on.", source: "fdesetup" };
  if (/FileVault is Off/i.test(stdout)) {
    // Apple silicon always encrypts the disk in hardware, but without FileVault
    // the key isn't tied to your password: anyone who starts the Mac can read it.
    const detail = appleSilicon
      ? "FileVault is off. The disk is hardware-encrypted, but without FileVault anyone who starts this Mac can read it."
      : "FileVault is off.";
    return { state: "off", detail, source: "fdesetup" };
  }
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

async function linuxEncryption(): Promise<EncryptionStatus> {
  const swaps = parseProcSwaps(await readFile("/proc/swaps", "utf8").catch(() => ""));
  let status = parseLsblk(await run("lsblk", ["-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"]).catch(() => "{}"), swaps);
  if (status.state === "unknown") {
    const root = parseFindmntRoot(await run("findmnt", ["-no", "FSTYPE,SOURCE", "/"]).catch(() => ""));
    if (root?.fstype === "zfs") status = parseZfsEncryption(await run("zfs", ["get", "-H", "-o", "value", "encryption", root.source]).catch(() => ""), root.source);
  }
  if (status.state === "off") {
    const homes = ecryptfsHomes(await readFile("/proc/mounts", "utf8").catch(() => ""));
    if (homes.length) return { state: "partial", detail: `The system disk is not encrypted; ${homes.join(", ")} is (eCryptfs).`, source: "ecryptfs" };
  }
  return status;
}

export async function diskEncryption(platform = process.platform): Promise<EncryptionStatus> {
  try {
    if (platform === "linux") return await linuxEncryption();
    if (platform === "darwin") return parseFdesetup(await run("fdesetup", ["status"]), process.arch === "arm64");
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
