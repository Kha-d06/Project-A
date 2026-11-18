/**
 * The saved list of devices seen on the home network. It stays on this computer
 * (never synced), so a new device can be pointed out and a known one marked as
 * trusted. Keyed by MAC where we have one, otherwise by IP.
 */
import { readFile, rename, writeFile } from "node:fs/promises";

import type { Device } from "./types";

export interface KnownDevice {
  key: string;
  mac: string | null;
  lastIp: string;
  name: string | null;
  vendor: string | null;
  trusted: boolean;
  firstSeen: string;
  lastSeen: string;
}

export type Inventory = Record<string, KnownDevice>;

/** Stable key for a device: its MAC when known, else "ip:<address>". */
export function deviceKey(device: { mac: string | null; ip: string }): string {
  return device.mac ? `mac:${device.mac}` : `ip:${device.ip}`;
}

export async function loadInventory(file: string): Promise<Inventory> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as Inventory;
  } catch {
    return {};
  }
}

export async function saveInventory(file: string, inventory: Inventory): Promise<void> {
  await writeFile(`${file}.tmp`, JSON.stringify(inventory, null, 2));
  await rename(`${file}.tmp`, file);
}

/**
 * Fold a fresh scan into the saved inventory. Returns the updated inventory and
 * the keys of devices never seen before (for the new-device alert). The router
 * and this computer itself are never counted as "new".
 */
export function reconcile(inventory: Inventory, devices: Device[], now = new Date().toISOString()): { inventory: Inventory; newKeys: string[] } {
  const next: Inventory = { ...inventory };
  const newKeys: string[] = [];
  for (const device of devices) {
    const key = deviceKey(device);
    const existing = next[key];
    if (existing) {
      next[key] = { ...existing, lastIp: device.ip, lastSeen: now, name: device.hostname ?? existing.name, vendor: device.vendor ?? existing.vendor };
    } else {
      next[key] = { key, mac: device.mac, lastIp: device.ip, name: device.hostname, vendor: device.vendor, trusted: false, firstSeen: now, lastSeen: now };
      if (device.role === "device") newKeys.push(key);
    }
  }
  return { inventory: next, newKeys };
}

/** Apply saved "trusted" flags and first-seen dates onto a scan's device list. */
export function annotate(devices: Device[], inventory: Inventory): Device[] {
  return devices.map((device) => {
    const known = inventory[deviceKey(device)];
    return known ? { ...device, trusted: known.trusted, firstSeen: known.firstSeen } : device;
  });
}

export function setTrusted(inventory: Inventory, key: string, trusted: boolean): Inventory {
  const device = inventory[key];
  return device ? { ...inventory, [key]: { ...device, trusted } } : inventory;
}
