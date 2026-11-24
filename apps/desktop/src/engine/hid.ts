/**
 * BadUSB warning: tell the person when a new keyboard appears.
 *
 * Some USB sticks and cables pretend to be a keyboard and type commands the
 * moment they are plugged in. Qalaa can't tell a real keyboard from a fake one,
 * so it never blocks input devices: it says a new keyboard was connected, and
 * if the person didn't just plug one in, they should unplug it.
 *
 * The first look records the keyboards already there. Sources are read-only:
 * `/proc/bus/input/devices` (Linux), PnP keyboard devices (Windows) and
 * `ioreg` HID devices (macOS), polled on a timer: a background service has no
 * window to receive device-change messages.
 */
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

export interface Keyboard {
  /** Stable for the same device in the same port. */
  key: string;
  name: string;
  usb: boolean;
  vendorId: string | null;
  productId: string | null;
}

/** Linux: blocks separated by blank lines; keyboards have the `kbd` handler and key events. */
export function parseProcInputDevices(text: string): Keyboard[] {
  const keyboards: Keyboard[] = [];
  for (const block of text.split(/\n\s*\n/)) {
    const handlers = /^H: Handlers=(.*)$/m.exec(block)?.[1] ?? "";
    const ev = /^B: EV=([0-9a-f]+)$/m.exec(block)?.[1];
    if (!/\bkbd\b/.test(handlers) || !ev) continue;
    // EV_KEY (bit 1) and EV_REP (bit 20, key repeat) together mark a real keyboard,
    // not a power button or a media remote with a few keys.
    const bits = parseInt(ev, 16);
    if (!(bits & 0x2) || !(bits & 0x100000)) continue;
    const ids = /^I: Bus=([0-9a-f]+) Vendor=([0-9a-f]+) Product=([0-9a-f]+)/m.exec(block);
    const name = /^N: Name="(.*)"$/m.exec(block)?.[1] ?? "Keyboard";
    const phys = /^P: Phys=(.*)$/m.exec(block)?.[1] ?? "";
    const usb = ids?.[1] === "0003" || phys.startsWith("usb-");
    const vendorId = ids?.[2] ?? null;
    const productId = ids?.[3] ?? null;
    // One physical keyboard often shows several input nodes (keys, media keys); key by the port.
    const port = phys.replace(/\/input\d+$/, "");
    keyboards.push({ key: `${vendorId}:${productId}@${port || name}`, name, usb, vendorId, productId });
  }
  return dedupe(keyboards);
}

/** Windows: `Get-PnpDevice -Class Keyboard -PresentOnly | Select InstanceId,FriendlyName | ConvertTo-Json`. */
export function parseWindowsKeyboards(json: string): Keyboard[] {
  let rows: unknown;
  try {
    rows = JSON.parse(json || "[]");
  } catch {
    return [];
  }
  const list = (Array.isArray(rows) ? rows : [rows]) as { InstanceId?: string; FriendlyName?: string }[];
  return dedupe(
    list
      .filter((r) => typeof r?.InstanceId === "string")
      .map((r) => {
        const id = r.InstanceId as string;
        const ids = /VID_([0-9A-F]{4})&PID_([0-9A-F]{4})/i.exec(id);
        return {
          key: id.toUpperCase(),
          name: r.FriendlyName || "Keyboard",
          usb: /^(USB|HID)\\/i.test(id) && Boolean(ids),
          vendorId: ids?.[1]?.toLowerCase() ?? null,
          productId: ids?.[2]?.toLowerCase() ?? null,
        };
      }),
  );
}

/** macOS: `ioreg -r -c IOHIDDevice -l`; keyboards are usage page 1, usage 6. */
export function parseIoregKeyboards(text: string): Keyboard[] {
  const keyboards: Keyboard[] = [];
  for (const block of text.split(/\+-o /).slice(1)) {
    const prop = (name: string) => new RegExp(`"${name}" = ("?)(.*?)\\1\\s*$`, "m").exec(block)?.[2] ?? null;
    if (prop("PrimaryUsagePage") !== "1" || prop("PrimaryUsage") !== "6") continue;
    const transport = prop("Transport");
    const vendor = prop("VendorID");
    const product = prop("ProductID");
    const location = prop("LocationID");
    const hex = (n: string | null) => (n && /^\d+$/.test(n) ? Number(n).toString(16).padStart(4, "0") : null);
    keyboards.push({
      key: `${hex(vendor)}:${hex(product)}@${location ?? prop("Product") ?? "?"}`,
      name: prop("Product") ?? "Keyboard",
      usb: transport === "USB",
      vendorId: hex(vendor),
      productId: hex(product),
    });
  }
  return dedupe(keyboards);
}

function dedupe(keyboards: Keyboard[]): Keyboard[] {
  const seen = new Map<string, Keyboard>();
  for (const k of keyboards) if (!seen.has(k.key)) seen.set(k.key, k);
  return [...seen.values()];
}

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: 15_000, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (_error, stdout) => resolve(String(stdout ?? "")));
  });
}

/** The keyboards connected now, or null where this system can't list them. */
export async function listKeyboards(platform: NodeJS.Platform = process.platform): Promise<Keyboard[] | null> {
  if (platform === "linux") return parseProcInputDevices(await readFile("/proc/bus/input/devices", "utf8").catch(() => ""));
  if (platform === "win32") {
    return parseWindowsKeyboards(
      await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-PnpDevice -Class Keyboard -PresentOnly | Select-Object InstanceId,FriendlyName | ConvertTo-Json -Compress"]),
    );
  }
  if (platform === "darwin") return parseIoregKeyboards(await run("ioreg", ["-r", "-c", "IOHIDDevice", "-l"]));
  return null;
}

export interface KeyboardBaseline {
  known: string[];
  seeded: boolean;
}

export const EMPTY_KEYBOARDS: KeyboardBaseline = { known: [], seeded: false };

/** New keyboards since the baseline; the first call seeds without reporting. */
export function diffKeyboards(baseline: KeyboardBaseline, current: Keyboard[]): { fresh: Keyboard[]; baseline: KeyboardBaseline } {
  if (!baseline.seeded) return { fresh: [], baseline: { seeded: true, known: [...new Set([...baseline.known, ...current.map((k) => k.key)])] } };
  const known = new Set(baseline.known);
  return { fresh: current.filter((k) => !known.has(k.key)), baseline };
}

/** How often to look: a cheap file read on Linux, a process launch elsewhere. */
export function pollMs(platform: NodeJS.Platform): number {
  return platform === "linux" ? 3_000 : 10_000;
}
