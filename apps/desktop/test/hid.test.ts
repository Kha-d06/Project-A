import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { buildHome } from "../src/core/home";
import { KeyboardService } from "../src/core/keyboard-service";
import { EMPTY_KEYBOARDS, type Keyboard, diffKeyboards, parseIoregKeyboards, parseProcInputDevices, parseWindowsKeyboards, pollMs } from "../src/engine/hid";

const PROC = `I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
P: Phys=LNXPWRBN/button/input0
S: Sysfs=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input0
U: Uniq=
H: Handlers=kbd event0
B: PROP=0
B: EV=3
B: KEY=10000000000000 0

I: Bus=0011 Vendor=0001 Product=0001 Version=ab41
N: Name="AT Translated Set 2 keyboard"
P: Phys=isa0060/serio0/input0
S: Sysfs=/devices/platform/i8042/serio0/input/input3
U: Uniq=
H: Handlers=sysrq kbd event3 leds
B: PROP=0
B: EV=120013
B: KEY=402000000 3803078f800d001 feffffdfffefffff fffffffffffffffe
B: MSC=10
B: LED=7

I: Bus=0003 Vendor=046d Product=c31c Version=0110
N: Name="Logitech USB Keyboard"
P: Phys=usb-0000:00:14.0-2/input0
S: Sysfs=/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:046D:C31C.0001/input/input5
U: Uniq=
H: Handlers=sysrq kbd event5 leds
B: PROP=0
B: EV=120013
B: KEY=1000000000007 ff9f207ac14057ff febeffdfffefffff fffffffffffffffe

I: Bus=0003 Vendor=046d Product=c31c Version=0110
N: Name="Logitech USB Keyboard Consumer Control"
P: Phys=usb-0000:00:14.0-2/input1
H: Handlers=kbd event6
B: EV=1f

I: Bus=0003 Vendor=1b4f Product=9206 Version=0101
N: Name="Arduino LLC Arduino Leonardo"
P: Phys=usb-0000:00:14.0-3/input2
H: Handlers=sysrq kbd event9 leds
B: EV=120013
`;

describe("keyboard parsers", () => {
  it("Linux: real keyboards only, USB marked, one entry per port", () => {
    const keyboards = parseProcInputDevices(PROC);
    expect(keyboards.map((k) => k.name)).toEqual(["AT Translated Set 2 keyboard", "Logitech USB Keyboard", "Arduino LLC Arduino Leonardo"]);
    expect(keyboards.map((k) => k.usb)).toEqual([false, true, true]);
    expect(keyboards[1]).toMatchObject({ vendorId: "046d", productId: "c31c", key: "046d:c31c@usb-0000:00:14.0-2" });
  });

  it("Windows: PnP keyboard devices, single object or list", () => {
    const one = parseWindowsKeyboards('{"InstanceId":"HID\\\\VID_1B4F&PID_9206&MI_02\\\\7&1A2B&0&0000","FriendlyName":"HID Keyboard Device"}');
    expect(one).toEqual([{ key: "HID\\VID_1B4F&PID_9206&MI_02\\7&1A2B&0&0000", name: "HID Keyboard Device", usb: true, vendorId: "1b4f", productId: "9206" }]);
    const many = parseWindowsKeyboards('[{"InstanceId":"ACPI\\\\PNP0303\\\\4&1D401FB5&0","FriendlyName":"Standard PS/2 Keyboard"},{"InstanceId":"USB\\\\VID_046D&PID_C31C\\\\5&2","FriendlyName":null}]');
    expect(many.map((k) => [k.name, k.usb])).toEqual([["Standard PS/2 Keyboard", false], ["Keyboard", true]]);
    expect(parseWindowsKeyboards("not json")).toEqual([]);
  });

  it("macOS: HID devices with keyboard usage", () => {
    const text = `+-o AppleUserHIDDevice  <class IOHIDDevice>
    {
      "Product" = "Apple Internal Keyboard / Trackpad"
      "Transport" = "SPI"
      "PrimaryUsagePage" = 1
      "PrimaryUsage" = 6
      "VendorID" = 1452
      "ProductID" = 832
      "LocationID" = 1
    }
+-o IOUSBHostHIDDevice  <class IOHIDDevice>
    {
      "Product" = "USB Optical Mouse"
      "Transport" = "USB"
      "PrimaryUsagePage" = 1
      "PrimaryUsage" = 2
    }
+-o IOUSBHostHIDDevice  <class IOHIDDevice>
    {
      "Product" = "Rubber Gadget"
      "Transport" = "USB"
      "PrimaryUsagePage" = 1
      "PrimaryUsage" = 6
      "VendorID" = 1452
      "ProductID" = 544
      "LocationID" = 337641472
    }
`;
    const keyboards = parseIoregKeyboards(text);
    expect(keyboards.map((k) => [k.name, k.usb, k.vendorId])).toEqual([
      ["Apple Internal Keyboard / Trackpad", false, "05ac"],
      ["Rubber Gadget", true, "05ac"],
    ]);
  });

  it("seeds first, then reports newcomers", () => {
    const k = (key: string): Keyboard => ({ key, name: key, usb: true, vendorId: null, productId: null });
    const first = diffKeyboards(EMPTY_KEYBOARDS, [k("a")]);
    expect(first.fresh).toEqual([]);
    expect(diffKeyboards(first.baseline, [k("a"), k("b")]).fresh.map((x) => x.key)).toEqual(["b"]);
    expect(pollMs("linux")).toBeLessThan(pollMs("win32"));
  });
});

describe("keyboard service", () => {
  it("alerts once, puts 'I plugged it in' on Home, and forgets unplugged devices", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-kb-"));
    let current = parseProcInputDevices(PROC).slice(0, 2);
    const events: unknown[] = [];
    const service = new KeyboardService(join(dir, "kb.json"), async () => current, (event, payload) => events.push({ event, payload }));
    await service.load();
    await service.check();
    expect(events).toEqual([]);

    current = parseProcInputDevices(PROC);
    await service.check();
    await service.check();
    expect(events).toEqual([{ event: "alert", payload: { kind: "keyboard", key: "1b4f:9206@usb-0000:00:14.0-3", name: "Arduino LLC Arduino Leonardo", usb: true } }]);
    expect(service.newCount()).toBe(1);

    const home = buildHome({ now: new Date(), platform: "linux", watchEnabled: true, onAccessScan: false, ransomwareWatch: true, networkWatch: true, cloudLookup: false, signatures: { count: 1, updatedAt: new Date().toISOString(), error: null }, lastScanAt: new Date().toISOString(), lastNetworkScanAt: new Date().toISOString(), lastBackupAt: new Date().toISOString(), lastBackupError: null, backupConfigured: true, quarantineCount: 0, recentThreats: 0, ransomwareAlertAt: null, updateAvailable: null, silentUntil: null, newKeyboards: service.newCount() });
    expect(home.actions[0]).toEqual({ id: "review_keyboard", priority: 1, command: { method: "keyboards.trust_all" } });

    const handlers = createHandlers({ version: "t", homeInput: async () => { throw new Error("unused"); }, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, keyboards: service }, () => {});
    expect(((await handlers["keyboards.get"]?.(undefined)) as { keyboards: { fresh: boolean }[] }).keyboards.filter((k) => k.fresh)).toHaveLength(1);
    await service.trustAll();
    expect(service.newCount()).toBe(0);

    // Plugged in and pulled out before anyone answered: no pending decision.
    current = [...parseProcInputDevices(PROC), { key: "x", name: "Gadget", usb: true, vendorId: null, productId: null }];
    await service.check();
    current = parseProcInputDevices(PROC);
    await service.check();
    expect(service.newCount()).toBe(0);
  });

  it("reports systems it can't read", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-kb-"));
    const service = new KeyboardService(join(dir, "kb.json"), async () => null, () => {});
    await service.check();
    expect(service.status().supported).toBe(false);
  });
});
