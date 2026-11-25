/**
 * ATT&CK T1200 (Hardware Additions): BadUSB keystroke injectors. A device
 * can't be plugged in on a CI runner, so these are recorded device listings
 * from before and after one was connected (a DigiSpark DigiKeyboard on Linux,
 * a USB Rubber Ducky-style ATmega32U4 on Windows, a gadget posing as an Apple
 * keyboard on macOS), fed through the same parsers and service as the real
 * thing. Mapped in tests/attack/atomics/planned.yaml.
 */
import { readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { KeyboardService } from "../src/core/keyboard-service";
import { type Keyboard, parseIoregKeyboards, parseProcInputDevices, parseWindowsKeyboards } from "../src/engine/hid";

const fixture = (name: string) => readFile(join(__dirname, "fixtures/attack", name), "utf8");

const recordings: [string, (text: string) => Keyboard[], string, string, Partial<Keyboard>][] = [
  ["Linux", parseProcInputDevices, "T1200-linux-before.txt", "T1200-linux-after.txt", { name: "digistump.com DigiKeyboard", vendorId: "16c0", productId: "27db", usb: true }],
  ["Windows", parseWindowsKeyboards, "T1200-windows-before.json", "T1200-windows-after.json", { vendorId: "03eb", productId: "2401", usb: true }],
  ["macOS", parseIoregKeyboards, "T1200-macos-before.txt", "T1200-macos-after.txt", { vendorId: "05ac", productId: "0220", usb: true }],
];

describe("T1200 BadUSB, from recorded device listings", () => {
  it.each(recordings)("%s: the injector is reported once, as soon as it appears", async (_os, parse, before, after, expected) => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-t1200-"));
    let listing = parse(await fixture(before));
    const events: { event: string; payload: Record<string, unknown> }[] = [];
    const service = new KeyboardService(join(dir, "kb.json"), async () => listing, (event, payload) => events.push({ event, payload: payload as Record<string, unknown> }));
    await service.load();
    await service.check(); // the keyboards already there are recorded, not reported
    expect(events).toEqual([]);

    listing = parse(await fixture(after));
    await service.check();
    await service.check();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ event: "alert", payload: { kind: "keyboard", usb: true } });
    const added = listing.find((k) => k.key === events[0]!.payload.key);
    expect(added).toMatchObject(expected);
    expect(service.newCount()).toBe(1);
  });
});
