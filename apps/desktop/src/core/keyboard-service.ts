/**
 * New-keyboard (BadUSB) warnings as a service, shared by the background service
 * and the classic app. Never blocks a device: it alerts, and the person either
 * confirms they plugged it in or unplugs it.
 */
import { readFile, rename, writeFile } from "node:fs/promises";

import { EMPTY_KEYBOARDS, type Keyboard, type KeyboardBaseline, diffKeyboards } from "../engine/hid";
import type { Emit } from "./handlers";

export interface KeyboardStatus {
  keyboards: (Keyboard & { fresh: boolean })[];
  supported: boolean;
}

export class KeyboardService {
  private baseline: KeyboardBaseline = EMPTY_KEYBOARDS;
  private current: Keyboard[] = [];
  private fresh = new Map<string, Keyboard>();
  private supported = true;

  constructor(
    private readonly file: string,
    private readonly list: () => Promise<Keyboard[] | null>,
    private readonly emit: Emit,
  ) {}

  async load(): Promise<void> {
    try {
      this.baseline = { ...EMPTY_KEYBOARDS, ...(JSON.parse(await readFile(this.file, "utf8")) as Partial<KeyboardBaseline>) };
    } catch {
      this.baseline = EMPTY_KEYBOARDS;
    }
  }

  private async save(): Promise<void> {
    await writeFile(`${this.file}.tmp`, JSON.stringify(this.baseline));
    await rename(`${this.file}.tmp`, this.file);
  }

  async check(): Promise<Keyboard[]> {
    const keyboards = await this.list();
    if (!keyboards) {
      this.supported = false;
      return [];
    }
    this.current = keyboards;
    const wasSeeded = this.baseline.seeded;
    const { fresh, baseline } = diffKeyboards(this.baseline, keyboards);
    this.baseline = baseline;
    if (!wasSeeded) await this.save();
    const reported = fresh.filter((k) => !this.fresh.has(k.key));
    for (const k of fresh) this.fresh.set(k.key, k);
    // Unplugged before anyone answered: nothing left to decide.
    for (const key of [...this.fresh.keys()]) if (!keyboards.some((k) => k.key === key)) this.fresh.delete(key);
    for (const k of reported) this.emit("alert", { kind: "keyboard", key: k.key, name: k.name, usb: k.usb });
    return reported;
  }

  newCount(): number {
    return this.fresh.size;
  }

  status(): KeyboardStatus {
    return { keyboards: this.current.map((k) => ({ ...k, fresh: this.fresh.has(k.key) })), supported: this.supported };
  }

  /** "I plugged it in": every keyboard waiting for an answer becomes known. */
  async trustAll(): Promise<KeyboardStatus> {
    this.baseline = { ...this.baseline, known: [...new Set([...this.baseline.known, ...this.fresh.keys()])] };
    this.fresh.clear();
    await this.save();
    return this.status();
  }
}
