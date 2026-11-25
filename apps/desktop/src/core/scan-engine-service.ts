/**
 * The native scanner (qalaa-scan) as the daemon runs it: where the binary is,
 * which verified rule bundle it uses, and daily differential bundle updates.
 */
import { join } from "node:path";

import type { NativeScanner } from "../engine/native-scan";
import { type UpdateResult, currentManifest, pinnedKeys, updateBundle, verifyWith } from "../engine/scan-bundle";

export interface ScanEngineStatus {
  available: boolean;
  /** Why it isn't available, or what it can't do, in plain words. */
  note: string | null;
  bundleVersion: string | null;
  signedUpdates: boolean;
  lastUpdate: { at: string; result: UpdateResult } | null;
}

export interface ScanEngineDeps {
  root: string;
  binary: string | null;
  /** Where bundles are served, e.g. https://server/api/v1/updates/scan-bundle/ */
  baseUrl: () => string;
  update?: typeof updateBundle;
  keys?: (binary: string) => Promise<string[]>;
  verify?: (binary: string, dir: string) => Promise<boolean>;
  now?: () => Date;
}

export class ScanEngineService {
  private version: string | null = null;
  private verified = false;
  private keys: string[] = [];
  private last: ScanEngineStatus["lastUpdate"] = null;

  constructor(private readonly deps: ScanEngineDeps) {}

  /** Checks the installed bundle once at start-up. */
  async load(): Promise<void> {
    if (!this.deps.binary) return;
    this.keys = await (this.deps.keys ?? pinnedKeys)(this.deps.binary).catch(() => []);
    const manifest = await currentManifest(this.deps.root);
    this.verified = Boolean(manifest) && (await (this.deps.verify ?? verifyWith)(this.deps.binary, join(this.deps.root, "current")).catch(() => false));
    this.version = this.verified ? (manifest?.version ?? null) : null;
  }

  /** What scans should use, or null when the binary isn't installed. */
  scanner(): NativeScanner | null {
    if (!this.deps.binary) return null;
    return { binary: this.deps.binary, bundleDir: this.verified ? join(this.deps.root, "current") : null };
  }

  async update(): Promise<UpdateResult> {
    const binary = this.deps.binary;
    if (!binary) return { updated: false, version: null, downloaded: [], reused: [], reason: "The native scanner isn't installed." };
    let result: UpdateResult;
    try {
      result = await (this.deps.update ?? updateBundle)({ root: this.deps.root, baseUrl: this.deps.baseUrl(), keys: this.keys, verifyDir: (dir) => (this.deps.verify ?? verifyWith)(binary, dir) });
    } catch (error) {
      result = { updated: false, version: this.version, downloaded: [], reused: [], reason: `Couldn't reach the update server (${error instanceof Error ? error.message : String(error)}). The current rules stay in use.` };
    }
    if (result.updated) {
      this.version = result.version;
      this.verified = true;
    }
    this.last = { at: (this.deps.now ?? (() => new Date()))().toISOString(), result };
    return result;
  }

  status(): ScanEngineStatus {
    const note = !this.deps.binary
      ? "The native scanner isn't installed, so only the built-in checks run."
      : !this.keys.length
        ? "This build has no rule-signing key, so the native scanner runs without YARA rules or the model."
        : !this.verified
          ? "No verified rule set yet; it is fetched with the next update."
          : null;
    return { available: Boolean(this.deps.binary), note, bundleVersion: this.version, signedUpdates: this.keys.length > 0, lastUpdate: this.last };
  }
}
