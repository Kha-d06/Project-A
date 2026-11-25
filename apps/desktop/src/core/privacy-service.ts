/**
 * The Privacy hub for any interface over qalaa-ipc (until now the camera and
 * microphone locks and the "who used them" watch ran only inside the Electron
 * window). Engines unchanged:
 *
 * - Camera and microphone locks: on Linux, the device nodes' permissions are
 *   changed by a root script (a password prompt); on Windows, the per-user
 *   privacy consent in the registry. Not available on macOS, which only lets
 *   the person do this in System Settings; the hub says so.
 * - Who's using the camera or microphone (Linux and Windows): checked every 5
 *   seconds while it's on; each new use is an alert and goes in a short log
 *   kept in memory only. macOS shows its own indicator and doesn't let other
 *   apps see who is recording.
 * - The clipboard auto-clear status, for the hub's countdown and Clear now.
 * - Links into the web dashboard (password and passkey vault, aliases), so the
 *   vault's end-to-end encryption stays in one audited place. Offered only when
 *   the Qalaa server is reached over https.
 */
import type { DeviceUse } from "../engine/security";
import type { BlockState, Device } from "../engine/privacy-block";
import type { ClipboardStatus } from "./clipboard-service";
import { IpcError } from "./protocol";

export const USE_POLL_MS = 5_000;
const LOG_LIMIT = 50;

export interface PrivacyStatus {
  platform: NodeJS.Platform;
  locks: { supported: boolean; camera: BlockState; microphone: BlockState };
  watch: { on: boolean; supported: boolean };
  /** Who's using the camera or microphone right now. */
  inUse: { device: string; app: string }[];
  log: { at: string; device: string; app: string }[];
  clipboard: ClipboardStatus | null;
  /** https links into the web dashboard, or null when the server isn't on https. */
  web: { vault: string; aliases: string; brokers: string } | null;
}

export interface PrivacyDeps {
  platform: NodeJS.Platform;
  locks: {
    supported(): boolean;
    state(device: Device): Promise<BlockState>;
    set(device: Device, block: boolean): Promise<void>;
  };
  deviceUse: () => Promise<{ uses: DeviceUse[] }>;
  newUses: (before: DeviceUse[], now: DeviceUse[]) => DeviceUse[];
  watchOn: () => boolean;
  saveWatch: (on: boolean) => Promise<void>;
  clipboard: () => ClipboardStatus | null;
  serverUrl: () => string;
  emit: (event: "alert", payload: unknown) => void;
  now?: () => number;
}

export class PrivacyService {
  private uses: DeviceUse[] = [];
  private log: PrivacyStatus["log"] = [];
  private timer: NodeJS.Timeout | null = null;
  private readonly now: () => number;

  constructor(private readonly deps: PrivacyDeps) {
    this.now = deps.now ?? Date.now;
  }

  private watchSupported(): boolean {
    return this.deps.platform === "linux" || this.deps.platform === "win32";
  }

  async status(): Promise<PrivacyStatus> {
    const supported = this.deps.locks.supported();
    const state = (device: Device) => (supported ? this.deps.locks.state(device).catch((): BlockState => "unknown") : Promise.resolve<BlockState>("unsupported"));
    const [camera, microphone] = await Promise.all([state("camera"), state("microphone")]);
    let web: PrivacyStatus["web"] = null;
    try {
      const base = new URL(this.deps.serverUrl());
      if (base.protocol === "https:") {
        const at = (path: string) => new URL(path, base).toString();
        web = { vault: at("/dashboard/passwords"), aliases: at("/dashboard/privacy"), brokers: at("/dashboard/privacy") };
      }
    } catch {
      web = null;
    }
    return {
      platform: this.deps.platform,
      locks: { supported, camera, microphone },
      watch: { on: this.deps.watchOn() && this.watchSupported(), supported: this.watchSupported() },
      inUse: this.uses.map((u) => ({ device: u.device, app: u.app })),
      log: this.log,
      clipboard: this.deps.clipboard(),
      web,
    };
  }

  /** Blocks or allows the camera or microphone. On Linux this asks for the password. */
  async setLock(params: unknown): Promise<PrivacyStatus> {
    const { device, block } = (params ?? {}) as { device?: unknown; block?: unknown };
    if (device !== "camera" && device !== "microphone") throw new IpcError("bad_params", 'Expected "camera" or "microphone".');
    if (typeof block !== "boolean") throw new IpcError("bad_params", '"block" must be true or false.');
    if (!this.deps.locks.supported()) throw new IpcError("unavailable", "Blocking the camera and microphone isn't available on this system.");
    await this.deps.locks.set(device, block).catch((error: unknown) => {
      throw new IpcError("failed", (error instanceof Error ? error.message : String(error)).slice(0, 300));
    });
    return this.status();
  }

  async setWatch(params: unknown): Promise<PrivacyStatus> {
    const on = (params as { on?: unknown } | undefined)?.on;
    if (typeof on !== "boolean") throw new IpcError("bad_params", '"on" must be true or false.');
    if (on && !this.watchSupported()) throw new IpcError("unavailable", "macOS shows its own camera and microphone indicator, and doesn't let other apps see who is recording.");
    await this.deps.saveWatch(on);
    this.applyWatch();
    return this.status();
  }

  /** Starts or stops the 5-second check to match the setting (the daemon calls this at start). */
  applyWatch(): void {
    const want = this.deps.watchOn() && this.watchSupported();
    if (want && !this.timer) {
      this.timer = setInterval(() => void this.checkUse().catch(() => undefined), USE_POLL_MS);
      this.timer.unref();
      void this.checkUse().catch(() => undefined);
    } else if (!want && this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      this.uses = [];
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** One check: a program that just started using the camera or microphone is an alert. */
  async checkUse(): Promise<{ device: string; app: string }[]> {
    const { uses } = await this.deps.deviceUse();
    const started = this.deps.newUses(this.uses, uses);
    this.uses = uses;
    const at = new Date(this.now()).toISOString();
    for (const use of started) {
      this.log.unshift({ at, device: use.device, app: use.app });
      this.deps.emit("alert", { kind: "device_use", device: use.device, app: use.app });
    }
    this.log.splice(LOG_LIMIT);
    return started.map((u) => ({ device: u.device, app: u.app }));
  }
}
