/**
 * The methods the background service answers, shared by the headless daemon
 * and (until the native app reaches parity) the Electron shell. Each host
 * supplies the state; the logic lives here once.
 */
import { type HomeInput, type HomeModel, type HomeToggle, buildHome } from "./home";
import { IpcError } from "./protocol";

export interface CoreHost {
  version: string;
  homeInput(): Promise<HomeInput>;
  /** Applies already-validated toggle changes and persists them. */
  updateToggles(changes: Partial<Record<HomeToggle["key"], boolean>>): Promise<void>;
  quickScan(): Promise<{ scanned: number; malicious: number; suspicious: number }>;
  updateSignatures(): Promise<void>;
}

export type Handler = (params: unknown) => Promise<unknown>;

const TOGGLE_KEYS: HomeToggle["key"][] = ["watchEnabled", "onAccessScan", "ransomwareWatch", "networkWatch", "cloudLookup"];

/** Only the Home toggles can be changed over IPC, and only with booleans. */
export function toggleChanges(params: unknown): Partial<Record<HomeToggle["key"], boolean>> {
  if (!params || typeof params !== "object" || Array.isArray(params)) throw new IpcError("bad_params", "Expected an object of settings.");
  const changes: Partial<Record<HomeToggle["key"], boolean>> = {};
  for (const [key, value] of Object.entries(params)) {
    if (!TOGGLE_KEYS.includes(key as HomeToggle["key"])) throw new IpcError("not_allowed", `The setting "${key}" can't be changed here.`);
    if (typeof value !== "boolean") throw new IpcError("bad_params", `"${key}" must be true or false.`);
    changes[key as HomeToggle["key"]] = value;
  }
  if (!Object.keys(changes).length) throw new IpcError("bad_params", "No settings to change.");
  return changes;
}

/** Events pushed to every client (the native window and the Guardian pet). */
export type Emit = (event: "home.changed" | "scan.started" | "scan.finished" | "threat.blocked" | "alert", payload: unknown) => void;

export function createHandlers(host: CoreHost, emit: Emit): Record<string, Handler> {
  const home = async () => buildHome(await host.homeInput());
  const changed = async () => {
    const model = await home();
    emit("home.changed", model);
    return model;
  };
  return {
    "home.get": () => home(),
    "settings.set": async (params) => {
      const toggles = await home();
      const changes = toggleChanges(params);
      for (const key of Object.keys(changes) as HomeToggle["key"][]) {
        if (changes[key] && !toggles.toggles.find((t) => t.key === key)?.available) throw new IpcError("unavailable", `"${key}" isn't available on this system.`);
      }
      await host.updateToggles(changes);
      return changed();
    },
    "scan.quick": async () => {
      emit("scan.started", {});
      const totals = await host.quickScan();
      emit("scan.finished", totals);
      await changed();
      return totals;
    },
    "signatures.update": async () => {
      await host.updateSignatures();
      return changed();
    },
  };
}
