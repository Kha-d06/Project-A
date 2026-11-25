/**
 * The methods the background service answers, shared by the headless daemon
 * and (until the native app reaches parity) the Electron shell. Each host
 * supplies the state; the logic lives here once.
 */
import { type HomeInput, type HomeModel, type HomeToggle, buildHome } from "./home";
import type { AliasService } from "./alias-service";
import type { BehaviourService } from "./behaviour-service";
import type { BrokerService } from "./broker-service";
import type { ClipboardService } from "./clipboard-service";
import type { CredentialGuardService } from "./credential-guard-service";
import type { KeyboardService } from "./keyboard-service";
import type { ListenerService } from "./listener-service";
import type { SafeDnsService } from "./safe-dns-service";
import type { SafePayService } from "./safepay-service";
import type { ScanEngineService } from "./scan-engine-service";
import { IpcError } from "./protocol";

export interface CoreHost {
  version: string;
  homeInput(): Promise<HomeInput>;
  /** Applies already-validated toggle changes and persists them. */
  updateToggles(changes: Partial<Record<HomeToggle["key"], boolean>>): Promise<void>;
  quickScan(): Promise<{ scanned: number; malicious: number; suspicious: number }>;
  updateSignatures(): Promise<void>;
  /** New listening-port alerts, where the host runs them. */
  listeners?: ListenerService;
  /** New-keyboard (BadUSB) warnings, where the host runs them. */
  keyboards?: KeyboardService;
  /** Safe DNS, where the host runs it. */
  safeDns?: SafeDnsService;
  /** Clipboard auto-clear, where the host runs it. */
  clipboard?: ClipboardService;
  /** Credential guardrails, where the host runs them. */
  credentials?: CredentialGuardService;
  /** SafePay clean browser sessions, where the host runs them. */
  safePay?: SafePayService;
  /** Disposable email aliases through the linked account. */
  aliases?: AliasService;
  /** The data-broker opt-out checklist. */
  brokers?: BrokerService;
  /** Sigma-derived behaviour rules over newly started programs. */
  behaviour?: BehaviourService;
  /** qalaa-scan, the native scanner, and its signed rule bundle. */
  scanEngine?: ScanEngineService;
}

export type Handler = (params: unknown) => Promise<unknown>;

const TOGGLE_KEYS: HomeToggle["key"][] = ["watchEnabled", "onAccessScan", "ransomwareWatch", "networkWatch", "cloudLookup", "safeDns", "clipboardGuard", "credentialGuard"];

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
export type Emit = (
  event: "home.changed" | "scan.started" | "scan.finished" | "threat.blocked" | "alert" | "clipboard.armed" | "clipboard.cleared" | "safepay.started" | "safepay.ended",
  payload: unknown,
) => void;

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
      // Safe DNS changes the system resolver (consent prompt), so it has its own path.
      const { safeDns, ...rest } = changes;
      if (safeDns !== undefined) {
        if (!host.safeDns) throw new IpcError("unavailable", "Safe DNS isn't running here.");
        await host.safeDns.setEnabled(safeDns);
      }
      if (Object.keys(rest).length) await host.updateToggles(rest);
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
    "clipboard.get": async () => requireClipboard(host).status(),
    "clipboard.copy_secret": async (params) => requireClipboard(host).copySecret((params as { text?: unknown } | undefined)?.text),
    "clipboard.clear_now": async () => requireClipboard(host).clearNow(),
    "brokers.get": async () => requireBrokers(host).status(),
    "brokers.mark": async (params) => {
      const status = await requireBrokers(host).mark(params);
      await changed();
      return status;
    },
    "brokers.template": async (params) => requireBrokers(host).template(params),
    "aliases.list": async () => requireAliases(host).list(),
    "aliases.create": async (params) => requireAliases(host).create(params),
    "safepay.get": async () => requireSafePay(host).status(),
    "safepay.launch": async (params) => requireSafePay(host).launch(params),
    "behaviour.get": async () => requireBehaviour(host).status(),
    "behaviour.dismiss": async (params) => {
      const status = requireBehaviour(host).dismiss((params as { id?: unknown } | undefined)?.id);
      await changed();
      return status;
    },
    "behaviour.stop": async (params) => {
      const status = await requireBehaviour(host).stop((params as { id?: unknown } | undefined)?.id);
      await changed();
      return status;
    },
    "behaviour.helper": async (params) => {
      const install = (params as { install?: unknown } | undefined)?.install;
      if (typeof install !== "boolean") throw new IpcError("bad_params", "Expected install: true or false.");
      return requireBehaviour(host).helper(install);
    },
    "scanengine.get": async () => requireScanEngine(host).status(),
    "scanengine.update": async () => {
      const result = await requireScanEngine(host).update();
      return { ...requireScanEngine(host).status(), result };
    },
    "credentials.get": async () => requireCredentials(host).status(),
    ...Object.fromEntries(
      (["suspend", "resume", "terminate", "allow", "dismiss"] as const).map((action) => [
        `credentials.${action}`,
        async (params: unknown) => {
          const status = await requireCredentials(host)[action]((params as { id?: unknown } | undefined)?.id);
          await changed();
          return status;
        },
      ]),
    ),
    "credentials.untrust": async (params) => requireCredentials(host).untrust((params as { exe?: unknown } | undefined)?.exe),
    "safedns.get": async () => {
      if (!host.safeDns) throw new IpcError("unavailable", "Safe DNS isn't running here.");
      return host.safeDns.status();
    },
    "safedns.adblock": async (params) => {
      if (!host.safeDns) throw new IpcError("unavailable", "Safe DNS isn't running here.");
      const on = (params as { on?: unknown } | undefined)?.on;
      if (typeof on !== "boolean") throw new IpcError("bad_params", "Expected on: true or false.");
      return host.safeDns.setAdBlocking(on);
    },
    "keyboards.get": async () => requireKeyboards(host).status(),
    "keyboards.trust_all": async () => {
      const status = await requireKeyboards(host).trustAll();
      await changed();
      return status;
    },
    "listeners.get": async () => requireListeners(host).status(),
    "listeners.check": async () => {
      await requireListeners(host).check();
      await changed();
      return requireListeners(host).status();
    },
    "listeners.trust": async (params) => {
      const status = await requireListeners(host).trust((params as { key?: unknown } | undefined)?.key);
      await changed();
      return status;
    },
    "listeners.block": async (params) => {
      const { port, block } = (params ?? {}) as { port?: unknown; block?: unknown };
      const status = await requireListeners(host).block(port, block);
      await changed();
      return status;
    },
  };
}

function requireBehaviour(host: CoreHost): BehaviourService {
  if (!host.behaviour) throw new IpcError("unavailable", "Behaviour rules aren't part of this app.");
  return host.behaviour;
}

function requireScanEngine(host: CoreHost): ScanEngineService {
  if (!host.scanEngine) throw new IpcError("unavailable", "The native scanner isn't part of this app.");
  return host.scanEngine;
}

function requireListeners(host: CoreHost): ListenerService {
  if (!host.listeners) throw new IpcError("unavailable", "Port alerts aren't running here.");
  return host.listeners;
}

function requireKeyboards(host: CoreHost): KeyboardService {
  if (!host.keyboards) throw new IpcError("unavailable", "Keyboard warnings aren't running here.");
  return host.keyboards;
}

function requireClipboard(host: CoreHost): ClipboardService {
  if (!host.clipboard) throw new IpcError("unavailable", "Clipboard auto-clear isn't running here.");
  return host.clipboard;
}

function requireCredentials(host: CoreHost): CredentialGuardService {
  if (!host.credentials) throw new IpcError("unavailable", "Credential guardrails aren't running here.");
  return host.credentials;
}

function requireSafePay(host: CoreHost): SafePayService {
  if (!host.safePay) throw new IpcError("unavailable", "SafePay isn't running here.");
  return host.safePay;
}

function requireAliases(host: CoreHost): AliasService {
  if (!host.aliases) throw new IpcError("unavailable", "Email aliases aren't available here.");
  return host.aliases;
}

function requireBrokers(host: CoreHost): BrokerService {
  if (!host.brokers) throw new IpcError("unavailable", "The data-broker checklist isn't available here.");
  return host.brokers;
}
