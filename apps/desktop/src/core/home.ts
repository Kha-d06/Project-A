/**
 * The Home view's model: what is protecting this computer, how fresh each check
 * is, what needs doing, and the quick toggles. Pure, so the daemon, the Electron
 * shell and the tests all compute it the same way.
 */
export type CheckStatus = "ok" | "attention" | "off" | "unknown";

export interface HomeInput {
  now: Date;
  platform: NodeJS.Platform;
  watchEnabled: boolean;
  onAccessScan: boolean;
  ransomwareWatch: boolean;
  networkWatch: boolean;
  cloudLookup: boolean;
  signatures: { count: number; updatedAt: string | null; error: string | null };
  lastScanAt: string | null;
  lastNetworkScanAt: string | null;
  lastBackupAt: string | null;
  lastBackupError: string | null;
  backupConfigured: boolean;
  quarantineCount: number;
  recentThreats: number;
  ransomwareAlertAt: string | null;
  updateAvailable: string | null;
  silentUntil: string | null;
  /** Programs newly listening for connections from other machines, awaiting a decision. */
  newListeners?: number;
  /** Keyboards connected since the last check that nobody has confirmed yet. */
  newKeyboards?: number;
  /** Safe DNS (the local filtering resolver), where the host runs it. */
  safeDns?: { on: boolean; available: boolean };
}

export interface HomeCheck {
  id: "signatures" | "realtime" | "ransomware" | "last_scan" | "network" | "backup";
  status: CheckStatus;
  /** When this was last checked or refreshed; null when never. */
  checkedAt: string | null;
}

export interface HomeAction {
  id: string;
  priority: 1 | 2 | 3;
  /** The daemon method the button calls, with its params. */
  command: { method: string; params?: Record<string, unknown> };
}

export interface HomeToggle {
  key: "watchEnabled" | "onAccessScan" | "ransomwareWatch" | "networkWatch" | "cloudLookup" | "safeDns";
  on: boolean;
  available: boolean;
}

export interface HomeModel {
  score: number;
  state: "protected" | "attention" | "at_risk";
  checks: HomeCheck[];
  actions: HomeAction[];
  toggles: HomeToggle[];
  silentUntil: string | null;
  generatedAt: string;
}

const DAY = 24 * 60 * 60 * 1000;
const age = (iso: string | null, now: Date) => (iso ? now.getTime() - Date.parse(iso) : Number.POSITIVE_INFINITY);

const WEIGHTS: Record<HomeCheck["id"], number> = { signatures: 25, realtime: 25, ransomware: 15, last_scan: 15, network: 10, backup: 10 };
const CREDIT: Record<CheckStatus, number> = { ok: 1, attention: 0.4, off: 0, unknown: 0.5 };

export function buildHome(input: HomeInput): HomeModel {
  const { now } = input;
  const fanotify = input.platform === "linux";
  const checks: HomeCheck[] = [
    {
      id: "signatures",
      status: input.signatures.count === 0 || input.signatures.error ? "attention" : age(input.signatures.updatedAt, now) > 2 * DAY ? "attention" : "ok",
      checkedAt: input.signatures.updatedAt,
    },
    { id: "realtime", status: input.watchEnabled || input.onAccessScan ? "ok" : "off", checkedAt: null },
    { id: "ransomware", status: input.ransomwareAlertAt && age(input.ransomwareAlertAt, now) < DAY ? "attention" : input.ransomwareWatch ? "ok" : "off", checkedAt: input.ransomwareAlertAt },
    { id: "last_scan", status: input.recentThreats > 0 ? "attention" : age(input.lastScanAt, now) > 14 * DAY ? "attention" : "ok", checkedAt: input.lastScanAt },
    { id: "network", status: input.lastNetworkScanAt ? (input.networkWatch ? "ok" : age(input.lastNetworkScanAt, now) > 30 * DAY ? "attention" : "ok") : "unknown", checkedAt: input.lastNetworkScanAt },
    {
      id: "backup",
      status: !input.backupConfigured ? "off" : input.lastBackupError || age(input.lastBackupAt, now) > 14 * DAY ? "attention" : "ok",
      checkedAt: input.lastBackupAt,
    },
  ];

  const total = checks.reduce((sum, check) => sum + WEIGHTS[check.id], 0);
  const earned = checks.reduce((sum, check) => sum + WEIGHTS[check.id] * CREDIT[check.status], 0);
  const score = Math.round((earned / total) * 100);
  const offCore = checks.some((c) => (c.id === "realtime" || c.id === "signatures") && c.status !== "ok");
  const needsAttention = checks.some((c) => c.status === "attention") || score < 85;
  const state: HomeModel["state"] = input.recentThreats > 0 || offCore ? "at_risk" : needsAttention ? "attention" : "protected";

  const actions: HomeAction[] = [];
  if (input.recentThreats > 0) actions.push({ id: "review_threats", priority: 1, command: { method: "view.open", params: { view: "timeline" } } });
  if ((input.newKeyboards ?? 0) > 0) actions.push({ id: "review_keyboard", priority: 1, command: { method: "keyboards.trust_all" } });
  if ((input.newListeners ?? 0) > 0) actions.push({ id: "review_listeners", priority: 1, command: { method: "view.open", params: { view: "listeners" } } });
  if (checks[1]?.status === "off") actions.push({ id: "turn_on_realtime", priority: 1, command: { method: "settings.set", params: { watchEnabled: true } } });
  if (checks[0]?.status !== "ok") actions.push({ id: "update_signatures", priority: 1, command: { method: "signatures.update" } });
  if (checks[3]?.status === "attention" && input.recentThreats === 0) actions.push({ id: "quick_scan", priority: 2, command: { method: "scan.quick" } });
  if (!input.backupConfigured) actions.push({ id: "set_up_backup", priority: 2, command: { method: "view.open", params: { view: "backup" } } });
  if (checks[4]?.status === "unknown") actions.push({ id: "scan_network", priority: 3, command: { method: "view.open", params: { view: "network" } } });
  if (input.updateAvailable) actions.push({ id: "install_update", priority: 2, command: { method: "view.open", params: { view: "updates" } } });
  actions.sort((a, b) => a.priority - b.priority);

  const toggles: HomeToggle[] = [
    { key: "watchEnabled", on: input.watchEnabled, available: true },
    { key: "onAccessScan", on: input.onAccessScan, available: fanotify },
    { key: "ransomwareWatch", on: input.ransomwareWatch, available: true },
    { key: "networkWatch", on: input.networkWatch, available: true },
    { key: "cloudLookup", on: input.cloudLookup, available: true },
  ];
  if (input.safeDns) toggles.push({ key: "safeDns", on: input.safeDns.on, available: input.safeDns.available });

  return { score, state, checks, actions, toggles, silentUntil: input.silentUntil, generatedAt: now.toISOString() };
}
