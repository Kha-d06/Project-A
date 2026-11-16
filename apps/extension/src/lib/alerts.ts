import type { Alert } from "./types";

const KEY = "alerts";
const MAX_ALERTS = 30;
// Revisiting the same site shortly after refreshes its entry instead of adding another.
const REPEAT_WINDOW_MS = 10 * 60 * 1000;

function isRepeat(previous: Alert, next: Alert): boolean {
  return (
    previous.host === next.host &&
    previous.verdict === next.verdict &&
    previous.kind === next.kind &&
    new Date(next.at).getTime() - new Date(previous.at).getTime() < REPEAT_WINDOW_MS
  );
}

export async function recordAlert(alert: Alert, keep: boolean): Promise<void> {
  if (!keep) return;
  const alerts = (await listAlerts()).filter((previous) => !isRepeat(previous, alert));
  await chrome.storage.local.set({ [KEY]: [alert, ...alerts].slice(0, MAX_ALERTS) });
}

export async function listAlerts(): Promise<Alert[]> {
  const stored = await chrome.storage.local.get(KEY);
  return (stored[KEY] as Alert[] | undefined) ?? [];
}

export async function clearAlerts(): Promise<void> {
  await chrome.storage.local.remove(KEY);
}
