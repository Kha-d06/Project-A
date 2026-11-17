"use client";

import { Laptop, Plus, RefreshCw, ShieldAlert, Smartphone } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Device, DeviceCommand, DeviceCommandKind, DeviceDetection } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

const ACTIVE = new Set(["queued", "sent", "running"]);

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : String(error);
}

function useDeviceText() {
  const { t } = useI18n();
  return t.extra.devices;
}

function StatusValue({ name, value }: { name: string; value: string | number | boolean | null }) {
  const d = useDeviceText();
  if (value === null || value === "") return <>—</>;
  if (typeof value === "boolean") return <>{value ? d.yes : d.no}</>;
  if (name === "protection") return <>{value === "watching" ? d.watching : d.paused}</>;
  if (name === "firewall") return <span className={value === "off" ? "text-danger" : undefined}>{d.firewallStates[String(value)] ?? String(value)}</span>;
  if (name === "exposed_risky_ports" && Number(value) > 0) return <span className="text-warning">{String(value)}</span>;
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) return <>{formatRelative(value)}</>;
  return <>{String(value)}</>;
}

function Detections({ device, command, onQuarantine }: { device: Device; command: DeviceCommand; onQuarantine: (hashes: string[]) => void }) {
  const d = useDeviceText();
  const list = command.result?.detections ?? [];
  if (!list.length) return null;
  // A later quarantine command on this device marks these files as handled.
  const handled = new Set(
    device.recent_commands
      .filter((c) => c.kind === "quarantine" && c.status === "done" && (c.result?.quarantined ?? 0) > 0)
      .flatMap((c) => c.args.sha256 ?? []),
  );
  const open = list.filter((item) => item.sha256 && !item.quarantined && !handled.has(item.sha256));
  const canAct = device.online && device.allow_remote;
  return (
    <div className="mt-2 space-y-2 rounded-control border border-line p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold text-ink">{d.detections}</p>
        {canAct && open.length > 1 && (
          <Button size="sm" variant="danger" onClick={() => onQuarantine(open.map((item) => item.sha256!))}>
            {d.quarantineAll}
          </Button>
        )}
      </div>
      <ul className="space-y-1.5">
        {list.map((item: DeviceDetection, index) => {
          const done = item.quarantined || (item.sha256 !== null && handled.has(item.sha256));
          return (
            <li key={`${item.sha256}-${index}`} className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="min-w-0">
                <span className={item.verdict === "malicious" ? "font-medium text-danger" : "font-medium text-warning"}>
                  {item.verdict === "malicious" ? d.malicious : d.suspicious}
                </span>{" "}
                <span className="font-mono break-all text-ink" dir="ltr">{item.name}</span>
                {item.folder && <span className="text-ink-faint"> · {item.folder}</span>}
                {item.title && <span className="block text-xs text-ink-muted" dir="auto">{item.title}</span>}
              </span>
              {done ? (
                <span className="text-xs text-ink-faint">{d.inQuarantine}</span>
              ) : (
                canAct &&
                item.sha256 && (
                  <Button size="sm" variant="secondary" onClick={() => onQuarantine([item.sha256!])}>
                    {d.quarantine}
                  </Button>
                )
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function CommandRow({ device, command, onQuarantine }: { device: Device; command: DeviceCommand; onQuarantine: (hashes: string[]) => void }) {
  const d = useDeviceText();
  const r = command.result;
  const threats = (r?.malicious ?? 0) + (r?.suspicious ?? 0);
  const failed = command.status === "failed" || command.status === "expired";
  return (
    <li className="py-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <span className="text-ink">
          {d.kinds[command.kind]}
          {command.args.folder_label && <span className="text-ink-muted"> · {command.args.folder_label}</span>}
        </span>
        <span className={failed ? "text-xs text-danger" : ACTIVE.has(command.status) ? "text-xs text-accent" : "text-xs text-ink-faint"}>
          {d.statuses[command.status]} · {formatDateTime(command.finished_at ?? command.created_at)}
        </span>
      </div>
      {command.error && <p className="text-xs text-danger" dir="auto">{command.error}</p>}
      {ACTIVE.has(command.status) && command.progress && (
        <div className="mt-1 space-y-1" role="status">
          <p className="text-xs text-accent">{d.progress(command.progress.scanned, command.progress.found ?? 0)}</p>
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-sunken">
            <div
              className={`h-full rounded-full ${(command.progress.found ?? 0) > 0 ? "bg-danger" : "bg-accent"} ${command.progress.total ? "" : "motion-safe:animate-pulse"}`}
              style={{ width: command.progress.total ? `${Math.min(100, Math.round((command.progress.scanned / command.progress.total) * 100))}%` : "100%" }}
            />
          </div>
        </div>
      )}
      {r && command.kind !== "quarantine" && command.kind !== "update_signatures" && r.scanned !== undefined && (
        <p className="text-xs text-ink-muted">{d.summary(r.scanned, threats)}</p>
      )}
      {r && command.kind === "quarantine" && <p className="text-xs text-ink-muted">{d.quarantinedCount(r.quarantined ?? 0)}</p>}
      <Detections device={device} command={command} onQuarantine={onQuarantine} />
    </li>
  );
}

function DeviceCard({ device, onChange }: { device: Device; onChange: () => void }) {
  const d = useDeviceText();
  const notify = useToast();
  const [chosenFolder, setFolder] = useState(device.folders[0]?.id ?? "");
  // The device may stop offering a folder between refreshes.
  const folder = device.folders.some((f) => f.id === chosenFolder) ? chosenFolder : (device.folders[0]?.id ?? "");
  const [pending, setPending] = useState<DeviceCommandKind | null>(null);
  const canAct = device.online && device.allow_remote;
  const busy = new Set(device.recent_commands.filter((c) => ACTIVE.has(c.status)).map((c) => c.kind));
  const Icon = device.platform === "android" ? Smartphone : Laptop;

  const send = async (kind: DeviceCommandKind, extra: { folder_id?: string; sha256?: string[] } = {}) => {
    setPending(kind);
    try {
      await api.devices.command(device.id, { kind, ...extra });
      notify("success", d.sent);
      onChange();
    } catch (error) {
      notify("error", errorText(error));
    } finally {
      setPending(null);
    }
  };

  const action = (kind: DeviceCommandKind, label: string, extra?: { folder_id?: string }) => (
    <Button
      size="sm"
      variant={kind === "full_scan" || kind === "quick_scan" ? "primary" : "secondary"}
      disabled={!canAct || busy.has(kind)}
      pending={pending === kind}
      onClick={() => send(kind, extra)}
    >
      {label}
    </Button>
  );

  const statusEntries = Object.entries(device.status).filter(([key]) => key in d.statusLabels);

  return (
    <Panel>
      <PanelHeader
        title={
          <span className="flex items-center gap-2">
            <Icon aria-hidden className="size-5 text-ink-muted" />
            {device.name}
          </span>
        }
        description={`${d.platforms[device.platform]} · ${d.version(device.app_version || "?")} · ${
          device.last_seen_at ? d.lastSeen(formatRelative(device.last_seen_at)) : d.neverSeen
        }`}
        action={
          <span className={device.online ? "inline-flex items-center gap-1.5 text-sm text-clear" : "inline-flex items-center gap-1.5 text-sm text-ink-faint"}>
            <span aria-hidden className={device.online ? "size-2 rounded-full bg-clear" : "size-2 rounded-full bg-line-strong"} />
            {device.online ? d.online : d.offline}
          </span>
        }
      />
      <div className="grid gap-6 p-5 lg:grid-cols-2">
        <div className="space-y-4">
          {statusEntries.length > 0 && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              {statusEntries.map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-ink-muted">{d.statusLabels[key]}</dt>
                  <dd className="text-ink">
                    <StatusValue name={key} value={value} />
                  </dd>
                </div>
              ))}
            </dl>
          )}
          {!device.allow_remote ? (
            <Alert tone="info">{d.remoteOff}</Alert>
          ) : !device.online ? (
            <Alert tone="info">{d.offlineHint}</Alert>
          ) : (
            <p className="text-xs text-clear">{d.remoteOn}</p>
          )}
          {device.platform === "android" && device.allow_remote && <p className="text-xs text-ink-muted">{d.phoneHint}</p>}
          <div className="flex flex-wrap gap-2">
            {action("quick_scan", d.quickScan)}
            {action("full_scan", d.fullScan)}
            {action("update_signatures", d.updateSignatures)}
          </div>
          {device.folders.length > 0 && (
            <div className="flex flex-wrap items-end gap-2">
              <Field label={d.folder}>
                {(props) => (
                  <Select {...props} value={folder} onChange={(event) => setFolder(event.target.value)} disabled={!canAct}>
                    {device.folders.map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              {action("folder_scan", d.folderScan, { folder_id: folder })}
            </div>
          )}
          <div className="flex gap-3 border-t border-line pt-3 text-sm">
            <button
              type="button"
              className="text-accent hover:underline"
              onClick={async () => {
                const name = window.prompt(d.renamePrompt, device.name)?.trim();
                if (!name || name === device.name) return;
                try {
                  await api.devices.rename(device.id, name.slice(0, 80));
                  onChange();
                } catch (error) {
                  notify("error", errorText(error));
                }
              }}
            >
              {d.rename}
            </button>
            <button
              type="button"
              className="text-danger hover:underline"
              onClick={async () => {
                if (!window.confirm(d.confirmRemove(device.name))) return;
                try {
                  await api.devices.remove(device.id);
                  onChange();
                } catch (error) {
                  notify("error", errorText(error));
                }
              }}
            >
              {d.remove}
            </button>
          </div>
        </div>
        <div className="rounded-control border border-line">
          <h3 className="border-b border-line px-5 py-3 text-sm font-semibold text-ink">{d.activity}</h3>
          {device.recent_commands.length === 0 ? (
            <p className="px-5 py-4 text-sm text-ink-muted">{d.noActivity}</p>
          ) : (
            <ul className="divide-y divide-line px-5">
              {device.recent_commands.map((command) => (
                <CommandRow key={command.id} device={device} command={command} onQuarantine={(sha256) => send("quarantine", { sha256 })} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </Panel>
  );
}

function AddDevice() {
  const d = useDeviceText();
  const notify = useToast();
  const [code, setCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [pending, setPending] = useState(false);
  return (
    <Panel>
      <PanelHeader
        title={d.addTitle}
        action={
          <Button
            size="sm"
            pending={pending}
            onClick={async () => {
              setPending(true);
              try {
                setCode(await api.extension.createLinkCode());
              } catch (error) {
                notify("error", errorText(error));
              } finally {
                setPending(false);
              }
            }}
          >
            {code ? <RefreshCw aria-hidden className="size-4" /> : <Plus aria-hidden className="size-4" />}
            {d.add}
          </Button>
        }
      />
      {code && (
        <div className="space-y-3 p-5">
          <ol className="list-decimal space-y-1 ps-5 text-sm text-ink">
            {d.addSteps.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ol>
          <p className="text-sm text-ink-muted">{d.code}</p>
          <p className="font-mono text-3xl tracking-[0.3em] text-ink" dir="ltr" aria-live="polite" id="device-link-code">
            {code.code}
          </p>
          <p className="text-xs text-ink-faint">{d.codeExpires(formatDateTime(code.expires_at))}</p>
        </div>
      )}
    </Panel>
  );
}

export function Devices() {
  const d = useDeviceText();
  const [devices, setDevices] = useState<Device[] | null>(null);

  const load = useCallback(() => {
    api.devices.list().then(setDevices).catch(() => setDevices([]));
  }, []);

  useEffect(() => load(), [load]);

  // Refresh quickly while something is waiting on a device, slowly otherwise.
  const waiting = devices?.some((device) => device.recent_commands.some((c) => ACTIVE.has(c.status))) ?? false;
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") load();
    }, waiting ? 2000 : 30000);
    return () => window.clearInterval(timer);
  }, [waiting, load]);

  return (
    <div className="space-y-6">
      <PageTitle title={d.title} description={d.description} />
      <AddDevice />
      {devices === null ? null : devices.length === 0 ? (
        <p className="text-ink-muted">{d.none}</p>
      ) : (
        devices.map((device) => <DeviceCard key={device.id} device={device} onChange={load} />)
      )}
      <p className="flex items-start gap-2 text-sm text-ink-faint">
        <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
        {d.honest}
      </p>
    </div>
  );
}
