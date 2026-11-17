"use client";

import { Check, Download, Pause, Play, Plus, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { VpnStatus } from "@/lib/api/types";
import { formatBytes, formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";
import { buildConfig, generateKeyPair, qrModules, tunnelFileName } from "@/lib/wireguard";

const LIMIT_CHOICES_GB = [0, 5, 10, 25, 50, 100, 250];

function useVpnText() {
  return useI18n().t.extra.vpn;
}

function errorText(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : String(error);
}

function QrCode({ text, label }: { text: string; label: string }) {
  const modules = useMemo(() => qrModules(text), [text]);
  const size = modules.length + 8; // quiet zone of four modules
  const path = modules.flatMap((row, y) => row.map((dark, x) => (dark ? `M${x + 4} ${y + 4}h1v1h-1z` : ""))).join("");
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${size} ${size}`} className="size-64 max-w-full rounded-control bg-white" shapeRendering="crispEdges">
      <path d={path} fill="#000" />
    </svg>
  );
}

function NewConnection({ name, config, onDone }: { name: string; config: string; onDone: () => void }) {
  const v = useVpnText();
  const [showText, setShowText] = useState(false);
  const download = () => {
    const url = URL.createObjectURL(new Blob([config], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = tunnelFileName(name);
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <Panel>
      <PanelHeader title={v.readyTitle(name)} description={v.readyIntro} />
      <div className="grid gap-6 p-5 md:grid-cols-[auto_1fr]">
        <QrCode text={config} label={v.qrLabel} />
        <div className="space-y-3">
          <Alert tone="warning">{v.onlyOnce}</Alert>
          <div className="flex flex-wrap gap-2">
            <Button onClick={download}>
              <Download aria-hidden className="size-4" />
              {v.download}
            </Button>
            <Button variant="secondary" onClick={() => setShowText(!showText)}>
              {showText ? v.hideConfig : v.showConfig}
            </Button>
            <Button variant="secondary" onClick={onDone}>
              <Check aria-hidden className="size-4" />
              {v.done}
            </Button>
          </div>
          {showText && (
            <pre className="overflow-x-auto rounded-control bg-surface-sunken p-3 font-mono text-xs text-ink" dir="ltr" id="vpn-config">
              {config}
            </pre>
          )}
          <p className="text-xs text-ink-muted">{v.leakNote}</p>
        </div>
      </div>
    </Panel>
  );
}

export function Vpn() {
  const v = useVpnText();
  const notify = useToast();
  const [status, setStatus] = useState<VpnStatus | null>(null);
  const [name, setName] = useState("");
  const [pending, setPending] = useState(false);
  // Held only in this page's memory, and dropped when the person presses Done.
  const [created, setCreated] = useState<{ name: string; config: string } | null>(null);

  const load = useCallback(() => {
    api.vpn.status().then(setStatus).catch((error) => notify("error", errorText(error)));
  }, [notify]);

  useEffect(() => {
    load();
    const timer = window.setInterval(() => document.visibilityState === "visible" && load(), 20_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const keys = await generateKeyPair();
      const deviceName = name.trim();
      const result = await api.vpn.add(deviceName, keys.publicKey);
      setCreated({
        name: deviceName,
        config: buildConfig({
          privateKey: keys.privateKey,
          address: result.address,
          dns: result.dns,
          serverPublicKey: result.server_public_key,
          endpoint: result.endpoint,
          allowedIps: result.allowed_ips,
        }),
      });
      setName("");
      load();
    } catch (error) {
      notify("error", errorText(error));
    } finally {
      setPending(false);
    }
  };

  const atLimit = status ? status.devices.length >= status.max_devices : false;

  return (
    <div className="space-y-6">
      <PageTitle title={v.title} description={v.description} />
      {status && !status.enabled && <Alert tone="info">{v.disabled}</Alert>}
      {status?.enabled && (
        <p className={status.server_online ? "flex items-center gap-2 text-sm text-clear" : "flex items-center gap-2 text-sm text-warning"} id="vpn-server-status">
          <span aria-hidden className={status.server_online ? "size-2 rounded-full bg-clear" : "size-2 rounded-full bg-warning"} />
          {status.server_online ? v.online : v.offline}
        </p>
      )}

      <Panel>
        <PanelHeader title={v.whatTitle} />
        <div className="grid gap-4 p-5 md:grid-cols-2">
          <ul className="space-y-2 text-sm">
            {v.does.map((line) => (
              <li key={line} className="flex gap-2">
                <Check aria-hidden className="mt-0.5 size-4 shrink-0 text-clear" />
                <span>{line}</span>
              </li>
            ))}
          </ul>
          <ul className="space-y-2 text-sm">
            {v.doesNot.map((line) => (
              <li key={line} className="flex gap-2">
                <X aria-hidden className="mt-0.5 size-4 shrink-0 text-warning" />
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>
      </Panel>

      {created && <NewConnection name={created.name} config={created.config} onDone={() => setCreated(null)} />}

      {status?.enabled && (
        <Panel>
          <PanelHeader title={v.addTitle} description={v.addHint} />
          <form onSubmit={add} className="flex flex-wrap items-end gap-3 p-5">
            <div className="min-w-48 flex-1">
              <Field label={v.name} hint={v.limit(status.max_devices)}>
                {(props) => <Input {...props} required maxLength={80} placeholder={v.namePlaceholder} value={name} onChange={(e) => setName(e.target.value)} />}
              </Field>
            </div>
            <Button type="submit" pending={pending} disabled={!status.server_online || atLimit}>
              <Plus aria-hidden className="size-4" />
              {pending ? v.creating : v.create}
            </Button>
          </form>
        </Panel>
      )}

      {status?.enabled && (
        <Panel>
          <PanelHeader title={v.devices} />
          {status.devices.length === 0 ? (
            <p className="p-5 text-ink-muted">{v.none}</p>
          ) : (
            <ul className="divide-y divide-line" id="vpn-devices">
              {status.devices.map((device) => (
                <li key={device.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
                  <div className="min-w-0">
                    <p className="font-medium text-ink" dir="auto">
                      {device.name} <span className="font-mono text-xs text-ink-faint" dir="ltr">{device.address}</span>
                    </p>
                    <p className="text-sm text-ink-muted">
                      {device.connected ? (
                        <span className="text-clear">{v.connected}</span>
                      ) : device.last_handshake_at ? (
                        v.lastSeen(formatRelative(device.last_handshake_at))
                      ) : (
                        v.never
                      )}
                      {(device.received_bytes > 0 || device.sent_bytes > 0) && ` · ${v.traffic(formatBytes(device.sent_bytes), formatBytes(device.received_bytes))}`}
                    </p>
                    <p className={`text-xs ${device.state === "active" ? "text-ink-faint" : "text-warning"}`}>
                      {device.state === "paused"
                        ? v.pausedNote
                        : device.state === "limit_reached"
                          ? v.limitReached
                          : device.monthly_limit_bytes
                            ? v.monthUsageOf(formatBytes(device.month_bytes), formatBytes(device.monthly_limit_bytes))
                            : v.monthUsage(formatBytes(device.month_bytes))}
                    </p>
                    {device.monthly_limit_bytes ? (
                      <div className="mt-1 h-1.5 w-48 max-w-full overflow-hidden rounded-full bg-surface-sunken">
                        <div
                          className={`h-full rounded-full ${device.state === "limit_reached" ? "bg-danger" : "bg-accent"}`}
                          style={{ width: `${Math.min(100, Math.round((device.month_bytes / device.monthly_limit_bytes) * 100))}%` }}
                        />
                      </div>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                  <label className="flex items-center gap-1.5 text-xs text-ink-muted">
                    {v.limitLabel}
                    <Select
                      className="h-8 w-auto text-xs"
                      value={String(device.monthly_limit_bytes ? Math.round(device.monthly_limit_bytes / 1e9) : 0)}
                      onChange={async (event) => {
                        try {
                          await api.vpn.update(device.id, { monthly_limit_gb: Number(event.target.value) });
                          load();
                        } catch (error) {
                          notify("error", errorText(error));
                        }
                      }}
                    >
                      {LIMIT_CHOICES_GB.map((gb) => (
                        <option key={gb} value={gb}>
                          {gb === 0 ? v.noLimit : `${gb} GB`}
                        </option>
                      ))}
                    </Select>
                  </label>
                  <Button
                    size="sm"
                    variant="secondary"
                    aria-pressed={device.paused}
                    onClick={async () => {
                      try {
                        await api.vpn.update(device.id, { paused: !device.paused });
                        load();
                      } catch (error) {
                        notify("error", errorText(error));
                      }
                    }}
                  >
                    {device.paused ? <Play aria-hidden className="size-4" /> : <Pause aria-hidden className="size-4" />}
                    {device.paused ? v.resume : v.pause}
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    aria-label={`${v.remove}: ${device.name}`}
                    onClick={async () => {
                      if (!window.confirm(v.confirmRemove(device.name))) return;
                      try {
                        await api.vpn.remove(device.id);
                        load();
                      } catch (error) {
                        notify("error", errorText(error));
                      }
                    }}
                  >
                    <Trash2 aria-hidden className="size-4" />
                    {v.remove}
                  </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}
    </div>
  );
}
