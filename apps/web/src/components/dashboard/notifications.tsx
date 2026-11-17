"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Profile } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";

function Switch({ checked, label, onChange, disabled }: { checked: boolean; label: string; onChange: () => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={onChange}
      className="relative h-6 w-11 shrink-0 rounded-full border border-line-strong transition-colors aria-checked:border-accent aria-checked:bg-accent disabled:opacity-60"
    >
      <span
        aria-hidden
        className="absolute top-0.5 start-0.5 size-4.5 rounded-full bg-ink-faint transition-transform duration-200 in-aria-checked:translate-x-5 in-aria-checked:bg-accent-ink rtl:in-aria-checked:-translate-x-5"
      />
    </button>
  );
}

/** VAPID keys are URL-safe base64; PushManager wants the raw bytes. */
function keyBytes(base64: string): Uint8Array<ArrayBuffer> {
  const padded = (base64 + "=".repeat((4 - (base64.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

type PushState = "unknown" | "unsupported" | "unavailable" | "blocked" | "on" | "off";

export function NotificationsSection({ profile, onSaved }: { profile: Profile; onSaved: (profile: Profile) => void }) {
  const { t } = useI18n();
  const n = t.extra.notifications;
  const notify = useToast();
  const [push, setPush] = useState<PushState>("unknown");
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    (async () => {
      if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
        setPush("unsupported");
        return;
      }
      const { public_key } = await api.push.key().catch(() => ({ public_key: null }));
      setPublicKey(public_key);
      if (!public_key) return setPush("unavailable");
      if (Notification.permission === "denied") return setPush("blocked");
      const registration = await navigator.serviceWorker.getRegistration();
      const subscription = await registration?.pushManager.getSubscription();
      setPush(subscription ? "on" : "off");
    })();
  }, []);

  const toggleSetting = async (key: "weekly_summary" | "breach_monitoring") => {
    try {
      onSaved(await api.user.updateSettings({ [key]: !profile.settings[key] }));
      notify("success", n.saved);
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : String(error));
    }
  };

  const togglePush = async () => {
    setPending(true);
    try {
      const registration = await navigator.serviceWorker.ready;
      if (push === "on") {
        const subscription = await registration.pushManager.getSubscription();
        if (subscription) {
          await api.push.unsubscribe(subscription.endpoint);
          await subscription.unsubscribe();
        }
        setPush("off");
        notify("success", n.pushDisabled);
        return;
      }
      if ((await Notification.requestPermission()) !== "granted") {
        setPush("blocked");
        return;
      }
      const subscription = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(publicKey!) });
      await api.push.subscribe(subscription.toJSON());
      setPush("on");
      notify("success", n.pushEnabled);
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : String(error));
    } finally {
      setPending(false);
    }
  };

  const pushNote = { unsupported: n.pushUnsupported, unavailable: n.pushUnavailable, blocked: n.pushBlocked }[push as "unsupported"];

  return (
    <Panel>
      <PanelHeader title={n.title} />
      <div className="divide-y divide-line">
        {(
          [
            ["weekly_summary", n.weekly, n.weeklyHint],
            ["breach_monitoring", n.breach, n.breachHint],
          ] as const
        ).map(([key, label, hint]) => (
          <div key={key} className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
            <div className="max-w-lg space-y-1">
              <p className="font-medium text-ink">{label}</p>
              <p className="text-sm text-ink-muted">{hint}</p>
            </div>
            <Switch checked={Boolean(profile.settings[key])} label={label} onChange={() => toggleSetting(key)} />
          </div>
        ))}
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div className="max-w-lg space-y-1">
            <p className="font-medium text-ink">{n.push}</p>
            <p className="text-sm text-ink-muted">{pushNote ?? n.pushHint}</p>
          </div>
          {(push === "on" || push === "off") && (
            <div className="flex gap-2">
              {push === "on" && (
                <Button variant="secondary" size="sm" onClick={() => api.push.test().catch(() => undefined)}>
                  {n.pushTest}
                </Button>
              )}
              <Button variant={push === "on" ? "secondary" : "primary"} size="sm" pending={pending} onClick={togglePush}>
                {push === "on" ? n.pushOff : n.pushOn}
              </Button>
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}
