"use client";

import { Copy, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { RiskBadge } from "@/components/scan/risk-badge";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { ExtensionEvent, Installation, Profile } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";

const BROWSER_NAMES: Record<string, string> = { chrome: "Chrome", edge: "Microsoft Edge", firefox: "Firefox" };

const EVENT_TEXT: Record<ExtensionEvent["kind"], string> = {
  warning_shown: "Warning shown",
  went_back: "Went back",
  proceeded: "Continued anyway",
  download_warning: "Download paused",
  link_checked: "Link checked",
};

const EVENT_RISK = {
  dangerous: "known_malicious",
  suspicious: "suspicious",
  caution: "suspicious",
  no_known_threat: "no_known_threat",
  unavailable: "inconclusive",
} as const;

function message(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function LinkCodePanel() {
  const notify = useToast();
  const [code, setCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (!code) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [code]);

  const remaining = code ? Math.max(0, Math.round((new Date(code.expires_at).getTime() - now) / 1000)) : 0;

  const create = async () => {
    setPending(true);
    try {
      setCode(await api.extension.createLinkCode());
      setNow(Date.now());
    } catch (error) {
      notify("error", message(error, "A code could not be created."));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title="Link a browser" description="Connect an installed SENTINEL Protect extension to this account." />
      <div className="space-y-4 px-5 py-5 text-sm">
        <ol className="list-decimal space-y-1.5 ps-5 text-ink-muted">
          <li>Create a code below.</li>
          <li>In the extension, open Settings, then SENTINEL account.</li>
          <li>Enter the code. It works once and expires after 10 minutes.</li>
        </ol>
        {code && remaining > 0 ? (
          <div className="flex flex-wrap items-center gap-4">
            <p aria-live="polite" className="font-mono text-2xl font-semibold tracking-[0.2em] text-ink">
              {code.code}
            </p>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => navigator.clipboard.writeText(code.code).then(() => notify("success", "Code copied."))}
            >
              <Copy aria-hidden className="size-4" />
              Copy
            </Button>
            <span className="text-ink-faint">
              Expires in {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, "0")}
            </span>
          </div>
        ) : (
          <Button onClick={create} pending={pending}>
            {code ? "Create a new code" : "Create a link code"}
          </Button>
        )}
      </div>
    </Panel>
  );
}

export function BrowserProtection() {
  const notify = useToast();
  const [installations, setInstallations] = useState<Installation[] | null>(null);
  const [events, setEvents] = useState<ExtensionEvent[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.extension.installations(), api.extension.events(), api.user.profile()]).then(
      ([loadedInstallations, loadedEvents, loadedProfile]) => {
        if (cancelled) return;
        setInstallations(loadedInstallations);
        setEvents(loadedEvents);
        setProfile(loadedProfile);
      },
      (caught: unknown) => !cancelled && setError(message(caught, "Browser protection could not be loaded.")),
    );
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const revoke = async (installation: Installation) => {
    try {
      await api.extension.revoke(installation.id);
      notify("success", "The extension was disconnected. It will stop checking sites until it is connected again.");
      setReloadKey((key) => key + 1);
    } catch (caught) {
      notify("error", message(caught, "The extension could not be disconnected."));
    }
  };

  const toggleSync = async () => {
    if (!profile) return;
    try {
      setProfile(await api.user.updateSettings({ sync_extension_events: !profile.settings.sync_extension_events }));
    } catch (caught) {
      notify("error", message(caught, "The setting could not be changed."));
    }
  };

  const clearEvents = async () => {
    try {
      await api.extension.clearEvents();
      setEvents([]);
      notify("success", "Extension history deleted.");
    } catch (caught) {
      notify("error", message(caught, "The history could not be deleted."));
    }
  };

  const syncing = profile?.settings.sync_extension_events ?? false;

  return (
    <>
      <PageTitle
        title="Browser protection"
        description="SENTINEL Protect checks the sites you open and warns before known dangerous ones load."
      />
      {error && <Alert tone="warning">{error}</Alert>}
      <div className="space-y-6">
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel>
            <PanelHeader title="Connected browsers" />
            {installations === null ? (
              <div className="h-24 animate-pulse" aria-busy />
            ) : installations.length === 0 ? (
              <div className="space-y-2 px-5 py-5 text-sm text-ink-muted">
                <p className="font-medium text-ink">No browser linked to this account</p>
                <p>
                  The extension also works without an account. Linking only adds it to this list and,
                  if you choose, records its warnings here.
                </p>
                <a href="/browser-protection" className="inline-block font-medium text-accent underline underline-offset-4">
                  How to install it
                </a>
              </div>
            ) : (
              <ul className="divide-y divide-line">
                {installations.map((installation) => (
                  <li key={installation.id} className="flex items-center gap-3 px-5 py-3 text-sm">
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-ink">
                        {BROWSER_NAMES[installation.browser] ?? installation.browser} · version {installation.version}
                      </p>
                      <p className="text-ink-faint">Last active {formatRelative(installation.last_seen_at)}</p>
                    </div>
                    <Button variant="danger" size="sm" onClick={() => revoke(installation)}>
                      Disconnect
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <LinkCodePanel />
        </div>

        <Panel>
          <PanelHeader title="Warning history" />
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line px-5 py-4">
            <div className="max-w-xl space-y-1">
              <p id="sync-label" className="font-medium text-ink">Record warnings from linked browsers</p>
              <p className="text-sm text-ink-muted">
                Only the domain, the verdict and what you did are saved, never full addresses or pages
                you visited without a warning. Off by default.
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={syncing}
              aria-labelledby="sync-label"
              disabled={!profile}
              onClick={toggleSync}
              className="relative h-6 w-11 shrink-0 rounded-full border border-line-strong transition-colors aria-checked:border-accent aria-checked:bg-accent disabled:opacity-60"
            >
              <span
                aria-hidden
                className="absolute start-0.5 top-0.5 size-4.5 rounded-full bg-ink-faint transition-transform duration-200 in-aria-checked:translate-x-5 in-aria-checked:bg-accent-ink rtl:in-aria-checked:-translate-x-5"
              />
            </button>
          </div>
          {events.length === 0 ? (
            <p className="px-5 py-5 text-sm text-ink-muted">
              {syncing ? "No warnings recorded yet." : "Nothing is recorded while this is off."}
            </p>
          ) : (
            <>
              <ul className="divide-y divide-line">
                {events.map((event) => (
                  <li key={`${event.host}-${event.created_at}`} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                    <span className="min-w-0 flex-1 truncate font-mono text-[0.8rem] text-ink">{event.host}</span>
                    <span className="text-ink-muted">{EVENT_TEXT[event.kind]}</span>
                    <RiskBadge risk={EVENT_RISK[event.verdict]} status="completed" />
                    <span className="text-xs text-ink-faint">{formatRelative(event.created_at)}</span>
                  </li>
                ))}
              </ul>
              <div className="border-t border-line px-5 py-3">
                <Button variant="ghost" size="sm" onClick={clearEvents}>
                  <Trash2 aria-hidden className="size-4" />
                  Delete warning history
                </Button>
              </div>
            </>
          )}
        </Panel>
      </div>
    </>
  );
}
