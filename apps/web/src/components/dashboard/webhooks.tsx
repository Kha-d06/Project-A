"use client";

import { useEffect, useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Webhook, WebhookEvent } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

export function WebhooksSection() {
  const { t } = useI18n();
  const w = t.extra.webhooks;
  const notify = useToast();
  const [hooks, setHooks] = useState<Webhook[] | null>(null);
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<WebhookEvent[]>(["scan.dangerous"]);
  const [secret, setSecret] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const load = () => api.webhooks.list().then(setHooks, () => setHooks([]));
  useEffect(() => {
    void load();
  }, []);

  const toggle = (event: WebhookEvent, on: boolean) =>
    setEvents((current) => (on ? [...new Set([...current, event])] : current.filter((e) => e !== event)));

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const created = await api.webhooks.create(url.trim(), events);
      setSecret(created.secret ?? null);
      setUrl("");
      await load();
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : String(error));
    } finally {
      setPending(false);
    }
  };

  const act = async (action: () => Promise<unknown>) => {
    try {
      await action();
      await load();
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : String(error));
    }
  };

  return (
    <Panel>
      <PanelHeader title={w.title} description={w.description} />
      <div className="space-y-4 px-5 py-5">
        {secret && (
          <Alert tone="warning" title={w.secretOnce}>
            <code className="font-mono text-xs break-all" dir="ltr">{secret}</code>
          </Alert>
        )}
        <form onSubmit={create} className="space-y-3">
          <Field label={w.url}>
            {(props) => (
              <Input {...props} type="url" required dir="ltr" placeholder="https://hooks.example.com/sentinel" value={url} onChange={(event) => setUrl(event.target.value)} />
            )}
          </Field>
          <fieldset className="space-y-1.5 text-sm">
            <legend className="mb-1 font-medium text-ink">{w.events}</legend>
            {(["scan.dangerous", "scan.completed"] as const).map((name) => (
              <label key={name} className="flex items-center gap-2">
                <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={events.includes(name)} onChange={(event) => toggle(name, event.target.checked)} />
                {name === "scan.dangerous" ? w.dangerous : w.completed}
              </label>
            ))}
          </fieldset>
          <Button type="submit" variant="secondary" pending={pending} disabled={!url.trim() || events.length === 0}>
            {w.add}
          </Button>
        </form>
        {hooks?.length === 0 && <p className="text-sm text-ink-muted">{w.none}</p>}
        <ul className="divide-y divide-line">
          {hooks?.map((hook) => (
            <li key={hook.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
              <code className="min-w-0 flex-1 truncate font-mono text-xs text-ink" dir="ltr">{hook.url}</code>
              <span className="text-xs text-ink-faint">
                {hook.active ? w.active : w.paused} ·{" "}
                {hook.last_status && hook.last_delivery_at ? w.lastDelivery(hook.last_status, formatRelative(hook.last_delivery_at)) : w.never}
              </span>
              <Button size="sm" variant="secondary" onClick={() => act(() => api.webhooks.setActive(hook.id, !hook.active))}>
                {hook.active ? w.pause : w.resume}
              </Button>
              <Button size="sm" variant="danger" onClick={() => act(() => api.webhooks.remove(hook.id))}>
                {w.remove}
              </Button>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}
