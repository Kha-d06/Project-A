"use client";

import { Check, Mail, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { IdentityStatus, MonitoredIdentity } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

function message(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : String(error);
}

function IdentityRow({ item, onChange }: { item: MonitoredIdentity; onChange: () => void }) {
  const s = useI18n().t.extra.identity;
  const notify = useToast();
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);

  const confirm = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      await api.identity.verify(item.id, code);
      setCode("");
      onChange();
    } catch (error) {
      notify("error", message(error));
    } finally {
      setPending(false);
    }
  };

  return (
    <li className="space-y-2 px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2 font-medium text-ink" dir="ltr">
          <Mail aria-hidden className="size-4 text-ink-faint" />
          {item.email}
        </span>
        <span className="flex items-center gap-3 text-sm">
          {!item.verified ? (
            <span className="text-warning">{s.waiting}</span>
          ) : item.breaches.length ? (
            <span className="text-danger">{s.breaches(item.breaches.length)}</span>
          ) : (
            <span className="inline-flex items-center gap-1 text-clear">
              <Check aria-hidden className="size-4" />
              {s.clean}
            </span>
          )}
          <button
            type="button"
            className="inline-flex items-center gap-1 text-danger hover:underline"
            onClick={async () => {
              try {
                await api.identity.remove(item.id);
                onChange();
              } catch (error) {
                notify("error", message(error));
              }
            }}
          >
            <Trash2 aria-hidden className="size-4" />
            {s.remove}
          </button>
        </span>
      </div>
      {!item.verified && (
        <form onSubmit={confirm} className="flex flex-wrap items-end gap-2">
          <p className="w-full text-sm text-ink-muted">{s.codeSent(item.email)}</p>
          <div className="w-36">
            <Field label={s.code}>
              {(props) => (
                <Input {...props} inputMode="numeric" autoComplete="one-time-code" dir="ltr" value={code} onChange={(e) => setCode(e.target.value)} />
              )}
            </Field>
          </div>
          <Button type="submit" pending={pending} disabled={code.trim().length < 6}>
            {s.confirm}
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={async () => {
              try {
                await api.identity.resend(item.id);
                notify("success", s.codeSent(item.email));
              } catch (error) {
                notify("error", message(error));
              }
            }}
          >
            {s.resend}
          </Button>
        </form>
      )}
      {item.verified && item.breaches.length > 0 && (
        <ul className="space-y-1 text-sm">
          {item.breaches.map((breach) => (
            <li key={breach.name} className="text-ink">
              <span className="font-medium">{breach.title}</span>
              {breach.breach_date && <span className="text-ink-faint"> · {breach.breach_date}</span>}
              {breach.data_classes.length > 0 && <span className="block text-xs text-ink-muted">{breach.data_classes.join(", ")}</span>}
            </li>
          ))}
        </ul>
      )}
      {item.last_checked_at && <p className="text-xs text-ink-faint">{s.checked(formatRelative(item.last_checked_at))}</p>}
    </li>
  );
}

/** Extra email addresses watched for breaches, each confirmed by its owner. */
export function IdentityMonitoring() {
  const s = useI18n().t.extra.identity;
  const notify = useToast();
  const [status, setStatus] = useState<IdentityStatus | null>(null);
  const [email, setEmail] = useState("");
  const [pending, setPending] = useState(false);

  const load = useCallback(() => {
    api.identity
      .status()
      .then(setStatus)
      .catch(() => undefined);
  }, []);
  useEffect(load, [load]);

  if (!status) return null;
  const full = status.identities.length >= status.max_identities;

  const add = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      await api.identity.add(email.trim());
      setEmail("");
      load();
    } catch (error) {
      notify("error", message(error));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title={s.title} description={s.description} />
      {!status.available && <div className="px-5 pt-4"><Alert tone="info">{s.unavailable}</Alert></div>}
      {status.available && !status.email_available && <div className="px-5 pt-4"><Alert tone="info">{s.noEmail}</Alert></div>}
      {status.available && status.email_available && (
        <form onSubmit={add} className="flex flex-wrap items-end gap-3 p-5" id="identity-add">
          <div className="min-w-56 flex-1">
            <Field label={s.add}>
              {(props) => (
                <Input {...props} type="email" dir="ltr" required placeholder={s.placeholder} value={email} onChange={(e) => setEmail(e.target.value)} />
              )}
            </Field>
          </div>
          <Button type="submit" pending={pending} disabled={full}>
            {s.add}
          </Button>
        </form>
      )}
      {status.identities.length > 0 && (
        <ul className="divide-y divide-line border-t border-line" id="identities">
          {status.identities.map((item) => (
            <IdentityRow key={item.id} item={item} onChange={load} />
          ))}
        </ul>
      )}
    </Panel>
  );
}
