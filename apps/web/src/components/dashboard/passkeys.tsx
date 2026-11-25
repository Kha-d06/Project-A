"use client";

import { useEffect, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Passkey } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";
import { creationOptions, credentialJson, usePasskeysSupported } from "@/lib/passkeys";

/** Account passkeys: add (the browser creates the key), list, and remove with the password. */
export function PasskeysSection() {
  const notify = useToast();
  const { t } = useI18n();
  const a = t.account;
  const [items, setItems] = useState<Passkey[] | null>(null);
  const [name, setName] = useState("");
  const [pending, setPending] = useState(false);
  const [removing, setRemoving] = useState<Passkey | null>(null);
  const [password, setPassword] = useState("");
  const supported = usePasskeysSupported();

  const reload = () => api.user.passkeys().then(setItems, () => setItems([]));
  useEffect(() => {
    void reload();
  }, []);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const { challenge_id, options } = await api.user.passkeyOptions();
      const credential = (await navigator.credentials.create({ publicKey: creationOptions(options) })) as PublicKeyCredential | null;
      if (!credential) return;
      await api.user.addPasskey(challenge_id, credentialJson(credential), name.trim() || a.passkeyNamePlaceholder);
      setName("");
      notify("success", a.passkeyAdded);
      await reload();
    } catch (error) {
      // The person cancelling the browser's prompt isn't an error worth shouting about.
      if (!(error instanceof DOMException && error.name === "NotAllowedError")) notify("error", error instanceof ApiError ? error.message : a.failed);
    } finally {
      setPending(false);
    }
  };

  const remove = async () => {
    if (!removing) return;
    setPending(true);
    try {
      await api.user.removePasskey(removing.id, password);
      setRemoving(null);
      setPassword("");
      await reload();
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : a.failed);
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title={a.passkeys} description={a.passkeysExplain} />
      <div className="divide-y divide-line">
        {items?.length === 0 && <p className="px-5 py-4 text-sm text-ink-muted">{a.passkeysNone}</p>}
        {items?.map((p) => (
          <div key={p.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 text-sm">
            <div>
              <p className="font-medium text-ink">{p.name}</p>
              <p className="text-ink-faint">
                {p.backed_up ? a.passkeySynced : a.passkeyThisDevice} · {p.last_used_at ? `${a.passkeyLastUsed} ${formatRelative(p.last_used_at)}` : a.passkeyNeverUsed}
              </p>
            </div>
            <Button size="sm" variant="danger" aria-label={`${a.removePasskey}: ${p.name}`} onClick={() => setRemoving(p)}>
              {a.removePasskey}
            </Button>
          </div>
        ))}
        <form onSubmit={add} className="flex flex-wrap items-end gap-3 px-5 py-4">
          {supported ? (
            <>
              <Field label={a.passkeyName}>
                {(props) => <Input {...props} value={name} maxLength={60} placeholder={a.passkeyNamePlaceholder} onChange={(event) => setName(event.target.value)} className="w-56" />}
              </Field>
              <Button type="submit" size="sm" pending={pending}>
                {a.addPasskey}
              </Button>
            </>
          ) : (
            <p className="text-sm text-ink-muted">{a.passkeysUnsupported}</p>
          )}
        </form>
      </div>
      <Dialog open={removing !== null} onClose={() => setRemoving(null)} title={a.removePasskeyTitle} description={a.removePasskeyBody}>
        <Field label={t.auth.password}>
          {(props) => <Input {...props} type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />}
        </Field>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={() => setRemoving(null)}>
            {t.common.cancel}
          </Button>
          <Button variant="danger" size="sm" pending={pending} disabled={!password} onClick={() => void remove()}>
            {a.removePasskey}
          </Button>
        </div>
      </Dialog>
    </Panel>
  );
}
