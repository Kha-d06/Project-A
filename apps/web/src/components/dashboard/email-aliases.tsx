"use client";

import { Copy } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { AliasList, EmailAlias } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

/** Disposable email aliases: create (random or chosen), copy, pause/resume, delete. */
export function EmailAliases() {
  const notify = useToast();
  const { t } = useI18n();
  const p = t.extra.privacy;
  const [data, setData] = useState<AliasList | null>(null);
  const [label, setLabel] = useState("");
  const [local, setLocal] = useState("");
  const [domain, setDomain] = useState("");
  const [pending, setPending] = useState(false);
  const [removing, setRemoving] = useState<EmailAlias | null>(null);

  const reload = () =>
    api.aliases.list().then(setData, () => setData({ aliases: [], domains: [], forwards_to: null }));
  useEffect(() => {
    void reload();
  }, []);

  const fail = (error: unknown) => notify("error", error instanceof ApiError ? error.message : p.failed);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const alias = await api.aliases.create({
        domain: domain || undefined,
        local_part: local.trim() || undefined,
        label: label.trim() || undefined,
      });
      setLabel("");
      setLocal("");
      notify("success", p.created(alias.address));
      await reload();
    } catch (error) {
      fail(error);
    } finally {
      setPending(false);
    }
  };

  const togglePause = async (alias: EmailAlias) => {
    try {
      await api.aliases.update(alias.id, { paused: !alias.paused });
      await reload();
    } catch (error) {
      fail(error);
    }
  };

  const remove = async () => {
    if (!removing) return;
    setPending(true);
    try {
      await api.aliases.remove(removing.id);
      setRemoving(null);
      await reload();
    } catch (error) {
      fail(error);
    } finally {
      setPending(false);
    }
  };

  const copy = async (address: string) => {
    try {
      await navigator.clipboard.writeText(address);
      notify("success", p.copied);
    } catch {
      notify("error", p.failed);
    }
  };

  const canCreate = data !== null && data.forwards_to !== null && data.domains.length > 0;

  return (
    <Panel>
      <PanelHeader title={p.aliases} description={data?.forwards_to ? `${p.aliasesExplain} ${p.forwardsTo(data.forwards_to)}.` : p.aliasesExplain} />
      <div className="divide-y divide-line">
        {data?.aliases.length === 0 && <p className="px-5 py-4 text-sm text-ink-muted">{p.none}</p>}
        {data?.aliases.map((a) => (
          <div key={a.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 text-sm">
            <div className="min-w-0">
              <p className="font-mono break-all text-ink" dir="ltr">
                {a.address}
                {a.paused && <span className="ms-2 rounded bg-surface-sunken px-1.5 py-0.5 font-sans text-xs text-ink-muted">{p.paused}</span>}
              </p>
              <p className="text-ink-faint">
                {a.label ? `${a.label} · ` : ""}
                {p.counts(a.forwarded_count, a.blocked_count)}
                {a.last_forwarded_at ? ` · ${p.lastForwarded} ${formatRelative(a.last_forwarded_at)}` : ""}
              </p>
            </div>
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" aria-label={`${p.copy}: ${a.address}`} onClick={() => void copy(a.address)}>
                <Copy className="size-4" aria-hidden /> {p.copy}
              </Button>
              <Button size="sm" variant="secondary" aria-label={`${a.paused ? p.resume : p.pause}: ${a.address}`} onClick={() => void togglePause(a)}>
                {a.paused ? p.resume : p.pause}
              </Button>
              <Button size="sm" variant="danger" aria-label={`${p.remove}: ${a.address}`} onClick={() => setRemoving(a)}>
                {p.remove}
              </Button>
            </div>
          </div>
        ))}
        {data && data.forwards_to === null && <p className="px-5 py-4 text-sm text-ink-muted">{p.verifyFirst}</p>}
        {data && data.forwards_to !== null && data.domains.length === 0 && <p className="px-5 py-4 text-sm text-ink-muted">{p.noDomain}</p>}
        {canCreate && (
          <form onSubmit={create} className="flex flex-wrap items-end gap-3 px-5 py-4">
            <Field label={p.label}>
              {(props) => <Input {...props} value={label} maxLength={120} placeholder={p.labelPlaceholder} onChange={(e) => setLabel(e.target.value)} className="w-52" />}
            </Field>
            <Field label={p.localPart} hint={p.localPartHint}>
              {(props) => <Input {...props} value={local} maxLength={32} dir="ltr" onChange={(e) => setLocal(e.target.value.toLowerCase())} className="w-44" />}
            </Field>
            {data.domains.length > 1 && (
              <Field label={p.domain}>
                {(props) => (
                  <Select {...props} value={domain || data.domains[0]} onChange={(e) => setDomain(e.target.value)}>
                    {data.domains.map((d) => (
                      <option key={d} value={d}>
                        @{d}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            )}
            <Button type="submit" size="sm" pending={pending}>
              {p.create}
            </Button>
          </form>
        )}
      </div>
      <Dialog open={removing !== null} onClose={() => setRemoving(null)} title={p.removeTitle} description={removing ? p.removeBody(removing.address) : undefined}>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={() => setRemoving(null)}>
            {t.common.cancel}
          </Button>
          <Button variant="danger" size="sm" pending={pending} onClick={() => void remove()}>
            {p.remove}
          </Button>
        </div>
      </Dialog>
    </Panel>
  );
}
