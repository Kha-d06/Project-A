"use client";

import { Copy, Link2, Users } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Group, Share } from "@/lib/api/types";
import { formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

const EXPIRY_DAYS = [1, 7, 30, 90];

export function ShareDialog({ scanId, open, onClose }: { scanId: string; open: boolean; onClose: () => void }) {
  const { t } = useI18n();
  const s = t.extra.share;
  const notify = useToast();
  const [includeTarget, setIncludeTarget] = useState(false);
  const [days, setDays] = useState(30);
  const [note, setNote] = useState("");
  const [destination, setDestination] = useState("link");
  const [groups, setGroups] = useState<Group[]>([]);
  const [shares, setShares] = useState<Share[]>([]);
  const [created, setCreated] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (!open) return;
    void api.groups.list().then(setGroups).catch(() => setGroups([]));
    void api.sharing.list(scanId).then(setShares).catch(() => setShares([]));
  }, [open, scanId]);

  const create = async () => {
    setPending(true);
    try {
      const share = await api.sharing.create(scanId, {
        include_target: includeTarget,
        note: note.trim() || undefined,
        expires_in_days: days,
        group_id: destination === "link" ? undefined : destination,
      });
      if (share.url) setCreated(share.url);
      else notify("success", s.sharedWithGroup);
      setShares(await api.sharing.list(scanId));
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : String(error));
    } finally {
      setPending(false);
    }
  };

  const copy = async (url: string) => {
    await navigator.clipboard.writeText(url).catch(() => undefined);
    notify("success", s.copied);
  };

  const revoke = async (id: string) => {
    await api.sharing.revoke(id);
    setShares(await api.sharing.list(scanId));
  };

  return (
    <Dialog open={open} onClose={onClose} title={s.title} description={s.description}>
      <div className="space-y-4">
        <Field label={s.destination}>
          {(props) => (
            <Select {...props} value={destination} onChange={(event) => setDestination(event.target.value)}>
              <option value="link">{s.anyone}</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <label className="flex items-start gap-3 text-sm">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-[var(--accent)]"
            checked={includeTarget}
            onChange={(event) => setIncludeTarget(event.target.checked)}
          />
          <span>
            <span className="font-medium text-ink">{s.includeTarget}</span>
            <span className="block text-xs text-ink-muted">{s.includeTargetHint}</span>
          </span>
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={s.expires}>
            {(props) => (
              <Select {...props} value={days} onChange={(event) => setDays(Number(event.target.value))}>
                {EXPIRY_DAYS.map((n) => (
                  <option key={n} value={n}>
                    {s.days(n)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={s.note}>
            {(props) => (
              <Input {...props} maxLength={300} placeholder={s.notePlaceholder} value={note} onChange={(event) => setNote(event.target.value)} />
            )}
          </Field>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button pending={pending} onClick={create}>
            {destination === "link" ? <Link2 aria-hidden className="size-4" /> : <Users aria-hidden className="size-4" />}
            {destination === "link" ? s.create : s.shareWithGroup}
          </Button>
          <Button variant="secondary" onClick={onClose}>
            {s.close}
          </Button>
        </div>
        {created && (
          <div className="flex items-center gap-2 rounded-control border border-line bg-surface-sunken p-2">
            <code className="min-w-0 flex-1 truncate text-xs" dir="ltr">
              {created}
            </code>
            <Button size="sm" variant="secondary" onClick={() => copy(created)}>
              <Copy aria-hidden className="size-4" />
              {s.copy}
            </Button>
          </div>
        )}
        {shares.length > 0 && (
          <div className="space-y-2 border-t border-line pt-3">
            <p className="text-xs font-semibold tracking-wider text-ink-faint uppercase">{s.existing}</p>
            <ul className="space-y-1.5 text-sm">
              {shares.map((share) => (
                <li key={share.id} className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-ink-muted">
                    {formatShortDate(share.created_at)} · {share.group_id ? s.groupShare : s.views(share.views)}
                    {share.expires_at && ` · ${s.expiresOn(formatShortDate(share.expires_at))}`}
                  </span>
                  {share.revoked_at ? (
                    <span className="text-xs text-ink-faint">{s.revoked}</span>
                  ) : (
                    <button type="button" className="text-xs text-danger hover:underline" onClick={() => revoke(share.id)}>
                      {s.revoke}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Dialog>
  );
}
