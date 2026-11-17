"use client";

import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { Panel } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { ModerationItem, ReportStatus } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";
import { formatDateTime } from "@/lib/format";

function ReviewControls({ item, onDone }: { item: ModerationItem; onDone: () => void }) {
  const { t } = useI18n();
  const s = t.extra.staff;
  const notify = useToast();
  const [note, setNote] = useState("");
  const [duplicateOf, setDuplicateOf] = useState("");
  const [pending, setPending] = useState<string | null>(null);

  const decide = async (status: "verified" | "rejected" | "duplicate") => {
    setPending(status);
    try {
      await api.moderation.review(item.id, {
        status,
        note: note || undefined,
        duplicate_of: status === "duplicate" ? duplicateOf.trim() : undefined,
      });
      notify("success", s.marked(t.community.statuses[status].label));
      onDone();
    } catch (caught) {
      notify("error", caught instanceof ApiError ? caught.message : s.reviewFailed);
    } finally {
      setPending(null);
    }
  };

  return (
    <div className="space-y-3 border-t border-line pt-4">
      <Input value={note} onChange={(event) => setNote(event.target.value)} placeholder={s.note} aria-label={s.noteLabel} maxLength={1000} />
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" pending={pending === "verified"} onClick={() => decide("verified")}>
          {s.verify}
        </Button>
        <Button size="sm" variant="secondary" pending={pending === "rejected"} onClick={() => decide("rejected")}>
          {s.reject}
        </Button>
        <Input
          value={duplicateOf}
          onChange={(event) => setDuplicateOf(event.target.value)}
          placeholder={s.originalId}
          aria-label={s.originalLabel}
          className="h-8 w-64 font-mono text-xs"
        />
        <Button size="sm" variant="ghost" disabled={!duplicateOf.trim()} pending={pending === "duplicate"} onClick={() => decide("duplicate")}>
          {s.markDuplicate}
        </Button>
      </div>
      <p className="text-xs text-ink-faint">
        {s.verifyHint}
      </p>
    </div>
  );
}

export function Moderation() {
  const { t } = useI18n();
  const s = t.extra.staff;
  const [status, setStatus] = useState<ReportStatus>("pending");
  const [sort, setSort] = useState<"oldest" | "reputation">("oldest");
  const [items, setItems] = useState<ModerationItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    api.moderation.queue(status, sort).then(
      (loaded) => !cancelled && setItems(loaded),
      (caught: unknown) => !cancelled && setError(caught instanceof ApiError ? caught.message : s.queueFailed),
    );
    return () => {
      cancelled = true;
    };
  }, [status, sort, reloadKey, s.queueFailed]);

  return (
    <>
      <PageTitle
        title={s.moderation}
        description={s.moderationHint}
        action={
          <div className="flex flex-wrap gap-3">
          <label className="flex items-center gap-2 text-sm text-ink-muted">
            {s.order}
            <Select value={sort} onChange={(event) => setSort(event.target.value as "oldest" | "reputation")}>
              <option value="oldest">{t.extra.moderation.sortOldest}</option>
              <option value="reputation">{t.extra.moderation.sortReputation}</option>
            </Select>
          </label>
          <label className="flex items-center gap-2 text-sm text-ink-muted">
            {s.show}
            <Select value={status} onChange={(event) => setStatus(event.target.value as ReportStatus)}>
              {Object.entries(t.community.statuses).map(([value, item]) => (
                <option key={value} value={value}>
                  {item.label}
                </option>
              ))}
            </Select>
          </label>
          </div>
        }
      />
      {error && <Alert tone="warning">{error}</Alert>}
      {items?.length === 0 && <Panel className="px-6 py-10 text-center text-sm text-ink-muted">{s.empty}</Panel>}
      <div className="space-y-4">
        {items?.map((item) => (
          <Panel key={item.id} className="space-y-3 p-5">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-ink-muted">
              <span>
                {t.community.categories[item.category].label} · {formatDateTime(item.created_at)} ·{" "}
                {t.extra.moderation.reputation[item.reporter_reputation.level]}
                {!item.anonymous && ` (${t.extra.moderation.history(item.reporter_reputation.verified, item.reporter_reputation.rejected)})`}
                {item.verification_expires_at && ` · ${t.extra.moderation.expires(formatDateTime(item.verification_expires_at))}`}
              </span>
              <span>
                {s.similar(item.similar_reports)}
              </span>
            </div>
            <p className="font-mono text-sm break-all text-ink" dir="auto">{item.subject}</p>
            <p className="text-sm whitespace-pre-line text-ink" dir="auto">{item.description}</p>
            {item.evidence && (
              <pre
                tabIndex={0}
                aria-label={s.evidence}
                className="max-h-60 overflow-auto rounded-control bg-surface-sunken p-3 font-mono text-xs whitespace-pre-wrap text-ink" dir="auto">
                {item.evidence}
              </pre>
            )}
            <p className="font-mono text-xs text-ink-faint">ID {item.id}</p>
            {status === "pending" ? (
              <ReviewControls item={item} onDone={() => setReloadKey((key) => key + 1)} />
            ) : (
              item.moderator_note && <p className="text-sm text-ink-muted">Note: {item.moderator_note}</p>
            )}
          </Panel>
        ))}
      </div>
    </>
  );
}
