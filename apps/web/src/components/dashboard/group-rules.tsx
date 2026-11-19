"use client";

import { Check, X } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/field";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Group, GroupCompliance, GroupPolicies } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

const DAY_CHOICES = [0, 3, 7, 14, 30];
const MINUTE_CHOICES = [0, 30, 60, 90, 120, 180, 240];

function Compliance({ groupId }: { groupId: string }) {
  const r = useI18n().t.extra.rules;
  const [data, setData] = useState<GroupCompliance | null>(null);
  useEffect(() => {
    api.groups
      .compliance(groupId)
      .then(setData)
      .catch(() => undefined);
  }, [groupId]);
  if (!data) return null;
  return (
    <div className="space-y-2" id="group-compliance">
      <p className="text-sm font-semibold text-ink">{r.compliance}</p>
      <p className="text-xs text-ink-muted">{r.complianceSummary(data.compliant, data.sharing)}</p>
      <p className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <a className="text-accent underline-offset-2 hover:underline" href={`/api/v1/groups/${encodeURIComponent(groupId)}/compliance/export`} download>
          {r.exportCsv}
        </a>
        <a className="text-accent underline-offset-2 hover:underline" href={`/api/v1/groups/${encodeURIComponent(groupId)}/compliance/export?format=html`} target="_blank" rel="noopener">
          {r.exportReport}
        </a>
      </p>
      <ul className="divide-y divide-line text-sm">
        {data.members.map((member) => (
          <li key={member.user_id} className="flex flex-wrap items-start justify-between gap-2 py-2">
            <span className="min-w-0">
              <span className="block truncate text-ink">{member.display_name ?? member.email}</span>
              {member.shared && member.last_device_scan && (
                <span className="block text-xs text-ink-faint">{formatRelative(member.last_device_scan)}</span>
              )}
            </span>
            {!member.shared ? (
              <span className="text-xs text-ink-faint">{r.notShared}</span>
            ) : member.problems.length === 0 ? (
              <span className="inline-flex items-center gap-1 text-xs text-clear">
                <Check aria-hidden className="size-3.5" />
                {r.ok}
              </span>
            ) : (
              <span className="flex flex-wrap justify-end gap-1">
                {member.problems.map((problem) => (
                  <span key={problem} className="inline-flex items-center gap-1 rounded-full border border-warning bg-warning-soft px-2 py-0.5 text-xs text-warning">
                    <X aria-hidden className="size-3" />
                    {r.problems[problem] ?? problem}
                  </span>
                ))}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** A group's rules: SafeSearch, locked protection and browsing time for families, security
 * requirements and a compliance view for organisations. */
export function GroupRules({ group, manager, onChange }: { group: Group; manager: boolean; onChange: (group: Group) => void }) {
  const r = useI18n().t.extra.rules;
  const notify = useToast();
  const [rules, setRules] = useState<GroupPolicies>(group.policies ?? {});
  const [pending, setPending] = useState(false);
  const family = group.kind === "family";
  const flags: [keyof GroupPolicies, string][] = family
    ? [
        ["safe_search", r.safeSearch],
        ["lock_protection", r.lockProtection],
      ]
    : [
        ["require_2fa", r.require2fa],
        ["require_extension", r.requireExtension],
      ];

  const save = async () => {
    setPending(true);
    try {
      const saved = await api.groups.setPolicies(group.id, {
        ...Object.fromEntries(flags.map(([key]) => [key, Boolean(rules[key])])),
        ...(family
          ? {
              daily_minutes: rules.daily_minutes ?? 0,
              ...(rules.allowed_from && rules.allowed_until ? { allowed_from: rules.allowed_from, allowed_until: rules.allowed_until } : {}),
            }
          : { max_days_since_scan: rules.max_days_since_scan ?? 0 }),
      });
      setRules(saved.policies ?? {});
      onChange(saved);
      notify("success", r.saved);
    } catch (error) {
      notify("error", error instanceof ApiError ? error.message : String(error));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-3 rounded-control border border-line p-3" id={`group-rules-${group.id}`}>
      <p className="text-sm font-semibold text-ink">{r.title}</p>
      <p className="text-xs text-ink-muted">{family ? r.familyIntro : r.orgIntro}</p>
      <ul className="space-y-2 text-sm">
        {flags.map(([key, label]) => (
          <li key={key}>
            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                className="mt-1 size-4 accent-[var(--accent)]"
                checked={Boolean(rules[key])}
                disabled={!manager}
                onChange={(event) => setRules({ ...rules, [key]: event.target.checked })}
              />
              <span className="text-ink">{label}</span>
            </label>
          </li>
        ))}
        {!family && (
          <li>
            <label className="flex flex-wrap items-center gap-2">
              <span className="text-ink">{r.maxDays}</span>
              <Select
                className="h-8 w-auto text-xs"
                value={String(rules.max_days_since_scan ?? 0)}
                disabled={!manager}
                onChange={(event) => setRules({ ...rules, max_days_since_scan: Number(event.target.value) })}
              >
                {DAY_CHOICES.map((days) => (
                  <option key={days} value={days}>
                    {r.days(days)}
                  </option>
                ))}
              </Select>
            </label>
          </li>
        )}
      </ul>
      {family && (
        <fieldset className="space-y-2 border-t border-line pt-3 text-sm">
          <legend className="sr-only">{r.screenTimeTitle}</legend>
          <p className="font-semibold text-ink" aria-hidden>
            {r.screenTimeTitle}
          </p>
          <p className="text-xs text-ink-muted">{r.screenTimeIntro}</p>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-ink">{r.allowedHours}</span>
            <label className="flex items-center gap-1 text-xs text-ink-muted">
              {r.from}
              <input
                type="time"
                className="h-8 rounded-control border border-line bg-surface px-2 text-xs text-ink"
                value={rules.allowed_from ?? ""}
                disabled={!manager}
                onChange={(event) => setRules({ ...rules, allowed_from: event.target.value || undefined })}
              />
            </label>
            <label className="flex items-center gap-1 text-xs text-ink-muted">
              {r.until}
              <input
                type="time"
                className="h-8 rounded-control border border-line bg-surface px-2 text-xs text-ink"
                value={rules.allowed_until ?? ""}
                disabled={!manager}
                onChange={(event) => setRules({ ...rules, allowed_until: event.target.value || undefined })}
              />
            </label>
            {!rules.allowed_from && !rules.allowed_until && <span className="text-xs text-ink-faint">{r.anyTime}</span>}
          </div>
          <label className="flex flex-wrap items-center gap-2">
            <span className="text-ink">{r.dailyLimit}</span>
            <Select
              className="h-8 w-auto text-xs"
              value={String(rules.daily_minutes ?? 0)}
              disabled={!manager}
              onChange={(event) => setRules({ ...rules, daily_minutes: Number(event.target.value) })}
            >
              {[...new Set([...MINUTE_CHOICES, rules.daily_minutes ?? 0])]
                .sort((a, b) => a - b)
                .map((minutes) => (
                  <option key={minutes} value={minutes}>
                    {r.minutes(minutes)}
                  </option>
                ))}
            </Select>
          </label>
        </fieldset>
      )}
      {manager && (
        <Button size="sm" variant="secondary" pending={pending} onClick={save}>
          {r.save}
        </Button>
      )}
      {manager && !family && <Compliance key={JSON.stringify(group.policies)} groupId={group.id} />}
    </div>
  );
}
