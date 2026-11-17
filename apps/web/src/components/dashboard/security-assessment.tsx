"use client";

import { Check, ChevronDown, Copy, FileText, Globe, Plus, ShieldAlert, Trash2, X } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type {
  AssessedDomain,
  AssessmentDetail,
  AssessmentSchedule,
  AssessmentStatus,
  AssessmentSummary,
  VerificationInstructions,
} from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

function useAssessText() {
  return useI18n().t.extra.assess;
}

function errorText(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : String(error);
}

export const SEVERITY_TONE: Record<string, string> = {
  critical: "border-danger bg-danger-soft text-danger",
  high: "border-danger bg-danger-soft text-danger",
  medium: "border-warning bg-warning-soft text-warning",
  low: "border-line bg-surface-sunken text-ink",
  info: "border-line bg-surface-sunken text-ink-muted",
};

export const RESULT_TONE: Record<string, string> = {
  critical: "text-danger",
  high: "text-danger",
  medium: "text-warning",
  low: "text-warning",
  no_issues: "text-clear",
  inconclusive: "text-ink-muted",
};

function CopyField({ label, value }: { label: string; value: string }) {
  const a = useAssessText();
  const notify = useToast();
  return (
    <div className="min-w-0 space-y-1">
      <p className="text-xs font-medium text-ink-muted">{label}</p>
      <div className="flex items-stretch gap-2">
        <code className="min-w-0 flex-1 overflow-x-auto rounded-control border border-line bg-surface-sunken px-2 py-1.5 font-mono text-xs text-ink" dir="ltr">
          {value}
        </code>
        <Button
          size="sm"
          variant="secondary"
          aria-label={`${a.copy}: ${label}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              notify("success", a.copied);
            } catch {
              notify("error", errorText("clipboard"));
            }
          }}
        >
          <Copy aria-hidden className="size-4" />
        </Button>
      </div>
    </div>
  );
}

function Verification({ instructions, onVerified }: { instructions: VerificationInstructions; onVerified: () => void }) {
  const a = useAssessText();
  const notify = useToast();
  const [pending, setPending] = useState(false);
  const domain = instructions.domain.domain;
  return (
    <div className="space-y-4 rounded-control border border-line p-4">
      <p className="font-medium text-ink">{a.verifyTitle(domain)}</p>
      <p className="text-sm text-ink-muted">{a.verifyIntro}</p>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="min-w-0 space-y-2">
          <p className="text-sm font-semibold text-ink">{a.methodDns}</p>
          <p className="text-xs text-ink-muted">{a.methodDnsHow}</p>
          <CopyField label={a.recordType} value={instructions.dns_type} />
          <CopyField label={a.recordName} value={instructions.dns_name} />
          <CopyField label={a.recordValue} value={instructions.dns_value} />
        </div>
        <div className="min-w-0 space-y-2">
          <p className="text-sm font-semibold text-ink">{a.methodFile}</p>
          <p className="text-xs text-ink-muted">{a.methodFileHow}</p>
          <CopyField label={a.fileUrl} value={instructions.file_url} />
          <CopyField label={a.fileContent} value={instructions.file_content} />
        </div>
      </div>
      <Button
        pending={pending}
        onClick={async () => {
          setPending(true);
          try {
            const result = await api.assess.verify(instructions.domain.id);
            if (result.verified) {
              notify("success", a.verifiedOk);
              onVerified();
            }
          } catch (error) {
            notify("error", error instanceof ApiError ? error.message : a.verifyFailed);
          } finally {
            setPending(false);
          }
        }}
      >
        {pending ? a.verifying : a.verify}
      </Button>
    </div>
  );
}

export function Findings({ detail }: { detail: AssessmentDetail }) {
  const a = useAssessText();
  return (
    <div className="space-y-3">
      {detail.error && <Alert tone="warning">{detail.error}</Alert>}
      {detail.summary && <p className="text-sm text-ink">{detail.summary}</p>}
      <ul className="space-y-2">
        {detail.findings.map((finding, index) => (
          <li key={index} className={`rounded-control border p-3 ${SEVERITY_TONE[finding.severity] ?? SEVERITY_TONE.info}`}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-current px-2 py-0.5 text-xs font-semibold uppercase">
                {a.severity[finding.severity] ?? finding.severity}
              </span>
              <span className="font-medium">{finding.title}</span>
            </div>
            <p className="mt-1.5 text-sm text-ink">{finding.explanation}</p>
            <p className="mt-1 text-sm text-ink-muted">
              <span className="font-medium">{a.recommendation}: </span>
              {finding.recommendation}
            </p>
          </li>
        ))}
      </ul>
      <details className="rounded-control border border-line">
        <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-ink">{a.checksRun}</summary>
        <ul className="divide-y divide-line px-3 text-sm">
          {detail.checks.map((check) => (
            <li key={check.key} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <span className="text-ink">{check.label}</span>
              <span className="text-xs text-ink-muted">
                {a.checkStatus[check.status] ?? check.status} · {check.detail}
              </span>
            </li>
          ))}
        </ul>
      </details>
      <p className="text-xs text-ink-faint">{a.pagesChecked(detail.pages_checked)}</p>
    </div>
  );
}

function AssessmentRow({ item }: { item: AssessmentSummary }) {
  const a = useAssessText();
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<AssessmentDetail | null>(null);
  const active = item.status === "queued" || item.status === "running";

  // While an assessment is running, poll it so the page updates when it finishes.
  const [liveStatus, setLiveStatus] = useState(item.status);
  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      try {
        const latest = await api.assess.assessment(item.id);
        if (cancelled) return;
        setLiveStatus(latest.status);
        if (latest.status === "completed" || latest.status === "failed") {
          setDetail(latest);
          window.clearInterval(timer);
        }
      } catch {
        // keep trying
      }
    }, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [active, item.id]);

  const status = liveStatus;
  const result = detail?.result ?? item.result;

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && !detail) {
      try {
        setDetail(await api.assess.assessment(item.id));
      } catch {
        // ignore
      }
    }
  };

  return (
    <li className="px-5 py-3">
      <button type="button" className="flex w-full flex-wrap items-center justify-between gap-2 text-start" onClick={toggle} aria-expanded={open}>
        <span className="min-w-0">
          <span className="font-medium text-ink" dir="ltr">{item.domain}</span>
          <span className="block text-xs text-ink-faint">
            {formatDateTime(item.created_at)}
            {item.scheduled && <> · {a.scheduledBadge}</>}
            {item.active_probes && <> · {a.activeBadge}</>}
          </span>
        </span>
        <span className="flex items-center gap-2">
          {status === "running" || status === "queued" ? (
            <span className="text-xs text-accent">{a.status[status]}</span>
          ) : result ? (
            <span className={`text-sm font-medium ${RESULT_TONE[result] ?? "text-ink"}`}>
              {a.resultLabel[result] ?? result}
            </span>
          ) : (
            <span className="text-xs text-ink-muted">{a.status[status]}</span>
          )}
          <ChevronDown aria-hidden className={`size-4 text-ink-faint transition-transform ${open ? "rotate-180" : ""}`} />
        </span>
      </button>
      {open && detail && (
        <div className="mt-3 space-y-3">
          <Findings detail={detail} />
          {detail.status === "completed" && (
            <Link
              href={`/dashboard/assessment/report/${detail.id}`}
              className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline"
            >
              <FileText aria-hidden className="size-4" />
              {a.report}
            </Link>
          )}
        </div>
      )}
    </li>
  );
}

function DomainCard({
  domain,
  canScan,
  onChange,
  onScanned,
}: {
  domain: AssessedDomain;
  canScan: boolean;
  onChange: () => void;
  onScanned: () => void;
}) {
  const a = useAssessText();
  const notify = useToast();
  const [instructions, setInstructions] = useState<VerificationInstructions | null>(null);
  const [pending, setPending] = useState(false);
  const [active, setActive] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [schedule, setSchedule] = useState<AssessmentSchedule>(domain.schedule ?? "off");
  const [nextRun, setNextRun] = useState<string | null>(domain.next_run_at ?? null);

  useEffect(() => {
    // When unverified, fetch the token and instructions (re-adding is idempotent).
    if (domain.verified) return;
    let cancelled = false;
    api.assess
      .addDomain(domain.domain)
      .then((result) => !cancelled && setInstructions(result))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [domain.verified, domain.id, domain.domain]);

  return (
    <Panel>
      <PanelHeader
        title={
          <span className="flex items-center gap-2">
            <Globe aria-hidden className="size-5 text-ink-muted" />
            <span dir="ltr">{domain.domain}</span>
          </span>
        }
        action={
          <span className={domain.verified ? "inline-flex items-center gap-1.5 text-sm text-clear" : "inline-flex items-center gap-1.5 text-sm text-warning"}>
            {domain.verified ? <Check aria-hidden className="size-4" /> : <X aria-hidden className="size-4" />}
            {domain.verified ? a.verified : a.unverified}
          </span>
        }
      />
      <div className="space-y-4 p-5">
        {!domain.verified && instructions && <Verification instructions={instructions} onVerified={onChange} />}
        {domain.verified && (
          <div className="space-y-3 rounded-control border border-line p-4">
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1 size-4 accent-[var(--accent)]"
                checked={active}
                onChange={(event) => {
                  setActive(event.target.checked);
                  if (!event.target.checked) setConfirmed(false);
                }}
              />
              <span>
                <span className="font-medium text-ink">{a.activeTitle}</span>
                <span className="block text-ink-muted">{a.activeHow}</span>
              </span>
            </label>
            {active && (
              <label className="ms-6 flex items-start gap-2 rounded-control border border-warning bg-warning-soft p-3 text-sm text-ink">
                <input
                  type="checkbox"
                  className="mt-1 size-4 accent-[var(--accent)]"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>{a.activeConfirm}</span>
              </label>
            )}
          </div>
        )}
        {domain.verified && (
          <div className="flex flex-wrap items-end gap-3">
            <label className="space-y-1 text-sm">
              <span className="block font-medium text-ink">{a.scheduleLabel}</span>
              <Select
                value={schedule}
                onChange={async (event) => {
                  const next = event.target.value as AssessmentSchedule;
                  try {
                    const saved = await api.assess.setSchedule(domain.id, next);
                    setSchedule(saved.schedule);
                    setNextRun(saved.next_run_at);
                    notify("success", a.scheduleSaved);
                  } catch (error) {
                    notify("error", errorText(error));
                  }
                }}
              >
                {(["off", "weekly", "monthly"] as const).map((value) => (
                  <option key={value} value={value}>
                    {a.schedules[value]}
                  </option>
                ))}
              </Select>
            </label>
            <p className="pb-2 text-xs text-ink-muted">
              {schedule !== "off" && nextRun ? a.nextRun(formatDateTime(nextRun)) : a.scheduleHint}
            </p>
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          {domain.verified && (
            <Button
              pending={pending}
              disabled={!canScan}
              onClick={async () => {
                if (active && !confirmed) {
                  notify("error", a.activeNeedsConfirm);
                  return;
                }
                setPending(true);
                try {
                  await api.assess.scan(domain.id, { active_probes: active, confirm_owner: active && confirmed });
                  setActive(false);
                  setConfirmed(false);
                  onScanned();
                } catch (error) {
                  notify("error", errorText(error));
                } finally {
                  setPending(false);
                }
              }}
            >
              {pending ? a.scanning : a.scan}
            </Button>
          )}
          <button
            type="button"
            className="text-sm text-danger hover:underline"
            onClick={async () => {
              if (!window.confirm(a.confirmRemove(domain.domain))) return;
              try {
                await api.assess.removeDomain(domain.id);
                onChange();
              } catch (error) {
                notify("error", errorText(error));
              }
            }}
          >
            <Trash2 aria-hidden className="mr-1 inline size-4" />
            {a.remove}
          </button>
        </div>
      </div>
    </Panel>
  );
}

export function SecurityAssessment() {
  const a = useAssessText();
  const notify = useToast();
  const [status, setStatus] = useState<AssessmentStatus | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [domain, setDomain] = useState("");
  const [pending, setPending] = useState(false);
  const pollRef = useRef<number | null>(null);

  const load = useCallback(
    () =>
      api.assess
        .status()
        .then((next) => setStatus(next))
        .catch((error) => {
          if (error instanceof ApiError && error.status === 403) setForbidden(true);
          else notify("error", errorText(error));
        }),
    [notify],
  );

  useEffect(() => {
    api.assess
      .status()
      .then((next) => setStatus(next))
      .catch((error) => {
        if (error instanceof ApiError && error.status === 403) setForbidden(true);
      });
  }, []);

  // Refresh while any assessment is still running.
  const running = status?.recent.some((r) => r.status === "queued" || r.status === "running") ?? false;
  useEffect(() => {
    if (!running) return;
    pollRef.current = window.setInterval(() => void load(), 5000);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [running, load]);

  if (forbidden) {
    return (
      <div className="space-y-6">
        <PageTitle title={a.title} description={a.description} />
        <Alert tone="info">{a.disabled}</Alert>
      </div>
    );
  }
  if (!status) return <PageTitle title={a.title} description={a.description} />;

  const atLimit = status.domains.length >= status.domain_limit;
  const canScan = status.used_this_month < status.monthly_limit;

  const addDomain = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      await api.assess.addDomain(domain.trim());
      setDomain("");
      await load();
    } catch (error) {
      notify("error", errorText(error));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageTitle title={a.title} description={a.description} />
      <Alert tone="warning">
        <ShieldAlert aria-hidden className="mb-1 inline size-4" /> {a.ownOnly}
      </Alert>

      <Panel>
        <PanelHeader title={a.whatTitle} />
        <div className="grid gap-4 p-5 md:grid-cols-2">
          <ul className="space-y-2 text-sm">
            {a.does.map((line) => (
              <li key={line} className="flex gap-2">
                <Check aria-hidden className="mt-0.5 size-4 shrink-0 text-clear" />
                <span>{line}</span>
              </li>
            ))}
          </ul>
          <ul className="space-y-2 text-sm">
            {a.doesNot.map((line) => (
              <li key={line} className="flex gap-2">
                <X aria-hidden className="mt-0.5 size-4 shrink-0 text-warning" />
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>
      </Panel>

      <Panel>
        <PanelHeader title={a.addTitle} description={a.usage(status.used_this_month, status.monthly_limit)} />
        <form onSubmit={addDomain} className="flex flex-wrap items-end gap-3 p-5">
          <div className="min-w-48 flex-1">
            <Field label={a.domainLabel} hint={a.limitReached(status.domain_limit)}>
              {(props) => (
                <Input {...props} dir="ltr" required placeholder={a.domainPlaceholder} value={domain} onChange={(e) => setDomain(e.target.value)} />
              )}
            </Field>
          </div>
          <Button type="submit" pending={pending} disabled={atLimit}>
            <Plus aria-hidden className="size-4" />
            {a.add}
          </Button>
        </form>
      </Panel>

      {status.domains.length === 0 ? (
        <p className="text-ink-muted">{a.none}</p>
      ) : (
        status.domains.map((d) => (
          <DomainCard key={d.id} domain={d} canScan={canScan} onChange={load} onScanned={load} />
        ))
      )}

      <Panel>
        <PanelHeader title={a.results} />
        {status.recent.length === 0 ? (
          <p className="p-5 text-ink-muted">{a.noResults}</p>
        ) : (
          <ul className="divide-y divide-line">
            {status.recent.map((item) => (
              <AssessmentRow key={item.id} item={item} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
