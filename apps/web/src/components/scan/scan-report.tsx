"use client";

import { ArrowLeft, Download, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Alert } from "@/components/ui/alert";
import { Button, ButtonLink } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Scan } from "@/lib/api/types";
import { formatDateTime, formatDuration } from "@/lib/format";
import { useScan } from "@/lib/hooks/use-scan";
import { type Dictionary } from "@/lib/i18n/en";
import { useI18n } from "@/lib/i18n/client";
import { isActive } from "@/lib/risk";
import { useSession } from "@/lib/session";

import { AiExplanation } from "./ai-explanation";
import { ChecksList } from "./checks";
import { FindingsList } from "./findings";
import { ScanDetails } from "./scan-details";
import { ScanProgress } from "./scan-progress";
import { Verdict } from "./verdict";

function downloadReport(scan: Scan) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `sentinel-report-${scan.id}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

const WARNING_SEVERITIES = new Set(["critical", "high", "medium"]);

function describeFindings(t: Dictionary, separator: string, warnings: number, notes: number): string {
  const parts = [warnings ? t.report.warningSigns(warnings) : t.report.noWarnings];
  if (notes) parts.push(t.report.minorNotes(notes));
  return parts.join(separator);
}

function ReportActions({ scan, backHref }: { scan: Scan; backHref: string }) {
  const { session } = useSession();
  const { t } = useI18n();
  const router = useRouter();
  const notify = useToast();
  const [deleting, setDeleting] = useState(false);
  const canDelete = session.status === "signed-in" && scan.saved_to_history;

  const remove = async () => {
    setDeleting(true);
    try {
      await api.scans.remove(scan.id);
      notify("success", t.report.deleted);
      router.push(backHref);
    } catch (error) {
      setDeleting(false);
      notify("error", error instanceof ApiError ? error.message : t.report.deleteFailed);
    }
  };

  return (
    <div className="flex flex-wrap gap-2">
      <Button variant="secondary" size="sm" onClick={() => downloadReport(scan)}>
        <Download aria-hidden className="size-4" />
        {t.report.download}
      </Button>
      {canDelete && (
        <Button variant="danger" size="sm" pending={deleting} onClick={remove}>
          <Trash2 aria-hidden className="size-4" />
          {t.report.delete}
        </Button>
      )}
    </div>
  );
}

function ReportBody({ scan, backHref, newScanHref }: { scan: Scan; backHref: string; newScanHref: string }) {
  const { t, locale } = useI18n();
  const finished = !isActive(scan.status);
  // Same definition as the verdict summary: medium severity and above are warning signs.
  const warnings = scan.findings.filter((finding) => WARNING_SEVERITIES.has(finding.severity)).length;
  const notes = scan.findings.length - warnings;

  return (
    <div className="space-y-6">
      <Panel className="overflow-hidden">
        <div className="space-y-6 p-5 sm:p-7">
          <h1 className="sr-only">{t.report.submitted(t.scanTypes[scan.scan_type], formatDateTime(scan.created_at))}</h1>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-ink-muted">
              {t.report.submitted(t.scanTypes[scan.scan_type], formatDateTime(scan.created_at))}
            </p>
            {finished && <ReportActions scan={scan} backHref={backHref} />}
          </div>
          <p className="font-mono text-sm break-all text-ink" dir="auto">
            {scan.target}
          </p>
          {finished ? <Verdict scan={scan} /> : <ScanProgress scan={scan} />}
          {finished && t.common.findingsInEnglish && scan.findings.length > 0 && (
            <p className="text-xs text-ink-faint">{t.common.findingsInEnglish}</p>
          )}
        </div>
      </Panel>

      {finished && scan.status !== "failed" && (
        <>
          <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
            <Panel>
              <PanelHeader
                title={t.report.found}
                description={describeFindings(t, locale === "ar" ? "، " : ", ", warnings, notes)}
              />
              <FindingsList findings={scan.findings} />
            </Panel>
            <div className="space-y-6">
              <Panel>
                <PanelHeader title={t.report.nextSteps} />
                <ul className="space-y-3 px-5 py-4 text-sm leading-relaxed text-ink">
                  {scan.recommendations.map((item) => (
                    <li key={item} className="flex gap-2.5" dir="auto">
                      <span aria-hidden className="mt-2 size-1 shrink-0 rounded-full bg-accent" />
                      {item}
                    </li>
                  ))}
                </ul>
              </Panel>
              {scan.limitations.length > 0 && (
                <Panel>
                  <PanelHeader title={t.report.limits} />
                  <ul className="space-y-2.5 px-5 py-4 text-sm leading-relaxed text-ink-muted">
                    {scan.limitations.map((item) => (
                      <li key={item} dir="auto">{item}</li>
                    ))}
                  </ul>
                </Panel>
              )}
            </div>
          </div>

          <AiExplanation scan={scan} />

          <Panel>
            <PanelHeader
              title={t.report.checks}
              description={t.report.checksDescription}
            />
            <ChecksList checks={scan.checks} />
          </Panel>

          <Panel>
            <PanelHeader title={t.report.technical} />
            <ScanDetails scan={scan} />
          </Panel>
        </>
      )}

      <div className="flex flex-wrap items-center justify-between gap-4 text-sm text-ink-faint">
        <p>
          {t.report.scanId} <span className="font-mono">{scan.id}</span>
          {scan.started_at && scan.completed_at && ` · ${t.report.took(formatDuration(scan.started_at, scan.completed_at))}`}
          {!scan.saved_to_history && ` · ${t.report.notSaved}`}
        </p>
        <ButtonLink href={newScanHref} variant="secondary" size="sm">
          {t.report.scanAgain}
        </ButtonLink>
      </div>
    </div>
  );
}

export function ScanReport({
  scanId,
  backHref,
  newScanHref,
}: {
  scanId: string;
  backHref: string;
  newScanHref: string;
}) {
  const state = useScan(scanId);
  const { t } = useI18n();

  return (
    <div className="space-y-6">
      <Link
        href={backHref}
        className="inline-flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink"
      >
        <ArrowLeft aria-hidden className="size-4 rtl:rotate-180" />
        {t.common.back}
      </Link>
      {state.phase === "loading" && (
        <Panel className="p-7" aria-busy>
          <div className="space-y-3">
            <div className="h-4 w-1/3 animate-pulse rounded bg-surface-sunken" />
            <div className="h-8 w-2/3 animate-pulse rounded bg-surface-sunken" />
            <span className="sr-only">{t.report.loading}</span>
          </div>
        </Panel>
      )}
      {state.phase === "error" && (
        <Alert
          tone="warning"
          title={state.error.status === 404 ? t.report.notAvailableTitle : t.report.loadFailedTitle}
        >
          {state.error.status === 404 ? t.report.notAvailableBody : state.error.message}
        </Alert>
      )}
      {state.phase === "ready" && <ReportBody scan={state.scan} backHref={backHref} newScanHref={newScanHref} />}
    </div>
  );
}
