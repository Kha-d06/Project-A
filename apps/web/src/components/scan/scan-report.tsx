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
import { SCAN_TYPE_LABEL, isActive } from "@/lib/risk";
import { useSession } from "@/lib/session";

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

function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function describeFindings(warnings: number, notes: number): string {
  if (warnings === 0 && notes === 0) return "No warning signs";
  const parts = [warnings ? plural(warnings, "warning sign") : "No warning signs"];
  if (notes) parts.push(plural(notes, "minor note"));
  return parts.join(", ");
}

function ReportActions({ scan, backHref }: { scan: Scan; backHref: string }) {
  const { session } = useSession();
  const router = useRouter();
  const notify = useToast();
  const [deleting, setDeleting] = useState(false);
  const canDelete = session.status === "signed-in" && scan.saved_to_history;

  const remove = async () => {
    setDeleting(true);
    try {
      await api.scans.remove(scan.id);
      notify("success", "The scan and its report were deleted.");
      router.push(backHref);
    } catch (error) {
      setDeleting(false);
      notify("error", error instanceof ApiError ? error.message : "The scan could not be deleted.");
    }
  };

  return (
    <div className="flex flex-wrap gap-2">
      <Button variant="secondary" size="sm" onClick={() => downloadReport(scan)}>
        <Download aria-hidden className="size-4" />
        Download report
      </Button>
      {canDelete && (
        <Button variant="danger" size="sm" pending={deleting} onClick={remove}>
          <Trash2 aria-hidden className="size-4" />
          Delete
        </Button>
      )}
    </div>
  );
}

function ReportBody({ scan, backHref, newScanHref }: { scan: Scan; backHref: string; newScanHref: string }) {
  const finished = !isActive(scan.status);
  // Same definition as the verdict summary: medium severity and above are warning signs.
  const warnings = scan.findings.filter((finding) => WARNING_SEVERITIES.has(finding.severity)).length;
  const notes = scan.findings.length - warnings;

  return (
    <div className="space-y-6">
      <Panel className="overflow-hidden">
        <div className="space-y-6 p-5 sm:p-7">
          <h1 className="sr-only">{SCAN_TYPE_LABEL[scan.scan_type]} scan report</h1>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-ink-muted">
              {SCAN_TYPE_LABEL[scan.scan_type]} scan · submitted {formatDateTime(scan.created_at)}
            </p>
            {finished && <ReportActions scan={scan} backHref={backHref} />}
          </div>
          <p className="font-mono text-sm break-all text-ink" dir="auto">
            {scan.target}
          </p>
          {finished ? <Verdict scan={scan} /> : <ScanProgress scan={scan} />}
        </div>
      </Panel>

      {finished && scan.status !== "failed" && (
        <>
          <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
            <Panel>
              <PanelHeader
                title="What we found"
                description={describeFindings(warnings, notes)}
              />
              <FindingsList findings={scan.findings} />
            </Panel>
            <div className="space-y-6">
              <Panel>
                <PanelHeader title="What to do next" />
                <ul className="space-y-3 px-5 py-4 text-sm leading-relaxed text-ink">
                  {scan.recommendations.map((item) => (
                    <li key={item} className="flex gap-2.5">
                      <span aria-hidden className="mt-2 size-1 shrink-0 rounded-full bg-accent" />
                      {item}
                    </li>
                  ))}
                </ul>
              </Panel>
              {scan.limitations.length > 0 && (
                <Panel>
                  <PanelHeader title="Limits of this scan" />
                  <ul className="space-y-2.5 px-5 py-4 text-sm leading-relaxed text-ink-muted">
                    {scan.limitations.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </Panel>
              )}
            </div>
          </div>

          <Panel>
            <PanelHeader
              title="Checks performed"
              description="Every check we attempted, including the ones that could not run."
            />
            <ChecksList checks={scan.checks} />
          </Panel>

          <Panel>
            <PanelHeader title="Technical details" />
            <ScanDetails scan={scan} />
          </Panel>
        </>
      )}

      <div className="flex flex-wrap items-center justify-between gap-4 text-sm text-ink-faint">
        <p>
          Scan ID <span className="font-mono">{scan.id}</span>
          {scan.started_at && scan.completed_at && ` · took ${formatDuration(scan.started_at, scan.completed_at)}`}
          {!scan.saved_to_history && " · not saved to an account"}
        </p>
        <ButtonLink href={newScanHref} variant="secondary" size="sm">
          Scan something else
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

  return (
    <div className="space-y-6">
      <Link
        href={backHref}
        className="inline-flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink"
      >
        <ArrowLeft aria-hidden className="size-4" />
        Back
      </Link>
      {state.phase === "loading" && (
        <Panel className="p-7" aria-busy>
          <div className="space-y-3">
            <div className="h-4 w-1/3 animate-pulse rounded bg-surface-sunken" />
            <div className="h-8 w-2/3 animate-pulse rounded bg-surface-sunken" />
            <span className="sr-only">Loading the report</span>
          </div>
        </Panel>
      )}
      {state.phase === "error" && (
        <Alert
          tone="warning"
          title={state.error.status === 404 ? "This report is not available" : "We could not load this report"}
        >
          {state.error.status === 404
            ? "It may have been deleted, or it belongs to an account you are not signed in to. Reports for scans made without an account are removed after 30 days."
            : state.error.message}
        </Alert>
      )}
      {state.phase === "ready" && <ReportBody scan={state.scan} backHref={backHref} newScanHref={newScanHref} />}
    </div>
  );
}
