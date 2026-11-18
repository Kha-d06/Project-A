"use client";

import { ArrowLeft, Printer } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { Findings, RESULT_TONE } from "@/components/dashboard/security-assessment";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api/client";
import type { AssessmentDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

/** A printable assessment report. "Save as PDF" uses the browser's own print dialog,
 * so nothing is generated or stored on the server. */
export function AssessmentReport({ id }: { id: string }) {
  const a = useI18n().t.extra.assess;
  const [detail, setDetail] = useState<AssessmentDetail | null>(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api.assess
      .assessment(id)
      .then((next) => !cancelled && setDetail(next))
      .catch(() => !cancelled && setMissing(true));
    return () => {
      cancelled = true;
    };
  }, [id]);

  const back = (
    <Link href="/dashboard/assessment" className="inline-flex items-center gap-1.5 text-sm text-accent hover:underline print:hidden">
      <ArrowLeft aria-hidden className="size-4 rtl:rotate-180" />
      {a.reportBack}
    </Link>
  );

  if (missing) {
    return (
      <div className="space-y-4">
        {back}
        <Alert tone="warning">{a.reportNotFound}</Alert>
      </div>
    );
  }
  if (!detail) return back;

  return (
    <article className="mx-auto max-w-3xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {back}
        <Button variant="secondary" size="sm" className="print:hidden" onClick={() => window.print()}>
          <Printer aria-hidden className="size-4" />
          {a.savePdf}
        </Button>
      </div>
      <header className="space-y-2 border-b border-line pb-4">
        <p className="text-xs font-semibold tracking-wide text-ink-faint">Qalaa</p>
        <h1 className="text-2xl font-semibold text-ink">
          {a.reportTitle(detail.domain)}
        </h1>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-ink-faint">{a.reportResult}</dt>
            <dd className={`font-medium ${RESULT_TONE[detail.result ?? ""] ?? "text-ink"}`}>
              {detail.result ? (a.resultLabel[detail.result] ?? detail.result) : a.status[detail.status]}
            </dd>
          </div>
          <div>
            <dt className="text-ink-faint">{a.reportStarted}</dt>
            <dd className="text-ink">{formatDateTime(detail.created_at)}</dd>
          </div>
          <div>
            <dt className="text-ink-faint">{a.reportFinished}</dt>
            <dd className="text-ink">{detail.finished_at ? formatDateTime(detail.finished_at) : "—"}</dd>
          </div>
          <div>
            <dt className="text-ink-faint">{a.reportFindings}</dt>
            <dd className="text-ink">
              {detail.finding_count}
              {detail.active_probes && <span className="text-ink-muted"> · {a.activeBadge}</span>}
            </dd>
          </div>
        </dl>
      </header>
      {detail.findings.length === 0 && !detail.error && <p className="text-ink-muted">{a.reportNoFindings}</p>}
      <Findings detail={detail} />
      <p className="border-t border-line pt-4 text-xs text-ink-faint">{a.reportDisclaimer}</p>
    </article>
  );
}
