"use client";

import { useEffect, useState } from "react";

import { Alert } from "@/components/ui/alert";
import { Panel } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { CommunityReport } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

export function ReportCard({ report }: { report: CommunityReport }) {
  const { t } = useI18n();
  const status = t.community.statuses[report.status];
  return (
    <Panel className="space-y-3 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm text-ink-muted">
          {t.community.sent(t.community.categories[report.category].label, formatDateTime(report.created_at))}
        </span>
        <span className="rounded-full border border-line-strong px-2.5 py-0.5 text-xs font-medium text-ink">{status.label}</span>
      </div>
      <p className="font-mono text-sm break-all text-ink" dir="auto">
        {report.subject}
      </p>
      <p className="text-sm whitespace-pre-line text-ink-muted" dir="auto">
        {report.description}
      </p>
      <p className="text-xs text-ink-faint">{status.description}</p>
      {report.moderator_note && (
        <p className="text-sm text-ink">
          {t.community.note} <span dir="auto">{report.moderator_note}</span>
        </p>
      )}
    </Panel>
  );
}

export function ReportStatus({ id, token }: { id: string; token: string | null }) {
  const { t } = useI18n();
  const [report, setReport] = useState<CommunityReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.reports.get(id, token).then(setReport, (caught: unknown) =>
      setError(caught instanceof ApiError ? caught.message : t.community.loadFailed),
    );
  }, [id, token, t.community.loadFailed]);

  if (error) return <Alert tone="warning">{error}</Alert>;
  if (!report) return <div className="h-40 animate-pulse rounded-panel border border-line bg-surface" aria-busy />;
  return <ReportCard report={report} />;
}
