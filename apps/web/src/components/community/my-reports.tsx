"use client";

import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { ButtonLink } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { CommunityReport } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";

import { ReportCard } from "./report-status";

export function MyReports() {
  const { t } = useI18n();
  const [reports, setReports] = useState<CommunityReport[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.reports.mine().then(setReports, (caught: unknown) =>
      setError(caught instanceof ApiError ? caught.message : t.community.mineFailed),
    );
  }, [t.community.mineFailed]);

  return (
    <>
      <PageTitle
        title={t.community.mine}
        description={t.community.mineDescription}
        action={<ButtonLink href="/report">{t.community.title}</ButtonLink>}
      />
      {error && <Alert tone="warning">{error}</Alert>}
      {reports?.length === 0 && (
        <Panel className="px-6 py-10 text-center text-sm text-ink-muted">
          {t.community.mineEmpty}
        </Panel>
      )}
      <div className="space-y-4">
        {reports?.map((report) => (
          <ReportCard key={report.id} report={report} />
        ))}
      </div>
    </>
  );
}
