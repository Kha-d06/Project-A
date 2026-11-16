"use client";

import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { ButtonLink } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { CommunityReport } from "@/lib/api/types";

import { ReportCard } from "./report-status";

export function MyReports() {
  const [reports, setReports] = useState<CommunityReport[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.reports.mine().then(setReports, (caught: unknown) =>
      setError(caught instanceof ApiError ? caught.message : "Your reports could not be loaded."),
    );
  }, []);

  return (
    <>
      <PageTitle
        title="My reports"
        description="Scams you reported while signed in. Anonymous reports are not listed here."
        action={<ButtonLink href="/report">Report a scam</ButtonLink>}
      />
      {error && <Alert tone="warning">{error}</Alert>}
      {reports?.length === 0 && (
        <Panel className="px-6 py-10 text-center text-sm text-ink-muted">
          You have not reported anything yet. If someone tried to scam you, reporting it helps SENTINEL warn others.
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
