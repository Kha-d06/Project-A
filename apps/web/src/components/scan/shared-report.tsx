"use client";

import { Printer } from "lucide-react";
import { useEffect, useState } from "react";

import { Alert } from "@/components/ui/alert";
import { Button, ButtonLink } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api/client";
import type { Scan, SharedScan } from "@/lib/api/types";
import { formatDateTime, formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

import { ChecksList } from "./checks";
import { FindingsList } from "./findings";
import { Verdict } from "./verdict";

/** A shared result has no ID, owner or history; Verdict needs only these fields. */
function asScan(shared: SharedScan): Scan {
  return {
    id: "",
    scan_type: shared.scan_type,
    status: shared.status,
    target: shared.target ?? "",
    risk: shared.risk,
    created_at: shared.shared_at,
    completed_at: shared.completed_at,
    confidence: shared.confidence,
    summary: shared.summary,
    findings: shared.findings.map((finding) => ({ ...finding, evidence: finding.evidence ?? {} })),
    checks: shared.checks,
    details: shared.details ?? {},
    recommendations: shared.recommendations,
    limitations: shared.limitations,
    error: null,
    started_at: null,
    saved_to_history: false,
    ai_explanation: null,
    ai_model: null,
    ai_generated_at: null,
  };
}

export function SharedReport({ token }: { token: string }) {
  const { t } = useI18n();
  const s = t.extra.shared;
  const [state, setState] = useState<{ status: "loading" } | { status: "missing" } | { status: "ready"; shared: SharedScan }>({ status: "loading" });

  useEffect(() => {
    api.sharing
      .view(token)
      .then((shared) => setState({ status: "ready", shared }))
      .catch(() => setState({ status: "missing" }));
  }, [token]);

  if (state.status === "loading") {
    return <p className="text-ink-muted" role="status">{t.report.loading}</p>;
  }
  if (state.status === "missing") {
    return (
      <Alert tone="info" title={s.notFoundTitle}>
        <p>{s.notFoundBody}</p>
        <ButtonLink href="/scan" size="sm" className="mt-3">
          {s.checkYourOwn}
        </ButtonLink>
      </Alert>
    );
  }
  const { shared } = state;
  const scan = asScan(shared);
  return (
    <div className="space-y-6">
      <Panel className="space-y-5 p-5 sm:p-7">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="font-display text-lg font-semibold text-ink">{s.title}</h1>
            <p className="text-sm text-ink-muted">
              {t.scanTypes[shared.scan_type]} · {s.sharedOn(formatDateTime(shared.shared_at))}
            </p>
          </div>
          <Button variant="secondary" size="sm" className="print:hidden" onClick={() => window.print()}>
            <Printer aria-hidden className="size-4" />
            {t.extra.share.print}
          </Button>
        </div>
        {shared.target ? (
          <p className="font-mono text-sm break-all text-ink" dir="auto">{shared.target}</p>
        ) : (
          <p className="text-sm text-ink-faint">{s.hidden}</p>
        )}
        {shared.note && (
          <blockquote className="border-s-2 border-accent ps-3 text-sm text-ink" dir="auto">
            <span className="block text-xs text-ink-faint">{s.note}</span>
            {shared.note}
          </blockquote>
        )}
        <Verdict scan={scan} />
      </Panel>
      <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <Panel>
          <PanelHeader title={t.report.found} />
          <FindingsList findings={scan.findings} />
        </Panel>
        <Panel>
          <PanelHeader title={t.report.nextSteps} />
          <ul className="space-y-3 px-5 py-4 text-sm leading-relaxed text-ink">
            {shared.recommendations.map((item) => (
              <li key={item} dir="auto">{item}</li>
            ))}
          </ul>
        </Panel>
      </div>
      <Panel>
        <PanelHeader title={t.report.checks} description={t.report.checksDescription} />
        <ChecksList checks={shared.checks} />
      </Panel>
      {shared.limitations.length > 0 && (
        <Panel>
          <PanelHeader title={t.report.limits} />
          <ul className="space-y-2.5 px-5 py-4 text-sm text-ink-muted">
            {shared.limitations.map((item) => (
              <li key={item} dir="auto">{item}</li>
            ))}
          </ul>
        </Panel>
      )}
      {shared.expires_at && <p className="text-sm text-ink-faint">{s.expiresOn(formatShortDate(shared.expires_at))}</p>}
    </div>
  );
}
