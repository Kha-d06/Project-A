"use client";

import { Puzzle } from "lucide-react";
import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { ScanList } from "@/components/dashboard/scan-list";
import { Alert } from "@/components/ui/alert";
import { ButtonLink } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { Activity, Installation, Overview as OverviewData, Profile, RiskLevel } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatRelative } from "@/lib/format";
import { type Dictionary } from "@/lib/i18n/en";
import { useI18n } from "@/lib/i18n/client";
import { RISK, TONE_CLASSES } from "@/lib/risk";
import { useSession } from "@/lib/session";

import { ActivityChart } from "./activity-chart";

// A chart of one or two scans says nothing; below this, the list is enough.
const MIN_SCANS_FOR_CHART = 5;
const RISK_ORDER: RiskLevel[] = ["known_malicious", "suspicious", "no_known_threat", "inconclusive"];


interface Loaded {
  overview: OverviewData;
  activity: Activity[];
  profile: Profile;
  installations: Installation[];
}

function RiskBreakdown({ overview }: { overview: OverviewData }) {
  const { t } = useI18n();
  const total = overview.total_scans;
  const bar: Record<RiskLevel, string> = {
    known_malicious: "bg-danger",
    suspicious: "bg-warning",
    no_known_threat: "bg-clear",
    inconclusive: "bg-unknown",
  };
  return (
    <div className="space-y-4 px-5 py-5">
      <div className="flex h-2 overflow-hidden rounded-full bg-surface-sunken" aria-hidden>
        {RISK_ORDER.map((risk) => {
          const count = overview.by_risk[risk] ?? 0;
          return count ? <span key={risk} className={bar[risk]} style={{ width: `${(count / total) * 100}%` }} /> : null;
        })}
      </div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        {RISK_ORDER.map((risk) => (
          <div key={risk}>
            <dt className="text-xs text-ink-faint">{t.risk[risk].short}</dt>
            <dd className={cn("font-display text-xl font-semibold", (overview.by_risk[risk] ?? 0) > 0 ? TONE_CLASSES[RISK[risk].tone].text : "text-ink")}>
              {overview.by_risk[risk] ?? 0}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function recommendations(t: Dictionary, { overview, profile }: Loaded): string[] {
  const tips: string[] = [];
  const flagged = (overview.by_risk.known_malicious ?? 0) + (overview.by_risk.suspicious ?? 0);
  if (flagged > 0) {
    tips.push(t.dashboard.overview.recFlagged);
  }
  if ((overview.by_risk.inconclusive ?? 0) > 0) {
    tips.push(t.dashboard.overview.recInconclusive);
  }
  if (!profile.settings.save_scan_history) {
    tips.push(t.dashboard.overview.recHistoryOff);
  }
  tips.push(t.dashboard.overview.rec2fa);
  return tips;
}

function ExtensionStatus({ installations }: { installations: Installation[] }) {
  const { t } = useI18n();
  const latest = installations[0];
  if (!latest) {
    return (
      <div className="space-y-2 text-sm">
        <p className="font-medium text-ink">{t.dashboard.overview.noBrowser}</p>
        <p className="text-ink-muted">{t.dashboard.overview.noBrowserBody}</p>
        <a href="/dashboard/browser-protection" className="inline-block font-medium text-accent hover:underline">
          {t.dashboard.overview.setUp}
        </a>
      </div>
    );
  }
  return (
    <div className="space-y-2 text-sm">
      <p className="font-medium text-ink">{t.dashboard.overview.browsersLinked(installations.length)}</p>
      <p className="text-ink-muted">{t.dashboard.overview.mostRecent(formatRelative(latest.last_seen_at))}</p>
      <a href="/dashboard/browser-protection" className="inline-block font-medium text-accent hover:underline">
        {t.dashboard.overview.manage}
      </a>
    </div>
  );
}

function EmptyOverview() {
  const { t } = useI18n();
  return (
    <Panel className="px-6 py-12 text-center">
      <div className="mx-auto max-w-md space-y-4">
        <h2 className="font-display text-lg font-semibold text-ink">{t.dashboard.overview.emptyTitle}</h2>
        <p className="text-sm text-ink-muted">{t.dashboard.overview.emptyBody}</p>
        <div className="flex flex-wrap justify-center gap-2">
          <ButtonLink href="/dashboard/scan?type=url">{t.dashboard.overview.checkLink}</ButtonLink>
          <ButtonLink href="/dashboard/scan?type=message" variant="secondary">
            {t.dashboard.overview.analyseMessage}
          </ButtonLink>
        </div>
      </div>
    </Panel>
  );
}

export function Overview() {
  const { session } = useSession();
  const { t } = useI18n();
  const [data, setData] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.user.overview(), api.user.activity(), api.user.profile(), api.extension.installations()])
      .then(([overview, activity, profile, installations]) => setData({ overview, activity, profile, installations }))
      .catch((caught: unknown) =>
        setError(caught instanceof ApiError ? caught.message : "The overview could not be loaded."),
      );
  }, []);

  const name = session.status === "signed-in" ? session.user.display_name : null;

  return (
    <>
      <PageTitle
        title={name ? t.dashboard.overview.welcome(name) : t.dashboard.overview.title}
        description={t.dashboard.overview.description}
        action={<ButtonLink href="/dashboard/scan">{t.dashboard.overview.newScan}</ButtonLink>}
      />
      {error && (
        <Alert tone="warning" title={t.dashboard.overview.unavailable}>
          {error}
        </Alert>
      )}
      {!data && !error && (
        <div className="grid gap-6 lg:grid-cols-2" aria-busy>
          {[0, 1, 2, 3].map((key) => (
            <div key={key} className="h-48 animate-pulse rounded-panel border border-line bg-surface" />
          ))}
        </div>
      )}
      {data && (
        <div className="space-y-6">
          {data.overview.total_scans === 0 ? (
            <EmptyOverview />
          ) : (
            <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
              <Panel>
                <PanelHeader title={t.dashboard.overview.results} description={t.dashboard.overview.savedScans(data.overview.total_scans)} />
                <RiskBreakdown overview={data.overview} />
                {data.overview.total_scans >= MIN_SCANS_FOR_CHART && (
                  <div className="border-t border-line px-5 py-5">
                    <ActivityChart days={data.overview.daily_activity} />
                  </div>
                )}
              </Panel>
              <Panel>
                <PanelHeader title={t.dashboard.overview.flagged} description={t.dashboard.overview.flaggedDescription} />
                <ScanList scans={data.overview.recent_threats} empty={t.dashboard.overview.nothingFlagged} />
              </Panel>
            </div>
          )}

          <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
            {data.overview.total_scans > 0 && (
              <Panel>
                <PanelHeader
                  title={t.dashboard.overview.recentScans}
                  action={
                    <ButtonLink href="/dashboard/history" variant="ghost" size="sm">
                      {t.dashboard.overview.viewAll}
                    </ButtonLink>
                  }
                />
                <ScanList scans={data.overview.recent_scans} empty="" />
              </Panel>
            )}
            <Panel className={cn(data.overview.total_scans === 0 && "lg:col-span-2")}>
              <PanelHeader title={t.dashboard.overview.browserProtection} />
              <div className="flex gap-4 px-5 py-5">
                <Puzzle aria-hidden className="mt-0.5 size-5 shrink-0 text-ink-faint" />
                <ExtensionStatus installations={data.installations} />
              </div>
            </Panel>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Panel>
              <PanelHeader title={t.dashboard.overview.recommendations} />
              <ul className="space-y-3 px-5 py-4 text-sm leading-relaxed text-ink">
                {recommendations(t, data).map((tip) => (
                  <li key={tip} className="flex gap-2.5">
                    <span aria-hidden className="mt-2 size-1 shrink-0 rounded-full bg-accent" />
                    {tip}
                  </li>
                ))}
              </ul>
            </Panel>
            <Panel>
              <PanelHeader title={t.dashboard.overview.activity} description={t.dashboard.overview.activityDescription} />
              <ul className="divide-y divide-line">
                {data.activity.map((event) => (
                  <li key={`${event.action}-${event.created_at}`} className="flex items-center justify-between gap-4 px-5 py-2.5 text-sm">
                    <span className={cn(event.action === "sign_in_failed" ? "text-warning" : "text-ink")}>
                      {t.dashboard.overview.actions[event.action] ?? event.action}
                    </span>
                    <span className="text-xs text-ink-faint">{formatRelative(event.created_at)}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
