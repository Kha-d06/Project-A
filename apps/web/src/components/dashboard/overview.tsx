"use client";

import { Puzzle } from "lucide-react";
import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { ScanList } from "@/components/dashboard/scan-list";
import { Alert } from "@/components/ui/alert";
import { ButtonLink } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { Activity, Overview as OverviewData, Profile, RiskLevel } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatRelative } from "@/lib/format";
import { RISK, TONE_CLASSES } from "@/lib/risk";
import { useSession } from "@/lib/session";

import { ActivityChart } from "./activity-chart";

// A chart of one or two scans says nothing; below this, the list is enough.
const MIN_SCANS_FOR_CHART = 5;
const RISK_ORDER: RiskLevel[] = ["known_malicious", "suspicious", "no_known_threat", "inconclusive"];

const ACTIVITY_TEXT: Record<string, string> = {
  account_created: "Account created",
  signed_in: "Signed in",
  signed_out: "Signed out",
  sign_in_failed: "Failed sign-in attempt",
  password_changed: "Password changed",
};

interface Loaded {
  overview: OverviewData;
  activity: Activity[];
  profile: Profile;
}

function RiskBreakdown({ overview }: { overview: OverviewData }) {
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
            <dt className="text-xs text-ink-faint">{RISK[risk].short}</dt>
            <dd className={cn("font-display text-xl font-semibold", (overview.by_risk[risk] ?? 0) > 0 ? TONE_CLASSES[RISK[risk].tone].text : "text-ink")}>
              {overview.by_risk[risk] ?? 0}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function recommendations({ overview, profile }: Loaded): string[] {
  const tips: string[] = [];
  const flagged = (overview.by_risk.known_malicious ?? 0) + (overview.by_risk.suspicious ?? 0);
  if (flagged > 0) {
    tips.push("Review your flagged scans and follow the next steps listed in each report, especially if you already opened a link or file.");
  }
  if ((overview.by_risk.inconclusive ?? 0) > 0) {
    tips.push("Some results were inconclusive because a check was unavailable. Re-scan those items later before trusting them.");
  }
  if (!profile.settings.save_scan_history) {
    tips.push("Scan history is switched off, so new scans are not saved here. You can turn it back on in Settings.");
  }
  tips.push("Turn on two-step verification for your email and banking accounts. It stops most stolen-password attacks.");
  return tips;
}

function EmptyOverview() {
  return (
    <Panel className="px-6 py-12 text-center">
      <div className="mx-auto max-w-md space-y-4">
        <h2 className="font-display text-lg font-semibold text-ink">No scans yet</h2>
        <p className="text-sm text-ink-muted">
          When you check a link, message or file while signed in, it is saved here with its full
          report. Got something you are unsure about right now?
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          <ButtonLink href="/dashboard/scan?type=url">Check a link</ButtonLink>
          <ButtonLink href="/dashboard/scan?type=message" variant="secondary">Analyse a message</ButtonLink>
        </div>
      </div>
    </Panel>
  );
}

export function Overview() {
  const { session } = useSession();
  const [data, setData] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.user.overview(), api.user.activity(), api.user.profile()])
      .then(([overview, activity, profile]) => setData({ overview, activity, profile }))
      .catch((caught: unknown) =>
        setError(caught instanceof ApiError ? caught.message : "The overview could not be loaded."),
      );
  }, []);

  const name = session.status === "signed-in" ? session.user.display_name : null;

  return (
    <>
      <PageTitle
        title={name ? `Welcome back, ${name}` : "Overview"}
        description="Your scans, warnings and account activity."
        action={<ButtonLink href="/dashboard/scan">New scan</ButtonLink>}
      />
      {error && <Alert tone="warning" title="Overview unavailable">{error}</Alert>}
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
                <PanelHeader title="Results so far" description={`${data.overview.total_scans} saved scan${data.overview.total_scans === 1 ? "" : "s"}`} />
                <RiskBreakdown overview={data.overview} />
                {data.overview.total_scans >= MIN_SCANS_FOR_CHART && (
                  <div className="border-t border-line px-5 py-5">
                    <ActivityChart days={data.overview.daily_activity} />
                  </div>
                )}
              </Panel>
              <Panel>
                <PanelHeader title="Flagged recently" description="Known threats and suspicious results" />
                <ScanList scans={data.overview.recent_threats} empty="Nothing you scanned has been flagged." />
              </Panel>
            </div>
          )}

          <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
            {data.overview.total_scans > 0 && (
              <Panel>
                <PanelHeader
                  title="Recent scans"
                  action={<ButtonLink href="/dashboard/history" variant="ghost" size="sm">View all</ButtonLink>}
                />
                <ScanList scans={data.overview.recent_scans} empty="" />
              </Panel>
            )}
            <Panel className={cn(data.overview.total_scans === 0 && "lg:col-span-2")}>
              <PanelHeader title="Browser protection" />
              <div className="flex gap-4 px-5 py-5">
                <Puzzle aria-hidden className="mt-0.5 size-5 shrink-0 text-ink-faint" />
                <div className="space-y-2 text-sm">
                  <p className="font-medium text-ink">No extension connected</p>
                  <p className="text-ink-muted">
                    The SENTINEL Protect extension is still in development, so there is nothing to
                    connect yet. Until it is released, browsing is not being checked.
                  </p>
                  <a href="/browser-protection" className="inline-block font-medium text-accent hover:underline">What it will do</a>
                </div>
              </div>
            </Panel>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Panel>
              <PanelHeader title="Recommendations" />
              <ul className="space-y-3 px-5 py-4 text-sm leading-relaxed text-ink">
                {recommendations(data).map((tip) => (
                  <li key={tip} className="flex gap-2.5">
                    <span aria-hidden className="mt-2 size-1 shrink-0 rounded-full bg-accent" />
                    {tip}
                  </li>
                ))}
              </ul>
            </Panel>
            <Panel>
              <PanelHeader title="Account activity" description="Sign-ins and security changes" />
              <ul className="divide-y divide-line">
                {data.activity.map((event) => (
                  <li key={`${event.action}-${event.created_at}`} className="flex items-center justify-between gap-4 px-5 py-2.5 text-sm">
                    <span className={cn(event.action === "sign_in_failed" ? "text-warning" : "text-ink")}>
                      {ACTIVITY_TEXT[event.action] ?? event.action}
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
