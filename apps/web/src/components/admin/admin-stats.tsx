"use client";

import { useEffect, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api/client";
import type { AdminStats as Stats } from "@/lib/api/types";
import { formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

const LINES = [
  ["scans", "var(--accent)"],
  ["flagged", "var(--warning)"],
  ["failed", "var(--danger)"],
  ["signups", "var(--ink-muted)"],
  ["reports", "var(--clear)"],
] as const;

export function AdminStats() {
  const { t, locale } = useI18n();
  const s = t.extra.staff;
  const [stats, setStats] = useState<Stats | null>(null);
  useEffect(() => {
    api.adminStats(30).then(setStats, () => setStats(null));
  }, []);
  if (!stats) return null;
  const data = stats.series.map((point) => Object.fromEntries([["date", point.date], ...LINES.map(([key]) => [s.series[key], point[key]])]));

  return (
    <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
      <Panel>
        <PanelHeader title={s.activity} description={s.activityHint(stats.days)} />
        <figure className="h-64 px-2 py-4" aria-label={s.activity}>
          <ResponsiveContainer>
            <LineChart data={data} margin={{ top: 4, right: 12, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} stroke="var(--line)" />
              <XAxis dataKey="date" reversed={locale === "ar"} tickFormatter={formatShortDate} tick={{ fill: "var(--ink-faint)", fontSize: 11 }} tickLine={false} axisLine={false} interval={6} />
              <YAxis orientation={locale === "ar" ? "right" : "left"} allowDecimals={false} tick={{ fill: "var(--ink-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                labelFormatter={(value) => formatShortDate(String(value))}
                contentStyle={{ background: "var(--surface-raised)", border: "1px solid var(--line)", borderRadius: 8, color: "var(--ink)" }}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {LINES.map(([key, color]) => (
                <Line key={key} type="monotone" dataKey={s.series[key]} stroke={color} strokeWidth={2} dot={false} isAnimationActive={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </figure>
      </Panel>
      <Panel>
        <PanelHeader title={s.workload} />
        <dl className="divide-y divide-line text-sm">
          {(Object.keys(stats.pending_by_age) as (keyof Stats["pending_by_age"])[]).map((key) => (
            <div key={key} className="flex justify-between px-5 py-2.5">
              <dt className="text-ink-muted">{s.pendingAge[key]}</dt>
              <dd className={key === "over_3_days" && stats.pending_by_age[key] ? "font-semibold text-warning" : "text-ink"}>{stats.pending_by_age[key]}</dd>
            </div>
          ))}
        </dl>
        <p className="border-t border-line px-5 pt-3 text-xs font-semibold tracking-wider text-ink-faint uppercase">{s.reviewsBy}</p>
        {stats.reviews_by_moderator.length ? (
          <ul className="space-y-1 px-5 py-3 text-sm">
            {stats.reviews_by_moderator.map((row) => (
              <li key={row.moderator} className="flex justify-between gap-2">
                <span className="truncate text-ink">{row.moderator}</span>
                <span className="tabular-nums text-ink-muted">{row.reviews}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="px-5 py-3 text-sm text-ink-muted">{s.noReviews}</p>
        )}
      </Panel>
    </div>
  );
}
