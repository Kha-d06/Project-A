"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { Overview } from "@/lib/api/types";
import { formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

export function ActivityChart({ days }: { days: Overview["daily_activity"] }) {
  const { t, locale } = useI18n();
  const other = t.dashboard.overview.chartOther;
  const flaggedLabel = t.dashboard.overview.chartFlagged;
  const data = days.map((day) => ({
    date: day.date,
    [other]: day.total - day.flagged,
    [flaggedLabel]: day.flagged,
  }));
  const total = days.reduce((sum, day) => sum + day.total, 0);
  const flagged = days.reduce((sum, day) => sum + day.flagged, 0);

  return (
    <figure className="space-y-3">
      <div className="h-48 w-full" aria-hidden>
        <ResponsiveContainer>
          <BarChart data={data} layout="horizontal" reverseStackOrder={false} margin={{ top: 4, right: 4, bottom: 0, left: -24 }} barCategoryGap={3}>
            <CartesianGrid vertical={false} stroke="var(--line)" />
            <XAxis
              dataKey="date"
              reversed={locale === "ar"}
              tickFormatter={formatShortDate}
              tick={{ fill: "var(--ink-faint)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              interval={6}
            />
            <YAxis orientation={locale === "ar" ? "right" : "left"} allowDecimals={false} tick={{ fill: "var(--ink-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
            <Tooltip
              cursor={{ fill: "var(--surface-sunken)" }}
              labelFormatter={(value) => formatShortDate(String(value))}
              contentStyle={{
                background: "var(--surface-raised)",
                border: "1px solid var(--line)",
                borderRadius: 8,
                fontSize: 12,
                color: "var(--ink)",
              }}
            />
            <Bar dataKey={other} stackId="scans" fill="var(--line-strong)" isAnimationActive={false} />
            <Bar dataKey={flaggedLabel} stackId="scans" fill="var(--risk-warning)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="text-sm text-ink-muted">
        {t.dashboard.overview.chartCaption(total, flagged)}
      </figcaption>
    </figure>
  );
}
