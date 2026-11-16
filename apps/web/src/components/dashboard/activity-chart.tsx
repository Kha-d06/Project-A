"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { Overview } from "@/lib/api/types";
import { formatShortDate } from "@/lib/format";

export function ActivityChart({ days }: { days: Overview["daily_activity"] }) {
  const data = days.map((day) => ({
    date: day.date,
    "Other results": day.total - day.flagged,
    Flagged: day.flagged,
  }));
  const total = days.reduce((sum, day) => sum + day.total, 0);
  const flagged = days.reduce((sum, day) => sum + day.flagged, 0);

  return (
    <figure className="space-y-3">
      <div className="h-48 w-full" aria-hidden>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -24 }} barCategoryGap={3}>
            <CartesianGrid vertical={false} stroke="var(--line)" />
            <XAxis
              dataKey="date"
              tickFormatter={formatShortDate}
              tick={{ fill: "var(--ink-faint)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              interval={6}
            />
            <YAxis allowDecimals={false} tick={{ fill: "var(--ink-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
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
            <Bar dataKey="Other results" stackId="scans" fill="var(--line-strong)" isAnimationActive={false} />
            <Bar dataKey="Flagged" stackId="scans" fill="var(--risk-warning)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="text-sm text-ink-muted">
        {total} scan{total === 1 ? "" : "s"} in the last 30 days, {flagged} flagged as suspicious or a known threat.
      </figcaption>
    </figure>
  );
}
