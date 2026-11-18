"use client";

import { ChevronDown } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "@/lib/api/client";
import type { ProviderStatus } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";

const STATUS_TONE: Record<ProviderStatus["status"], { dot: string; chip: string; bar: string }> = {
  active: { dot: "bg-clear", chip: "border-clear/30 bg-clear-soft text-clear", bar: "bg-clear" },
  degraded: { dot: "bg-warning", chip: "border-warning/30 bg-warning-soft text-warning", bar: "bg-warning" },
  awaiting_first_sync: { dot: "bg-warning", chip: "border-warning/30 bg-warning-soft text-warning", bar: "bg-warning/70" },
  not_configured: { dot: "bg-ink-faint", chip: "border-line-strong bg-surface-sunken text-ink-muted", bar: "bg-line-strong" },
};
const ORDER: ProviderStatus["status"][] = ["active", "degraded", "awaiting_first_sync", "not_configured"];

/** Live status of this deployment's providers, as reported by the API. */
export function IntegrationsStatus() {
  const { t } = useI18n();
  const [providers, setProviders] = useState<ProviderStatus[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    api.system.providers().then(setProviders, () => setFailed(true));
  }, []);

  if (failed) {
    return (
      <p className="rounded-panel border border-line bg-surface px-5 py-4 text-sm text-ink-muted">
        {t.home.integrationsDown}
      </p>
    );
  }

  if (!providers) {
    return (
      <div className="space-y-3" aria-busy>
        <div className="skeleton h-3 w-full" />
        {Array.from({ length: 5 }, (_, index) => (
          <div key={index} className="skeleton h-12" />
        ))}
      </div>
    );
  }

  const sorted = [...providers].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));
  const counts = ORDER.map((status) => ({ status, count: providers.filter((p) => p.status === status).length })).filter((c) => c.count);

  return (
    <div className="overflow-hidden rounded-panel border border-line bg-surface shadow-raised">
      <div className="space-y-3 border-b border-line px-5 py-5 sm:px-6">
        <div className="flex h-1.5 overflow-hidden rounded-full bg-surface-sunken" aria-hidden>
          {counts.map(({ status, count }) => (
            <span key={status} className={cn("h-full", STATUS_TONE[status].bar)} style={{ width: `${(count / providers.length) * 100}%` }} />
          ))}
        </div>
        <ul className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-ink-muted">
          {counts.map(({ status, count }) => (
            <li key={status} className="inline-flex items-center gap-2">
              <span aria-hidden className={cn("size-2 rounded-full", STATUS_TONE[status].dot)} />
              <span className="font-mono text-ink tabular-nums">{count}</span> {t.home.integrationStatus[status]}
            </li>
          ))}
        </ul>
      </div>
      <ul className="divide-y divide-line">
        {sorted.map((provider) => (
          <li key={provider.key}>
            <details className="group">
              <summary className="flex cursor-pointer list-none items-center gap-4 px-5 py-3.5 transition-colors hover:bg-surface-raised sm:px-6 [&::-webkit-details-marker]:hidden">
                <span aria-hidden className={cn("size-2 shrink-0 rounded-full", STATUS_TONE[provider.status].dot)} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium text-ink">{provider.name}</span>
                  <span className="block truncate text-sm text-ink-muted">{provider.purpose}</span>
                </span>
                <span className={cn("hidden shrink-0 rounded-full border px-2.5 py-0.5 text-xs sm:inline", STATUS_TONE[provider.status].chip)}>
                  {t.home.integrationStatus[provider.status]}
                </span>
                <ChevronDown aria-hidden className="size-4 shrink-0 text-ink-faint transition-transform duration-300 group-open:rotate-180" />
              </summary>
              <div className="animate-fade-up space-y-1.5 px-5 pb-4 ps-11 text-sm sm:px-6 sm:ps-12">
                <p className="text-ink-muted">{provider.detail}</p>
                <p className="text-xs text-ink-faint">
                  <span className="font-medium text-ink-muted">{t.home.dataShared} </span>
                  {provider.shares_data}
                </p>
              </div>
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}
