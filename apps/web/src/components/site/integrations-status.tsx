"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api/client";
import type { ProviderStatus } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";

const STATUS_DOT: Record<ProviderStatus["status"], string> = {
  active: "bg-accent",
  degraded: "bg-warning",
  awaiting_first_sync: "bg-warning",
  not_configured: "bg-ink-faint",
};

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
      <ul className="grid gap-3 md:grid-cols-2" aria-busy>
        {Array.from({ length: 4 }, (_, index) => (
          <li key={index} className="h-28 animate-pulse rounded-panel border border-line bg-surface" />
        ))}
      </ul>
    );
  }

  return (
    <ul className="grid gap-3 md:grid-cols-2">
      {providers.map((provider) => {

        return (
          <li key={provider.key} className="space-y-2 rounded-panel border border-line bg-surface p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="font-medium text-ink">{provider.name}</h3>
                <p className="text-sm text-ink-muted">{provider.purpose}</p>
              </div>
              <span className="inline-flex shrink-0 items-center gap-1.5 text-xs text-ink-muted">
                <span aria-hidden className={cn("size-1.5 rounded-full", STATUS_DOT[provider.status])} />
                {t.home.integrationStatus[provider.status]}
              </span>
            </div>
            <p className="text-sm text-ink-faint">{provider.detail}</p>
            <p className="text-xs text-ink-faint">
              <span className="font-medium text-ink-muted">{t.home.dataShared} </span>
              {provider.shares_data}
            </p>
          </li>
        );
      })}
    </ul>
  );
}
