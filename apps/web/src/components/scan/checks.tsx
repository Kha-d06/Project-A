"use client";

import { CircleCheck, CircleDashed, CircleMinus, CircleX } from "lucide-react";

import type { Check, CheckStatus } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";

const STATUS: Record<CheckStatus, { icon: typeof CircleCheck; className: string }> = {
  completed: { icon: CircleCheck, className: "text-accent" },
  unavailable: { icon: CircleDashed, className: "text-warning" },
  failed: { icon: CircleX, className: "text-warning" },
  skipped: { icon: CircleMinus, className: "text-ink-faint" },
};

export function ChecksList({ checks }: { checks: Check[] }) {
  const { t } = useI18n();
  return (
    <ul className="divide-y divide-line">
      {checks.map((check) => {
        const status = STATUS[check.status];
        return (
          <li key={check.key} className="flex gap-3 px-5 py-3.5">
            <status.icon aria-hidden className={cn("mt-0.5 size-4 shrink-0", status.className)} />
            <div className="min-w-0 flex-1 space-y-0.5">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                <p className="text-sm font-medium text-ink" dir="auto">{check.label}</p>
                <p className="text-xs text-ink-faint">
                  <span className="sr-only">{t.checkStatus.prefix} </span>
                  {t.checkStatus[check.status]}
                </p>
              </div>
              <p className="text-sm text-ink-muted" dir="auto">{check.detail}</p>
              <p className="text-xs text-ink-faint">{check.provider}</p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
