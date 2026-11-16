"use client";

import { XCircle } from "lucide-react";

import type { Scan } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";
import { RISK, TONE_CLASSES } from "@/lib/risk";

import { RiskIcon } from "./risk-badge";

export function Verdict({ scan }: { scan: Scan }) {
  const { t } = useI18n();
  if (scan.status === "failed" || !scan.risk) {
    return (
      <div className="flex animate-fade-up gap-4">
        <span className="grid size-12 shrink-0 place-items-center rounded-full bg-surface-sunken text-ink-muted">
          <XCircle aria-hidden className="size-6" />
        </span>
        <div className="space-y-1">
          <h2 className="font-display text-title font-semibold">{t.report.failedTitle}</h2>
          <p className="text-ink-muted">
            {scan.error ?? t.report.failedFallback} {t.report.failedBody}
          </p>
        </div>
      </div>
    );
  }

  const presentation = RISK[scan.risk];
  const tone = TONE_CLASSES[presentation.tone];
  return (
    <div className="flex animate-fade-up flex-col gap-4 sm:flex-row">
      <span
        className={cn(
          "grid size-12 shrink-0 place-items-center rounded-full",
          tone.soft,
          tone.text,
          scan.risk === "known_malicious" && "animate-attention",
        )}
      >
        <RiskIcon risk={scan.risk} className="size-6" />
      </span>
      <div className="space-y-2">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h2 className={cn("font-display text-title font-semibold", tone.text)}>
            {t.risk[scan.risk].label}
          </h2>
          {scan.confidence && <span className="text-sm text-ink-muted">{t.confidence[scan.confidence]}</span>}
        </div>
        {scan.summary && <p className="max-w-2xl text-ink">{scan.summary}</p>}
      </div>
    </div>
  );
}
