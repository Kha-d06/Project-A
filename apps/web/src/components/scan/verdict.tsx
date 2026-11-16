import { XCircle } from "lucide-react";

import type { Scan } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { RISK, TONE_CLASSES } from "@/lib/risk";

import { RiskIcon } from "./risk-badge";

const CONFIDENCE_TEXT = {
  high: "High confidence",
  medium: "Moderate confidence",
  low: "Low confidence",
} as const;

export function Verdict({ scan }: { scan: Scan }) {
  if (scan.status === "failed" || !scan.risk) {
    return (
      <div className="flex animate-fade-up gap-4">
        <span className="grid size-12 shrink-0 place-items-center rounded-full bg-surface-sunken text-ink-muted">
          <XCircle aria-hidden className="size-6" />
        </span>
        <div className="space-y-1">
          <h2 className="font-display text-title font-semibold">The scan could not finish</h2>
          <p className="text-ink-muted">
            {scan.error ?? "Something went wrong while scanning."} No verdict was reached, so
            treat the item as unchecked.
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
            {presentation.label}
          </h2>
          {scan.confidence && (
            <span className="text-sm text-ink-muted">{CONFIDENCE_TEXT[scan.confidence]}</span>
          )}
        </div>
        {scan.summary && <p className="max-w-2xl text-ink">{scan.summary}</p>}
      </div>
    </div>
  );
}
