import { Check } from "lucide-react";

import type { Scan } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { SCAN_TYPE_LABEL } from "@/lib/risk";

const STEPS = ["Received", "Checking", "Report"] as const;

/**
 * Honest progress: the backend does not report a percentage, so this shows which
 * stage the scan is in and an indeterminate sweep, never an invented number.
 */
export function ScanProgress({ scan }: { scan: Scan }) {
  const current = scan.status === "queued" ? 0 : 1;
  const message =
    scan.status === "queued"
      ? "Waiting for a scanner to pick this up."
      : `Running ${SCAN_TYPE_LABEL[scan.scan_type].toLowerCase()} checks. Most finish within a few seconds; following redirects can take longer.`;

  return (
    <div className="space-y-6" role="status" aria-live="polite">
      <div className="relative h-1 overflow-hidden rounded-full bg-surface-sunken">
        <div className="motion-indicator absolute inset-y-0 w-2/5 animate-scan-sweep rounded-full bg-gradient-to-r from-transparent via-accent to-transparent" />
      </div>
      <ol className="flex items-center gap-3 text-sm">
        {STEPS.map((step, index) => {
          const done = index < current;
          const active = index === current;
          return (
            <li key={step} className="flex items-center gap-3">
              <span
                className={cn(
                  "flex items-center gap-2",
                  done || active ? "text-ink" : "text-ink-faint",
                )}
              >
                <span
                  className={cn(
                    "grid size-5 place-items-center rounded-full border text-[0.7rem] transition-colors duration-300",
                    done && "border-accent bg-accent text-accent-ink",
                    active && "border-accent text-accent",
                    !done && !active && "border-line-strong",
                  )}
                >
                  {done ? <Check aria-hidden className="size-3" /> : index + 1}
                </span>
                {step}
                {active && <span className="sr-only">(in progress)</span>}
              </span>
              {index < STEPS.length - 1 && <span aria-hidden className="h-px w-6 bg-line-strong sm:w-12" />}
            </li>
          );
        })}
      </ol>
      <p className="text-sm text-ink-muted">{message}</p>
    </div>
  );
}
