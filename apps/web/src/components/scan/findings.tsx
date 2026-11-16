import type { Finding } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { SEVERITY, TONE_CLASSES } from "@/lib/risk";

import { EvidenceList } from "./evidence";

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="px-5 py-6 text-sm text-ink-muted">
        None of the checks below found a warning sign. That is a good sign, but it is not proof:
        new threats often have not been reported yet.
      </p>
    );
  }
  return (
    <ul className="divide-y divide-line">
      {findings.map((finding, index) => {
        const severity = SEVERITY[finding.severity];
        const tone = TONE_CLASSES[severity.tone];
        return (
          <li
            key={`${finding.category}-${index}`}
            className="grid animate-fade-up gap-3 px-5 py-4 sm:grid-cols-[9.5rem_1fr]"
            style={{ animationDelay: `${Math.min(index, 6) * 40}ms` }}
          >
            <div>
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 text-xs font-semibold tracking-wide uppercase",
                  tone.text,
                )}
              >
                <span aria-hidden className={cn("size-1.5 rounded-full bg-current")} />
                {severity.label}
              </span>
            </div>
            <div className="min-w-0 space-y-2">
              <h3 className="font-medium text-ink">{finding.title}</h3>
              <p className="text-sm leading-relaxed text-ink-muted">{finding.explanation}</p>
              <EvidenceList evidence={finding.evidence} />
              <p className="text-xs text-ink-faint">Source: {finding.source}</p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
