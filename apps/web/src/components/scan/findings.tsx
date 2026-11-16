"use client";

import type { Finding } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";
import { SEVERITY, TONE_CLASSES } from "@/lib/risk";

import { EvidenceList } from "./evidence";

export function FindingsList({ findings }: { findings: Finding[] }) {
  const { t } = useI18n();
  if (findings.length === 0) {
    return <p className="px-5 py-6 text-sm text-ink-muted">{t.report.findingsEmpty}</p>;
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
                {t.severity[finding.severity]}
              </span>
            </div>
            <div className="min-w-0 space-y-2">
              <h3 className="font-medium text-ink" dir="auto">{finding.title}</h3>
              <p className="text-sm leading-relaxed text-ink-muted" dir="auto">{finding.explanation}</p>
              <EvidenceList evidence={finding.evidence} />
              <p className="text-xs text-ink-faint">
                {t.report.source} <span dir="auto">{finding.source}</span>
              </p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
