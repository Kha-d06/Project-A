import { RiskBadge } from "@/components/scan/risk-badge";
import type { Dictionary } from "@/lib/i18n/en";

type Specimen = Dictionary["home"]["specimen"];

/**
 * The homepage's one rich moment: what Qalaa actually hands back, using the real
 * verdict badge. Labelled as an example so nobody mistakes it for a live result.
 *
 * Its evidence list is the page's only authored entrance: a short CSS stagger
 * (300ms, strong ease-out, 60ms apart) that needs no script, so the content is
 * there even before or without JavaScript, and becomes a plain fade under
 * reduced motion.
 */
export function VerdictSpecimen({ s }: { s: Specimen }) {
  const enter = (index: number) => ({ animationDelay: `${180 + index * 60}ms` });
  return (
    <figure className="w-full">
      <div className="overflow-hidden rounded-panel border border-line bg-surface">
        <div className="flex items-center gap-3 border-b border-line bg-surface-sunken/60 px-5 py-3">
          <span className="min-w-0 truncate font-mono text-[0.8125rem] text-ink-muted" dir="ltr">
            {s.url}
          </span>
        </div>

        <div className="space-y-6 p-5 sm:p-6">
          <div className="space-y-3">
            <RiskBadge risk="known_malicious" status="completed" />
            <p className="text-xl font-medium tracking-[-0.01em] text-ink">{s.title}</p>
          </div>

          <div className="space-y-3">
            <p className="text-[0.8125rem] font-medium text-ink-muted">{s.foundTitle}</p>
            <ul className="space-y-2.5">
              {s.found.map((item, index) => (
                <li key={item} className="flex animate-fade-up items-center gap-3 text-[0.9375rem] text-ink" style={enter(index)}>
                  <span aria-hidden className="keystone" />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div className="animate-fade-up space-y-2 border-t border-line pt-5" style={enter(s.found.length)}>
            <p className="text-[0.8125rem] font-medium text-ink-muted">{s.unknownTitle}</p>
            <p className="flex items-start gap-3 text-[0.9375rem] text-ink-muted">
              <span aria-hidden className="keystone mt-2 bg-transparent shadow-[inset_0_0_0_1.5px_var(--ink-faint)]" />
              {s.unknown}
            </p>
          </div>

          <p
            className="animate-fade-up rounded-control bg-danger-soft px-4 py-3 text-[0.9375rem] text-ink"
            style={enter(s.found.length + 1)}
          >
            {s.advice}
          </p>
        </div>
      </div>
      <figcaption className="mt-3 text-[0.8125rem] text-ink-faint">{s.caption}</figcaption>
    </figure>
  );
}
