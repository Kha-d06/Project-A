"use client";

import { FileSearch, Link2, MessageSquareWarning, ScanSearch, ShieldCheck } from "lucide-react";
import { usePrefersReducedMotion } from "@/lib/reduced-motion";

import { Stagger, StaggerItem } from "@/components/motion/reveal";

/**
 * "How it works": three stages joined by a rail. A sample travels along the rail,
 * is inspected by the scanner ring in the middle and comes out as a verdict.
 * The motion is decorative; the steps' text carries the meaning.
 */
export function InspectionPipeline({ steps }: { steps: { title: string; body: string }[] }) {
  const reduce = usePrefersReducedMotion();
  const icons = [
    <span key="in" className="relative grid size-full place-items-center">
      <Link2 className="size-5" />
      {!reduce && (
        <>
          <MessageSquareWarning className="pl-in absolute size-5 opacity-0 [animation-delay:2s]" />
          <FileSearch className="pl-in absolute size-5 opacity-0 [animation-delay:4s]" />
        </>
      )}
    </span>,
    <ScanSearch key="scan" className="size-5" />,
    <ShieldCheck key="out" className="size-5" />,
  ];

  return (
    <div className="relative">
      {/* the rail, behind the three stations (desktop layout) */}
      <div aria-hidden className="pointer-events-none absolute inset-x-[16%] top-8 hidden h-px md:block rtl:-scale-x-100">
        <div className="h-px w-full bg-[linear-gradient(90deg,transparent,var(--line-strong)_12%,var(--line-strong)_88%,transparent)]" />
        {!reduce && (
          <>
            <span className="pl-packet absolute -top-[5px] size-[11px] rounded-full bg-accent shadow-[0_0_0_4px_color-mix(in_srgb,var(--accent)_20%,transparent),0_0_18px_var(--accent)]" />
            <span className="pl-trail absolute top-0 h-px w-24 bg-[linear-gradient(90deg,transparent,var(--accent))]" />
          </>
        )}
      </div>

      <Stagger as="ol" className="relative grid gap-10 md:grid-cols-3 md:gap-8">
        {steps.map((step, index) => (
          <StaggerItem key={step.title} className="group text-center md:px-4">
            <div className="relative mx-auto mb-6 grid size-16 place-items-center">
              {index === 1 && !reduce && (
                <>
                  <span aria-hidden className="absolute inset-0 rounded-full border border-accent/40 pl-ring" />
                  <span aria-hidden className="absolute -inset-3 rounded-full border border-accent/20 pl-ring [animation-delay:1.2s]" />
                </>
              )}
              <span
                className={
                  "relative grid size-16 place-items-center rounded-2xl border bg-surface shadow-raised transition-transform duration-300 group-hover:-translate-y-1 " +
                  (index === 2 ? "border-oasis/40 text-oasis" : "border-line-strong text-accent")
                }
              >
                {icons[index]}
              </span>
            </div>
            <span className="font-mono text-xs tracking-[0.2em] text-ink-faint">0{index + 1}</span>
            <h3 className="mt-2 font-display text-xl font-semibold tracking-[-0.015em] text-ink">{step.title}</h3>
            <p className="mx-auto mt-2 max-w-xs text-sm leading-relaxed text-ink-muted">{step.body}</p>
          </StaggerItem>
        ))}
      </Stagger>

      <style>{`
        .pl-packet { animation: pl-travel 6s cubic-bezier(.55,0,.45,1) infinite; }
        .pl-trail { animation: pl-trail 6s cubic-bezier(.55,0,.45,1) infinite; }
        .pl-ring { animation: pl-ring 2.4s ease-out infinite; }
        .pl-in { animation: pl-in 6s ease-in-out infinite; }
        @keyframes pl-travel {
          0% { left: 0%; opacity: 0; }
          8% { opacity: 1; }
          42%, 58% { left: calc(50% - 5px); }
          92% { opacity: 1; }
          100% { left: calc(100% - 11px); opacity: 0; }
        }
        @keyframes pl-trail {
          0% { left: -6rem; opacity: 0; }
          10% { opacity: .8; }
          42%, 58% { left: calc(50% - 6rem); opacity: .2; }
          100% { left: calc(100% - 6rem); opacity: 0; }
        }
        @keyframes pl-ring { from { transform: scale(.85); opacity: .9; } to { transform: scale(1.35); opacity: 0; } }
        @keyframes pl-in { 0%, 30% { opacity: 0; } 33%, 63% { opacity: 1; } 66%, 100% { opacity: 0; } }
      `}</style>
    </div>
  );
}
