"use client";

import { Lock, ShieldAlert } from "lucide-react";
import { usePrefersReducedMotion } from "@/lib/reduced-motion";

/**
 * Decorative browser window for the "browser protection" band: a page starts to
 * load, the extension intercepts it and a warning slides over the page. Uses only
 * placeholder bars and glyphs, never readable addresses or messages.
 */
export function BrowserGuardVisual() {
  const reduce = usePrefersReducedMotion();
  const anim = (name: string) => (reduce ? "" : name);

  return (
    <div aria-hidden className="relative mx-auto w-full max-w-md select-none">
      <div className="absolute -inset-6 rounded-[2rem] bg-[radial-gradient(closest-side,var(--glow),transparent)]" />
      <div className="relative overflow-hidden rounded-2xl border border-line-strong bg-surface shadow-float">
        {/* window chrome */}
        <div className="flex items-center gap-2 border-b border-line bg-surface-sunken/60 px-4 py-3">
          <span className="size-2.5 rounded-full bg-line-strong" />
          <span className="size-2.5 rounded-full bg-line-strong" />
          <span className="size-2.5 rounded-full bg-line-strong" />
          <div className="ms-3 flex h-7 flex-1 items-center gap-2 rounded-md border border-line bg-surface px-2.5">
            <Lock className="size-3.5 text-ink-faint" />
            <span className={"h-2 rounded-full bg-line-strong " + anim("bg-type")} style={reduce ? { width: "55%" } : undefined} />
          </div>
          <span className="grid size-7 place-items-center rounded-md border border-accent/40 bg-accent-soft text-accent">
            <svg viewBox="0 0 32 32" className="size-4" fill="currentColor"><path d="M3 29V5h3v2h2V5h3v6h2v2h2v-2h2v2h2v-2h2V5h3v2h2V5h3v24H3Z" /></svg>
          </span>
        </div>
        {/* the page, loading */}
        <div className="relative h-64 space-y-3 p-5">
          <div className={"h-24 rounded-lg bg-surface-sunken " + anim("bg-load")} />
          <div className={"h-3 w-3/4 rounded-full bg-surface-sunken " + anim("bg-load [animation-delay:.1s]")} />
          <div className={"h-3 w-1/2 rounded-full bg-surface-sunken " + anim("bg-load [animation-delay:.2s]")} />
          <div className={"h-9 w-40 rounded-md bg-surface-sunken " + anim("bg-load [animation-delay:.3s]")} />
          {/* the warning */}
          <div className={"absolute inset-0 grid place-items-center bg-surface/80 backdrop-blur-[2px] " + (reduce ? "" : "bg-warn")}>
            <div className="flex flex-col items-center gap-3">
              <span className="relative grid size-16 place-items-center rounded-2xl border border-danger/40 bg-danger-soft text-danger">
                {!reduce && <span className="absolute inset-0 rounded-2xl border border-danger/50 bg-pulse" />}
                <ShieldAlert className="size-7" />
              </span>
              <span className="h-2.5 w-40 rounded-full bg-danger/25" />
              <span className="h-2 w-28 rounded-full bg-line-strong" />
              <span className="mt-1 flex gap-2">
                <span className="h-8 w-24 rounded-md bg-accent" />
                <span className="h-8 w-16 rounded-md border border-line-strong" />
              </span>
            </div>
          </div>
        </div>
      </div>
      <style>{`
        .bg-type { width: 0; animation: bg-type 6s ease-out infinite; }
        .bg-load { animation: bg-load 6s ease-in-out infinite; }
        .bg-warn { opacity: 0; animation: bg-warn 6s cubic-bezier(.2,.8,.2,1) infinite; }
        .bg-pulse { animation: bg-pulse 1.5s ease-out infinite; }
        @keyframes bg-type { 0% { width: 0; } 22%, 100% { width: 62%; } }
        @keyframes bg-load { 0%, 20% { opacity: .35; } 32%, 100% { opacity: 1; } }
        @keyframes bg-warn { 0%, 34% { opacity: 0; transform: translateY(8px); } 42%, 90% { opacity: 1; transform: none; } 100% { opacity: 0; } }
        @keyframes bg-pulse { from { transform: scale(1); opacity: .8; } to { transform: scale(1.5); opacity: 0; } }
      `}</style>
    </div>
  );
}
