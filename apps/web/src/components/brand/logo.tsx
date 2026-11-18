import { cn } from "@/lib/cn";

/**
 * The Qalaa mark: a citadel (qal'a) seen front on. Two crenellated towers, a
 * curtain wall and an open gate; the brass keystone above the gate is the one
 * place the accent appears: the point where everything is checked on its way in.
 */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden className={cn("size-7", className)} fill="none">
      <path
        d="M3 29V5h3v2h2V5h3v6h2v2h2v-2h2v2h2v-2h2V5h3v2h2V5h3v24H3Z"
        className="fill-ink"
      />
      <path d="M13 29v-6.5a3 3 0 0 1 6 0V29h-6Z" className="fill-canvas" />
      <rect x="6.4" y="12" width="1.2" height="3.6" rx="0.6" className="fill-canvas" />
      <rect x="24.4" y="12" width="1.2" height="3.6" rx="0.6" className="fill-canvas" />
      <path d="m16 15.4 2 2-2 2-2-2 2-2Z" className="fill-accent" />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <LogoMark />
      {/* Latin wordmark in English, Arabic wordmark (قلعة) in the Arabic interface. */}
      <span className="wordmark-en font-display text-[0.95rem] font-bold tracking-[0.18em] text-ink uppercase">Qalaa</span>
      <span className="wordmark-ar font-display text-[1.15rem] font-bold text-ink">قلعة</span>
    </span>
  );
}
