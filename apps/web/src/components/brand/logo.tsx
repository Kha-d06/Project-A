import { cn } from "@/lib/cn";

/**
 * The Qalaa mark: a shield cut by a horizontal sightline, the line a sentinel
 * keeps watch along. The sightline is the one place the accent appears.
 */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden className={cn("size-7", className)} fill="none">
      <path
        d="M16 2.5 4.5 6.8v8.4c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V6.8L16 2.5Z"
        className="fill-ink"
      />
      <path
        d="M16 6.4 8.3 9.3v5.9c0 4.9 3.2 8.7 7.7 10.3 4.5-1.6 7.7-5.4 7.7-10.3V9.3L16 6.4Z"
        className="fill-canvas"
      />
      <rect x="6.5" y="14.2" width="19" height="2.6" rx="1.3" className="fill-accent" />
      <circle cx="16" cy="15.5" r="2.4" className="fill-ink" />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <LogoMark />
      <span className="font-display text-[0.95rem] font-bold tracking-[0.18em] text-ink uppercase">
        Qalaa
      </span>
    </span>
  );
}
