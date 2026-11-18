import type { ReactNode } from "react";

import { Reveal } from "@/components/motion/reveal";
import { cn } from "@/lib/cn";

/** A landing-page section: an eyebrow, a title and an optional intro, then content. */
export function Section({
  id,
  eyebrow,
  title,
  intro,
  children,
  className,
  align = "start",
}: {
  id?: string;
  eyebrow?: string;
  title: string;
  intro?: ReactNode;
  children: ReactNode;
  className?: string;
  align?: "start" | "center";
}) {
  return (
    <section id={id} className={cn("relative scroll-mt-20", className)}>
      <div
        aria-hidden
        className="absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,var(--line-strong)_20%,var(--line-strong)_80%,transparent)]"
      />
      <div className="mx-auto max-w-6xl px-4 py-20 sm:px-6 sm:py-28">
        <Reveal className={cn("max-w-2xl space-y-4", align === "center" && "mx-auto text-center")}>
          {eyebrow && (
            <p className={cn("flex items-center gap-3 eyebrow text-accent", align === "center" && "justify-center")}>
              <span aria-hidden className="h-px w-6 bg-accent/60" />
              {eyebrow}
            </p>
          )}
          <h2 className="font-display text-title font-semibold text-balance text-ink">{title}</h2>
          {intro && <div className="text-pretty text-ink-muted sm:text-lg sm:leading-relaxed">{intro}</div>}
        </Reveal>
        <div className="mt-12 sm:mt-14">{children}</div>
      </div>
    </section>
  );
}
