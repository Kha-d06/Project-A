import type { ReactNode } from "react";

import { cn } from "@/lib/cn";

export function Section({
  id,
  eyebrow,
  title,
  intro,
  children,
  className,
}: {
  id?: string;
  eyebrow?: string;
  title: string;
  intro?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section id={id} className={cn("scroll-mt-20 border-t border-line", className)}>
      <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
        <div className="max-w-2xl space-y-3">
          {eyebrow && (
            <p className="text-xs font-semibold tracking-[0.16em] text-accent uppercase">{eyebrow}</p>
          )}
          <h2 className="font-display text-title font-bold text-ink sm:text-[2.1rem]">{title}</h2>
          {intro && <div className="text-ink-muted sm:text-lg">{intro}</div>}
        </div>
        <div className="mt-10">{children}</div>
      </div>
    </section>
  );
}
