import type { ReactNode } from "react";

import { getDictionary, getLocale } from "@/lib/i18n/server";

/** Layout for long-form pages: policies, documentation, about. */
export async function ProsePage({
  title,
  intro,
  children,
  language = "en",
}: {
  title: string;
  intro?: ReactNode;
  children: ReactNode;
  /** The language the page content is written in. */
  language?: "en" | "ar";
}) {
  const locale = await getLocale();
  const notice = language === locale ? null : getDictionary(locale).common.englishOnly;
  return (
    <article className="mx-auto max-w-3xl px-4 py-12 sm:px-6 sm:py-16" lang={language} dir={language === "ar" ? "rtl" : "ltr"}>
      {notice && (
        <p lang={locale} dir="rtl" className="mb-6 rounded-control border border-line bg-surface-sunken px-4 py-2.5 text-sm text-ink-muted">
          {notice}
        </p>
      )}
      <header className="space-y-3 border-b border-line pb-8">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">{title}</h1>
        {intro && <p className="text-lg text-ink-muted">{intro}</p>}
      </header>
      <div className="space-y-10 pt-8 text-[0.95rem] leading-relaxed text-ink-muted [&_a]:text-accent [&_a]:underline [&_a]:decoration-accent/50 [&_a]:underline-offset-4 hover:[&_a]:decoration-accent [&_h2]:font-display [&_h2]:text-lg [&_h2]:font-semibold [&_h2]:text-ink [&_li]:ms-5 [&_li]:list-disc [&_section]:space-y-3 [&_strong]:text-ink [&_ul]:space-y-1.5">
        {children}
      </div>
    </article>
  );
}
