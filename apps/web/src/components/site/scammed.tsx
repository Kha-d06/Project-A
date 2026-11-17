"use client";

import { useState } from "react";

import { ButtonLink } from "@/components/ui/button";
import { CONTACTS, SITUATIONS } from "@/content/scammed";
import { useI18n } from "@/lib/i18n/client";

export function ScammedGuide() {
  const { t, locale } = useI18n();
  const s = t.extra.scammed;
  const [active, setActive] = useState(SITUATIONS[0]!.id);
  const lang = locale === "ar" ? "ar" : "en";
  const situation = SITUATIONS.find((item) => item.id === active) ?? SITUATIONS[0]!;

  return (
    <div className="mx-auto max-w-4xl space-y-8 px-4 py-12 sm:px-6">
      <header className="space-y-3">
        <h1 className="font-display text-display font-bold text-ink">{s.title}</h1>
        <p className="text-lg text-ink-muted">{s.intro}</p>
      </header>
      <section className="space-y-3">
        <h2 className="font-display text-lg font-semibold text-ink">{s.pick}</h2>
        <div className="grid gap-2 sm:grid-cols-2" role="group" aria-label={s.pick}>
          {SITUATIONS.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={item.id === active}
              onClick={() => setActive(item.id)}
              className="rounded-control border border-line bg-surface px-4 py-3 text-start text-sm text-ink transition-colors hover:border-accent aria-pressed:border-accent aria-pressed:bg-surface-sunken aria-pressed:font-semibold"
            >
              {item[lang].title}
            </button>
          ))}
        </div>
      </section>
      <section className="space-y-3 rounded-panel border border-danger/40 bg-danger-soft p-5" aria-live="polite">
        <h2 className="font-display text-lg font-semibold text-ink">{situation[lang].title}</h2>
        <ol className="list-decimal space-y-2 ps-5 text-ink">
          {situation[lang].steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>
      <section className="space-y-3">
        <h2 className="font-display text-lg font-semibold text-ink">{s.contacts}</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          {CONTACTS.map((contact) => (
            <div key={contact.country.en} className="space-y-1.5 rounded-panel border border-line bg-surface p-4 text-sm">
              <p className="font-semibold text-ink">{contact.country[lang]}</p>
              <ul className="space-y-1 text-ink-muted">
                {contact.items.map((item) => (
                  <li key={item.en}>
                    {item.href ? (
                      <a href={item.href} target="_blank" rel="noopener noreferrer" className="text-accent underline underline-offset-4">
                        {item[lang]}
                      </a>
                    ) : (
                      item[lang]
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <p className="text-xs text-ink-faint">{s.contactsNote}</p>
      </section>
      <section className="flex flex-wrap items-center gap-4">
        <p className="text-ink-muted">{s.done}</p>
        <ButtonLink href="/report">{s.report}</ButtonLink>
      </section>
    </div>
  );
}
