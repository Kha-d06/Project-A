"use client";

import { Languages } from "lucide-react";
import { useRouter } from "next/navigation";

import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";
import { LOCALE_COOKIE, LOCALE_NAMES, type Locale } from "@/lib/i18n/locales";

const ONE_YEAR_SECONDS = 365 * 24 * 3600;

export function LanguageSwitch({ className }: { className?: string }) {
  const { locale, t } = useI18n();
  const router = useRouter();
  const other: Locale = locale === "ar" ? "en" : "ar";

  return (
    <button
      type="button"
      lang={other}
      onClick={() => {
        document.cookie = `${LOCALE_COOKIE}=${other}; Path=/; Max-Age=${ONE_YEAR_SECONDS}; SameSite=Lax`;
        router.refresh();
      }}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-control px-2.5 py-1.5 text-sm text-ink-muted transition-colors hover:bg-surface-sunken hover:text-ink",
        className,
      )}
      title={t.common.switchLanguage}
    >
      <Languages aria-hidden className="size-4" />
      {LOCALE_NAMES[other]}
      {/* The accessible name starts with the visible text (WCAG 2.5.3). */}
      <span className="sr-only" lang={locale}>
        {` – ${t.common.switchLanguage}`}
      </span>
    </button>
  );
}
