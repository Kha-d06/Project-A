"use client";

import Link from "next/link";

import { Logo } from "@/components/brand/logo";
import { LanguageSwitch } from "@/components/site/language-switch";
import { ThemeToggle } from "@/components/site/theme-toggle";
import { useI18n } from "@/lib/i18n/client";

export function SiteFooter() {
  const { t } = useI18n();
  const columns = [
    {
      title: t.footer.tools,
      links: [
        { href: "/scan?type=url", label: t.scanners.url },
        { href: "/scan?type=message", label: t.scanners.message },
        { href: "/scan?type=file", label: t.scanners.file },
        { href: "/scan?type=qr", label: t.scanners.qr },
        { href: "/scan?type=website", label: t.scanners.website },
        { href: "/scan?type=apk", label: t.scanners.apk },
        { href: "/browser-protection", label: t.nav.browserProtection },
        { href: "/intelligence", label: t.footer.intelligence },
        { href: "/report", label: t.footer.report },
        { href: "/trends", label: t.extra.trends.nav },
        { href: "/download", label: t.extra.download.nav },
        { href: "/tools/password", label: t.extra.password.nav },
        { href: "/help/scammed", label: t.extra.scammed.nav },
      ],
    },
    {
      title: t.footer.project,
      links: [
        { href: "/about", label: t.footer.about },
        { href: "/docs", label: t.footer.docs },
        { href: "/about#contact", label: t.footer.contact },
      ],
    },
    {
      title: t.footer.policies,
      links: [
        { href: "/privacy", label: t.footer.privacy },
        { href: "/terms", label: t.footer.terms },
        { href: "/about#limits", label: t.footer.limits },
      ],
    },
  ];

  return (
    <footer className="print:hidden border-t border-line bg-surface">
      <div className="mx-auto grid max-w-6xl gap-10 px-4 py-12 sm:px-6 md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div className="space-y-3">
          <Logo />
          <p className="max-w-xs text-sm text-ink-muted">{t.footer.tagline}</p>
        </div>
        {columns.map((column) => (
          <div key={column.title}>
            <h2 className="text-xs font-semibold tracking-wider text-ink-faint uppercase">{column.title}</h2>
            <ul className="mt-3 space-y-2">
              {column.links.map((link) => (
                <li key={link.href}>
                  <Link href={link.href} className="text-sm text-ink-muted hover:text-ink">
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-5 text-sm text-ink-faint sm:px-6">
          <p>{t.footer.free}</p>
          <div className="flex items-center gap-2">
            <LanguageSwitch />
            <ThemeToggle />
          </div>
        </div>
      </div>
    </footer>
  );
}
