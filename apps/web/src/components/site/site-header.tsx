"use client";

import { Menu, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { Logo } from "@/components/brand/logo";
import { ButtonLink } from "@/components/ui/button";
import { LanguageSwitch } from "@/components/site/language-switch";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";
import { useSession } from "@/lib/session";

const NAV = [
  { href: "/#product", key: "product" },
  { href: "/scan", key: "tools" },
  { href: "/browser-protection", key: "browserProtection" },
  { href: "/#how-it-works", key: "howItWorks" },
  { href: "/learn", key: "learn" },
  { href: "/about", key: "about" },
] as const;

function AccountActions({ stacked = false }: { stacked?: boolean }) {
  const { session } = useSession();
  const { t } = useI18n();
  const size = stacked ? "lg" : "sm";
  const width = stacked ? "w-full" : undefined;

  if (session.status === "signed-in") {
    return (
      <ButtonLink href="/dashboard" size={size} className={width}>
        {t.nav.openDashboard}
      </ButtonLink>
    );
  }
  return (
    <>
      <ButtonLink href="/sign-in" variant="ghost" size={size} className={width}>
        {t.nav.signIn}
      </ButtonLink>
      <ButtonLink href="/sign-up" size={size} className={width}>
        {t.nav.getStarted}
      </ButtonLink>
    </>
  );
}

export function SiteHeader() {
  const pathname = usePathname();
  const { t } = useI18n();
  // Remember which page the menu was opened on; navigating anywhere closes it.
  const [openOn, setOpenOn] = useState<string | null>(null);
  const menuOpen = openOn === pathname;
  const setMenuOpen = (open: boolean) => setOpenOn(open ? pathname : null);

  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: KeyboardEvent) => event.key === "Escape" && setMenuOpen(false);
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  });

  return (
    <header className="sticky top-0 z-40 print:hidden border-b border-line bg-canvas/85 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-4 sm:px-6">
        <Link href="/" aria-label={t.nav.home} className="rounded-control">
          <Logo />
        </Link>

        <nav aria-label={t.nav.main} className="hidden flex-1 lg:block">
          <ul className="flex items-center gap-1">
            {NAV.map((item) => (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={cn(
                    "rounded-control px-3 py-2 text-sm transition-colors",
                    pathname === item.href ? "text-ink" : "text-ink-muted hover:text-ink",
                  )}
                >
                  {(item.key === "learn" ? t.extra.nav.learn : t.nav[item.key])}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <div className="ms-auto hidden items-center gap-2 lg:flex">
          <LanguageSwitch />
          <AccountActions />
        </div>

        <button
          type="button"
          className="ms-auto grid size-10 place-items-center rounded-control text-ink lg:hidden"
          aria-expanded={menuOpen}
          aria-controls="mobile-menu"
          aria-label={menuOpen ? t.nav.closeMenu : t.nav.openMenu}
          onClick={() => setMenuOpen(!menuOpen)}
        >
          {menuOpen ? <X aria-hidden className="size-5" /> : <Menu aria-hidden className="size-5" />}
        </button>
      </div>

      {menuOpen && (
        <div id="mobile-menu" className="animate-fade-up border-t border-line bg-canvas lg:hidden">
          <nav aria-label={t.nav.main} className="mx-auto max-w-6xl px-4 py-4 sm:px-6">
            <ul className="space-y-1">
              {NAV.map((item) => (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className="block rounded-control px-3 py-3 text-base text-ink hover:bg-surface-sunken"
                  >
                    {(item.key === "learn" ? t.extra.nav.learn : t.nav[item.key])}
                  </Link>
                </li>
              ))}
            </ul>
            <div className="mt-4 flex flex-col gap-2 border-t border-line pt-4">
              <LanguageSwitch className="justify-center py-3 text-base" />
              <AccountActions stacked />
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
