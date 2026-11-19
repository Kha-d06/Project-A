"use client";

import { Menu, X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { Logo } from "@/components/brand/logo";
import { ButtonLink } from "@/components/ui/button";
import { LanguageSwitch } from "@/components/site/language-switch";
import { DownloadHeaderLink } from "@/components/site/platform-download";
import { ThemeToggle } from "@/components/site/theme-toggle";
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
  // Reduced motion keeps the fade and drops the movement.
  const rise = useReducedMotion() ? 0 : -6;
  const setMenuOpen = (open: boolean) => setOpenOn(open ? pathname : null);
  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: KeyboardEvent) => event.key === "Escape" && setMenuOpen(false);
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  });

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-canvas print:hidden">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-8 px-4 sm:px-6">
        <Link href="/" aria-label={t.nav.home} className="rounded-control">
          <Logo />
        </Link>

        <nav aria-label={t.nav.main} className="hidden flex-1 lg:block">
          <ul className="flex items-center gap-1">
            {NAV.map((item) => (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={pathname === item.href ? "page" : undefined}
                  className={cn(
                    "block whitespace-nowrap rounded-control px-2.5 py-2 text-sm transition-colors duration-150 xl:px-3",
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
          {/* The nav needs the room on narrower screens; the footer has the same switch. */}
          <div className="hidden 2xl:block">
            <ThemeToggle />
          </div>
          <div className="hidden xl:block">
            <DownloadHeaderLink />
          </div>
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

      <AnimatePresence>
      {menuOpen && (
        <motion.div
          id="mobile-menu"
          initial={{ opacity: 0, y: rise }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: rise, transition: { duration: 0.15 } }}
          transition={{ duration: 0.2, ease: [0.23, 1, 0.32, 1] }}
          className="border-t border-line bg-canvas lg:hidden"
        >
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
              <ThemeToggle className="self-center" />
              <DownloadHeaderLink className="justify-center" />
              <AccountActions stacked />
            </div>
          </nav>
        </motion.div>
      )}
      </AnimatePresence>
    </header>
  );
}
