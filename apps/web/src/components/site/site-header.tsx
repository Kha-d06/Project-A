"use client";

import { Menu, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
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
  const [scrolled, setScrolled] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: KeyboardEvent) => event.key === "Escape" && setMenuOpen(false);
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  });

  return (
    <header
      className={cn(
        "sticky top-0 z-40 border-b transition-[background-color,border-color,box-shadow] duration-300 print:hidden",
        scrolled || menuOpen
          ? "border-line bg-canvas/80 shadow-[0_8px_30px_-18px_rgb(0_0_0/0.35)] backdrop-blur-xl backdrop-saturate-150"
          : "border-transparent bg-transparent",
      )}
    >
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-4 sm:px-6">
        <Link href="/" aria-label={t.nav.home} className="rounded-control">
          <Logo />
        </Link>

        <nav aria-label={t.nav.main} className="hidden flex-1 lg:block">
          <ul className="flex items-center gap-0.5" onMouseLeave={() => setHovered(null)}>
            {NAV.map((item) => (
              <li key={item.href} className="relative">
                {(hovered ?? (NAV.some((n) => n.href === pathname) ? pathname : null)) === item.href && (
                  <motion.span
                    layoutId="nav-pill"
                    aria-hidden
                    className="absolute inset-0 rounded-full border border-line-strong/60 bg-surface-raised/80"
                    transition={{ type: "spring", stiffness: 420, damping: 34 }}
                  />
                )}
                <Link
                  href={item.href}
                  onMouseEnter={() => setHovered(item.href)}
                  onFocus={() => setHovered(item.href)}
                  className={cn(
                    "relative block rounded-full px-3.5 py-2 text-sm transition-colors",
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

      <AnimatePresence>
      {menuOpen && (
        <motion.div
          id="mobile-menu"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.28, ease: [0.2, 0.8, 0.2, 1] }}
          className="overflow-hidden border-t border-line bg-canvas lg:hidden"
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
              <AccountActions stacked />
            </div>
          </nav>
        </motion.div>
      )}
      </AnimatePresence>
    </header>
  );
}
