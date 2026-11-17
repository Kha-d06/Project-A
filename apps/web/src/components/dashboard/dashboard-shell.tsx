"use client";

import {
  Flag,
  KeyRound,
  Laptop,
  LockKeyhole,
  Users,
  Gavel,
  Globe,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  Puzzle,
  Radar,
  ScanSearch,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { Logo } from "@/components/brand/logo";
import { LanguageSwitch } from "@/components/site/language-switch";
import { ThemeToggle } from "@/components/site/theme-toggle";
import type { ScanType } from "@/lib/api/types";
import { type Dictionary } from "@/lib/i18n/en";
import { useI18n } from "@/lib/i18n/client";
import { cn } from "@/lib/cn";
import { useSession } from "@/lib/session";

type NavKey = keyof Dictionary["dashboard"]["nav"] | `extra.${keyof Dictionary["extra"]["nav"]}`;

const NAV: { href: string; key: NavKey; icon: typeof History }[] = [
  { href: "/dashboard", key: "overview", icon: LayoutDashboard },
  { href: "/dashboard/scan", key: "scanCenter", icon: ScanSearch },
  { href: "/dashboard/history", key: "history", icon: History },
  { href: "/dashboard/browser-protection", key: "browserProtection", icon: Puzzle },
  { href: "/dashboard/intelligence", key: "intelligence", icon: Radar },
  { href: "/dashboard/reports", key: "myReports", icon: Flag },
  { href: "/dashboard/devices", key: "extra.devices", icon: Laptop },
  { href: "/dashboard/groups", key: "extra.groups", icon: Users },
  { href: "/dashboard/passwords", key: "extra.vault", icon: LockKeyhole },
  { href: "/dashboard/vpn", key: "extra.vpn", icon: Globe },
  { href: "/dashboard/breach", key: "extra.breach", icon: KeyRound },
  { href: "/dashboard/settings", key: "settings", icon: Settings },
];

// Shown only to these roles. The API enforces the same rule on every request.
const STAFF_NAV: { href: string; key: NavKey; icon: typeof History; roles: string[] }[] = [
  { href: "/dashboard/moderation", key: "moderation", icon: Gavel, roles: ["moderator", "admin"] },
  { href: "/dashboard/admin", key: "admin", icon: ShieldCheck, roles: ["admin"] },
];

const SCANNERS: ScanType[] = ["url", "message", "file", "qr", "website", "apk", "screenshot"];

function isCurrent(pathname: string, href: string) {
  return href === "/dashboard" ? pathname === href : pathname.startsWith(href);
}

function SidebarNav() {
  const pathname = usePathname();
  const { session, signOut } = useSession();
  const { t } = useI18n();
  const router = useRouter();

  return (
    <div className="flex h-full flex-col gap-6">
      <nav aria-label={t.dashboard.nav.label} className="space-y-6">
        <ul className="space-y-0.5">
          {[
            ...NAV,
            ...STAFF_NAV.filter((item) => session.status === "signed-in" && item.roles.includes(session.user.role)),
          ].map((item) => {
            const current = isCurrent(pathname, item.href);
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={current ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-3 rounded-control px-3 py-2 text-sm transition-colors",
                    current ? "bg-surface-sunken font-medium text-ink" : "text-ink-muted hover:bg-surface-sunken/60 hover:text-ink",
                  )}
                >
                  <item.icon aria-hidden className={cn("size-4", current && "text-accent")} />
                  {item.key.startsWith("extra.")
                    ? t.extra.nav[item.key.slice(6) as keyof Dictionary["extra"]["nav"]]
                    : t.dashboard.nav[item.key as keyof Dictionary["dashboard"]["nav"]]}
                </Link>
              </li>
            );
          })}
        </ul>
        <div>
          <p className="px-3 text-xs font-semibold tracking-wider text-ink-faint uppercase">{t.dashboard.nav.scanners}</p>
          <ul className="mt-2 space-y-0.5">
            {SCANNERS.map((type) => (
              <li key={type}>
                <Link href={`/dashboard/scan?type=${type}`} className="block rounded-control px-3 py-1.5 text-sm text-ink-muted hover:text-ink">
                  {t.scanners[type]}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </nav>
      <div className="mt-auto space-y-3 border-t border-line pt-4">
        {session.status === "signed-in" && (
          <p className="truncate px-3 text-sm text-ink-muted" title={session.user.email}>
            {session.user.display_name ?? session.user.email}
          </p>
        )}
        <div className="flex items-center justify-between gap-2 px-1">
          <button
            type="button"
            onClick={async () => {
              await signOut();
              router.push("/");
            }}
            className="inline-flex items-center gap-2 rounded-control px-2 py-1.5 text-sm text-ink-muted hover:text-ink"
          >
            <LogOut aria-hidden className="size-4 rtl:rotate-180" />
            {t.dashboard.nav.signOut}
          </button>
          <ThemeToggle />
        </div>
        <div className="px-1">
          <LanguageSwitch />
        </div>
      </div>
    </div>
  );
}

export function DashboardShell({ children }: { children: ReactNode }) {
  const { session } = useSession();
  const { t } = useI18n();
  const router = useRouter();
  const pathname = usePathname();
  const [openOn, setOpenOn] = useState<string | null>(null);
  const menuOpen = openOn === pathname;

  useEffect(() => {
    if (session.status === "signed-out") {
      router.replace(`/sign-in?next=${encodeURIComponent(pathname)}`);
    }
  }, [session.status, router, pathname]);

  if (session.status !== "signed-in") {
    return (
      <div className="grid min-h-dvh place-items-center" role="status">
        <span className="text-sm text-ink-muted">{t.dashboard.nav.loading}</span>
      </div>
    );
  }

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[15rem_1fr] print:block">
      <aside className="sticky top-0 hidden h-dvh print:!hidden overflow-y-auto border-e border-line bg-surface px-3 py-5 lg:block">
        <Link href="/" aria-label={t.nav.home} className="mb-8 block px-3">
          <Logo />
        </Link>
        <SidebarNav />
      </aside>

      <div className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-line bg-canvas/90 px-4 backdrop-blur lg:hidden print:hidden">
        <Link href="/" aria-label={t.nav.home}>
          <Logo />
        </Link>
        <button
          type="button"
          aria-expanded={menuOpen}
          aria-controls="dashboard-menu"
          aria-label={menuOpen ? t.nav.closeMenu : t.nav.openMenu}
          onClick={() => setOpenOn(menuOpen ? null : pathname)}
          className="grid size-10 place-items-center rounded-control"
        >
          {menuOpen ? <X aria-hidden className="size-5" /> : <Menu aria-hidden className="size-5" />}
        </button>
      </div>
      {menuOpen && (
        <div id="dashboard-menu" className="animate-fade-up border-b border-line bg-surface px-3 py-4 lg:hidden">
          <SidebarNav />
        </div>
      )}

      <main id="main" className="min-w-0">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8 sm:py-10">{children}</div>
      </main>
    </div>
  );
}

export function PageTitle({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="space-y-1">
        <h1 className="font-display text-title font-bold text-ink">{title}</h1>
        {description && <p className="text-ink-muted">{description}</p>}
      </div>
      {action}
    </div>
  );
}
